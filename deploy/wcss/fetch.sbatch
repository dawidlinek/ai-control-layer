#!/bin/bash
# Fetch Hugging Face checkpoints into a shared HF cache on WCSS (CPU job, no GPU hours). serve.sbatch then resolves
# them offline (HF_HUB_OFFLINE=1) by repo id. Uses the vLLM apptainer image's Python (huggingface_hub is a vLLM
# dependency), so nothing is installed.
#   sbatch --parsable -A <account> --export=ALL,SIF=<path>.sif,HF_CACHE=<pd>/hf_cache,REPOS="a/b c/d" fetch.sbatch

#SBATCH --job-name=acl-llm-fetch
#SBATCH --partition=lem-cpu-short
#SBATCH --cpus-per-task=4
#SBATCH --mem=16gb
#SBATCH --time=1:00:00
#SBATCH --output=acl-llm-fetch_%j.out
#SBATCH --error=acl-llm-fetch_%j.err

set -euo pipefail
PD="/lustre/pd03/${SLURM_JOB_ACCOUNT}"
SIF="${SIF:?SIF=<vllm image> required}"
HF_CACHE="${HF_CACHE:?HF_CACHE=<dir> required}"
REPOS="${REPOS:-Qwen/Qwen3.8-27B-FP8 speakleash/Bielik-11B-v3.0-Instruct-FP8-Dynamic}"
mkdir -p "$PD/runs" "$HF_CACHE"
LOG="$PD/runs/${SLURM_JOB_ID}-fetch.log"
exec > >(tee -a "$LOG") 2>&1

export HF_HOME="$HF_CACHE" HF_HUB_DISABLE_XET=1 HF_HUB_DISABLE_TELEMETRY=1
if [ -f "$PD/.hf_token" ]; then export HF_TOKEN="$(cat "$PD/.hf_token")"; fi   # optional, never logged
export APPTAINER_TMPDIR="$TMPDIR/apptainer"
mkdir -p "$APPTAINER_TMPDIR"

# shellcheck disable=SC2086
apptainer exec -B /lustre "$SIF" python3 - $REPOS <<'PY'
import json, pathlib, sys
from huggingface_hub import snapshot_download

failed = []
for repo in sys.argv[1:]:
    path = None
    for attempt in (1, 2, 3):
        try:
            path = pathlib.Path(snapshot_download(repo, max_workers=8))
            break
        except Exception as exc:  # network hiccup: bounded retries inside the job, never on the login node
            print(f"{repo}: attempt {attempt} failed: {type(exc).__name__}")
    if path is None:
        failed.append(repo)
        continue
    # A download can end without every shard: check each safetensors file named in the index.
    idx = path / "model.safetensors.index.json"
    names = set(json.loads(idx.read_text())["weight_map"].values()) if idx.exists() else {p.name for p in path.glob("*.safetensors")}
    missing = [n for n in names if not (path / n).exists()]
    print(f"{repo}: {len(names)} shards, {len(missing)} missing, {path}")
    if missing or not names:
        failed.append(repo)
sys.exit(1 if failed else 0)
PY
echo "fetch done"
