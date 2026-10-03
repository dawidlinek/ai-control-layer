#!/bin/bash
# One-time setup on WCSS (CPU job, no GPU hours): build the vLLM venv archive and download weights to PD.
#   submit (account is chosen explicitly, it decides whose grant pays):
#     sbatch --parsable -A <account> deploy-wcss/setup.sbatch
# Outputs: $PD/llm-stack/vllm.tar, $PD/models/<MODEL_DIR>/, log in $PD/runs/<jobid>-setup.log

#SBATCH --job-name=acl-llm-setup
#SBATCH --partition=lem-cpu-short           # build on Lem (AlmaLinux 9) = same OS as the GPU nodes
#SBATCH --cpus-per-task=16
#SBATCH --mem=64gb
#SBATCH --time=3:00:00
#SBATCH --output=acl-llm-setup_%j.out
#SBATCH --error=acl-llm-setup_%j.err

set -euo pipefail
PD="/lustre/pd03/${SLURM_JOB_ACCOUNT}"
MODEL_REPO="${MODEL_REPO:-Qwen/Qwen3.8-27B-FP8}"
MODEL_DIR="${MODEL_DIR:-qwen3.8-27b-fp8}"
mkdir -p "$PD/llm-stack" "$PD/models" "$PD/runs"
LOG="$PD/runs/${SLURM_JOB_ID}-setup.log"
exec > >(tee -a "$LOG") 2>&1

source /usr/local/sbin/modules.sh
module load Python/3.12.3-GCCcore-13.3.0

# --- 1. vLLM venv -> one archive on PD (unpacked per node by serve.sbatch) ---
if [ ! -f "$PD/llm-stack/vllm.tar" ] || [ "${REBUILD:-0}" = 1 ]; then
    export PIP_CACHE_DIR="$TMPDIR/pipcache"          # never $HOME (50 GB quota)
    python -m venv "$TMPDIR/venv"
    "$TMPDIR/venv/bin/pip" install --upgrade pip
    "$TMPDIR/venv/bin/pip" install vllm "huggingface_hub[cli]"
    "$TMPDIR/venv/bin/python" -c "import vllm; print('vllm', vllm.__version__)"
    tar -C "$TMPDIR" -cf "$PD/llm-stack/vllm.tar.tmp" venv && mv "$PD/llm-stack/vllm.tar.tmp" "$PD/llm-stack/vllm.tar"
    HF="$TMPDIR/venv/bin/hf"
else
    echo "vllm.tar exists; set REBUILD=1 to rebuild"
    python -m venv "$TMPDIR/hfenv" && "$TMPDIR/hfenv/bin/pip" install -q "huggingface_hub[cli]"
    HF="$TMPDIR/hfenv/bin/hf"
fi

# --- 2. weights -> PD (token optional: a mode-600 file, never in the script or log) ---
export HF_HOME="$TMPDIR/hf" HF_HUB_DISABLE_XET=1
if [ -f "$PD/.hf_token" ]; then export HF_TOKEN="$(cat "$PD/.hf_token")"; fi
for attempt in 1 2 3; do
    "$HF" download "$MODEL_REPO" --local-dir "$PD/models/$MODEL_DIR" --max-workers 16 && break
    echo "download attempt $attempt failed; retrying"
done
# Xet/CAS can exit 0 with missing shards: verify every safetensors shard named in the index exists.
"$TMPDIR"/*/bin/python - "$PD/models/$MODEL_DIR" <<'PY'
import json, pathlib, sys
d = pathlib.Path(sys.argv[1]); idx = d / "model.safetensors.index.json"
names = set(json.loads(idx.read_text())["weight_map"].values()) if idx.exists() else {p.name for p in d.glob("*.safetensors")}
missing = [n for n in names if not (d / n).exists()]
print(f"shards: {len(names)} expected, {len(missing)} missing")
sys.exit(1 if missing or not names else 0)
PY
echo "setup done: $PD/llm-stack/vllm.tar, $PD/models/$MODEL_DIR"
