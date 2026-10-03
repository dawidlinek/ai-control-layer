#!/bin/bash
# Serve one model with vLLM (OpenAI-compatible) on a Lem H100 for the AI Control Layer gateway.
#   sbatch --parsable -A <account> deploy/wcss/serve.sbatch
# Publishes "<host> <port> <jobid>" to $PD/serve/endpoint; reach it with `uv run python scripts/wcss.py tunnel`.
# The login node cannot open TCP to compute nodes, so the job dials out instead: a reverse forward to
# 127.0.0.1:<port> on ui.wcss.pl with ~/.ssh/acl_tunnel, whose authorized_keys line is
#   restrict,port-forwarding,permitlisten="127.0.0.1:*",from="10.*,156.17.*" ssh-ed25519 ... acl-tunnel
# The endpoint requires the API key in $PD/.llm_api_key (mode 600; same value as LOCAL_LLM_API_KEY in .env).
# Two runtimes: the venv archive built by setup.sbatch (default), or an existing vLLM apptainer image
# with weights resolved offline from an HF cache:
#   --export=ALL,SIF=<path>.sif,MODEL=Qwen/Qwen3.8-27B,HF_CACHE=<pd>/hf_cache

#SBATCH --job-name=acl-llm-serve
#SBATCH --partition=lem-gpu-short
#SBATCH --gres=gpu:hopper:1,storage:local:100g
#SBATCH --cpus-per-task=16                  # <= 16 per GPU
#SBATCH --mem=200gb                         # <= 250 GB per GPU
#SBATCH --time=4:00:00
#SBATCH --signal=B:TERM@120
#SBATCH --output=acl-llm-serve_%j.out
#SBATCH --error=acl-llm-serve_%j.err

set -uo pipefail
PD="/lustre/pd03/${SLURM_JOB_ACCOUNT}"
MODEL_DIR="${MODEL_DIR:-qwen3.8-27b-fp8}"
MODEL="${MODEL:-$PD/models/$MODEL_DIR}"     # a local path, or an HF id resolved from HF_CACHE
SIF="${SIF:-}"                              # apptainer image with vLLM; empty = setup.sbatch's venv archive
HF_CACHE="${HF_CACHE:-}"
SERVED_NAME="${SERVED_NAME:-qwen3.8-27b}"
PORT="${PORT:-$((20000 + SLURM_JOB_ID % 10000))}"   # per job: a GPU node is shared by up to 4 jobs
MAX_LEN="${MAX_LEN:-131072}"
MAX_SEQS="${MAX_SEQS:-256}"                 # hybrid Mamba models (Qwen3.8): <= the Mamba cache blocks vLLM reports
TOOL_PARSER="${TOOL_PARSER:-qwen3_coder}"
REASONING_PARSER="${REASONING_PARSER:-qwen3}"
mkdir -p "$PD/runs" "$PD/serve"
test -s "$PD/.llm_api_key" || { echo "missing $PD/.llm_api_key"; exit 2; }

export PYTHONNOUSERSITE=1 OMP_NUM_THREADS=8
export DG_JIT_CACHE_DIR="$PD/llm-stack/dg-cache"
export DG_CACHE_DIR="$PD/llm-stack/dg-cache"
export TRITON_CACHE_DIR="$TMPDIR/triton-cache"
export VLLM_CACHE_ROOT="$TMPDIR/vllm-cache"
mkdir -p "$DG_JIT_CACHE_DIR" "$TRITON_CACHE_DIR" "$VLLM_CACHE_ROOT"
if [ -n "$HF_CACHE" ]; then
    export HF_HOME="$HF_CACHE" HF_HUB_OFFLINE=1 HF_HUB_DISABLE_TELEMETRY=1
else
    export HF_HOME="$TMPDIR/hf"
fi

if [ -n "$SIF" ]; then
    test -s "$SIF" || { echo "missing image $SIF"; exit 2; }
    export APPTAINER_TMPDIR="$TMPDIR/apptainer"
    mkdir -p "$APPTAINER_TMPDIR"
    VLLM=(apptainer exec --nv -B /lustre -B "$TMPDIR" "$SIF" vllm)   # the environment passes through
else
    source /usr/local/sbin/modules.sh
    module load Python/3.12.3-GCCcore-13.3.0    # the venv links against this module's libpython
    module load CUDA/13.0.0                     # nothing else sets CUDA_HOME on GPU nodes
    tar -xf "$PD/llm-stack/vllm.tar" -C "$TMPDIR"
    for f in "$TMPDIR"/venv/bin/*; do
        [ -f "$f" ] && [ "$(head -c2 "$f" 2>/dev/null)" = '#!' ] && sed -i "1s|.*|#!$TMPDIR/venv/bin/python|" "$f"
    done
    VLLM=("$TMPDIR/venv/bin/vllm")
fi

TUNNEL_KEY="${TUNNEL_KEY:-$HOME/.ssh/acl_tunnel}"
ENDPOINT_HOST="$(hostname -s)" BIND=0.0.0.0
if [ -s "$TUNNEL_KEY" ]; then
    # one attempt, no retry loop (WCSS safety rule); the job's cgroup ends it with the job
    ssh -i "$TUNNEL_KEY" -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=accept-new \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -N \
        -R "127.0.0.1:$PORT:127.0.0.1:$PORT" ui.wcss.pl > "$PD/runs/${SLURM_JOB_ID}-tunnel.log" 2>&1 &
    ENDPOINT_HOST=localhost BIND=127.0.0.1   # reachable only through the tunnel
fi
echo "$ENDPOINT_HOST $PORT $SLURM_JOB_ID" > "$PD/serve/endpoint"
LOG="$PD/runs/${SLURM_JOB_ID}-serve.log"
echo "serving $MODEL as $SERVED_NAME on $(hostname -s) $BIND:$PORT (endpoint $ENDPOINT_HOST), log $LOG"

# API key read from a file by the shell; vLLM reads VLLM_API_KEY (never on the command line / in the log).
VLLM_API_KEY="$(cat "$PD/.llm_api_key")" exec "${VLLM[@]}" serve "$MODEL" \
    --served-model-name "$SERVED_NAME" \
    --host "$BIND" --port "$PORT" \
    --max-model-len "$MAX_LEN" \
    --max-num-seqs "$MAX_SEQS" \
    --gpu-memory-utilization 0.90 \
    --enable-auto-tool-choice --tool-call-parser "$TOOL_PARSER" \
    --reasoning-parser "$REASONING_PARSER" \
    --default-chat-template-kwargs '{"enable_thinking": false}' \
    > "$LOG" 2>&1
