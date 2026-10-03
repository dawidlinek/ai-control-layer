#!/bin/bash
# Serve one model with vLLM (OpenAI-compatible) on a Lem H100 for the AI Control Layer gateway.
#   sbatch --parsable -A <account> deploy-wcss/serve.sbatch
# Publishes "<node> <port>" to $PD/serve/endpoint; reach it with `uv run python scripts/wcss.py tunnel`.
# The endpoint requires the API key in $PD/.llm_api_key (mode 600; same value as LOCAL_LLM_API_KEY in .env).

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
SERVED_NAME="${SERVED_NAME:-qwen3.8-27b}"
PORT="${PORT:-8000}"
MAX_LEN="${MAX_LEN:-32768}"
TOOL_PARSER="${TOOL_PARSER:-qwen3_coder}"
REASONING_PARSER="${REASONING_PARSER:-qwen3}"
mkdir -p "$PD/runs" "$PD/serve"
test -s "$PD/.llm_api_key" || { echo "missing $PD/.llm_api_key"; exit 2; }

source /usr/local/sbin/modules.sh
module load Python/3.12.3-GCCcore-13.3.0    # the venv links against this module's libpython
module load CUDA/13.0.0                     # nothing else sets CUDA_HOME on GPU nodes

export HF_HOME="$TMPDIR/hf" PYTHONNOUSERSITE=1 OMP_NUM_THREADS=8
export DG_JIT_CACHE_DIR="$PD/llm-stack/dg-cache"
export DG_CACHE_DIR="$PD/llm-stack/dg-cache"
export TRITON_CACHE_DIR="$PD/llm-stack/triton-cache"
export VLLM_CACHE_ROOT="$PD/llm-stack/vllm-cache"
mkdir -p "$DG_JIT_CACHE_DIR" "$TRITON_CACHE_DIR" "$VLLM_CACHE_ROOT"

tar -xf "$PD/llm-stack/vllm.tar" -C "$TMPDIR"
for f in "$TMPDIR"/venv/bin/*; do
    [ -f "$f" ] && [ "$(head -c2 "$f" 2>/dev/null)" = '#!' ] && sed -i "1s|.*|#!$TMPDIR/venv/bin/python|" "$f"
done
export PATH="$TMPDIR/venv/bin:$PATH"

echo "$(hostname -s) $PORT $SLURM_JOB_ID" > "$PD/serve/endpoint"
LOG="$PD/runs/${SLURM_JOB_ID}-serve.log"
echo "serving $MODEL_DIR as $SERVED_NAME on $(hostname -s):$PORT, log $LOG"

# API key read from a file by the shell; vLLM reads VLLM_API_KEY (never on the command line / in the log).
VLLM_API_KEY="$(cat "$PD/.llm_api_key")" exec vllm serve "$PD/models/$MODEL_DIR" \
    --served-model-name "$SERVED_NAME" \
    --host 0.0.0.0 --port "$PORT" \
    --max-model-len "$MAX_LEN" \
    --gpu-memory-utilization 0.90 \
    --enable-auto-tool-choice --tool-call-parser "$TOOL_PARSER" \
    --reasoning-parser "$REASONING_PARSER" \
    --default-chat-template-kwargs '{"enable_thinking": false}' \
    > "$LOG" 2>&1
