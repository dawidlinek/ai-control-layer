#!/bin/bash
# Serve one or two models with vLLM (OpenAI-compatible) on one Lem H100 for the AI Control Layer gateway.
#   sbatch --parsable -A <account> [--time=HH:MM:SS] deploy/wcss/serve.sbatch
# Publishes one line "<host> <port> <jobid> <served name>" per model to $PD/serve/endpoint; reach them with
# `uv run python scripts/wcss.py tunnel` (first line -> 127.0.0.1:8001, second -> :8002).
# Second model (optional, same GPU, its own vLLM server and port): MODEL2=<hf id or path>, SERVED_NAME2, MAX_LEN2,
# MAX_SEQS2, GPU_UTIL2. Third model (optional, e.g. an embeddings model): MODEL3, SERVED_NAME3, MAX_LEN3, GPU_UTIL3,
# ARGS3 (default `--runner pooling`). Keep GPU_UTIL + GPU_UTIL2 + GPU_UTIL3 <= 0.9. Each further server starts only after
# the previous one is healthy (servers profiling GPU memory at once misread each other's allocations).
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
#SBATCH --cpus-per-task=8                   # <= 16 per GPU; cores are billed too (4 per vLLM server)
#SBATCH --mem=64gb                          # <= 250 GB per GPU
#SBATCH --time=4:00:00                      # override per run: sbatch --time=... (lem-gpu-short <= 3 days)
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
GPU_UTIL="${GPU_UTIL:-0.90}"
MODEL2="${MODEL2:-}"                        # e.g. speakleash/Bielik-11B-v3.0-Instruct-FP8-Dynamic
SERVED_NAME2="${SERVED_NAME2:-bielik-11b}"
PORT2="${PORT2:-$((30000 + SLURM_JOB_ID % 10000))}"
MAX_LEN2="${MAX_LEN2:-32768}"
MAX_SEQS2="${MAX_SEQS2:-64}"
GPU_UTIL2="${GPU_UTIL2:-0.30}"
MODEL3="${MODEL3:-}"                        # e.g. Qwen/Qwen3-Embedding-0.6B
SERVED_NAME3="${SERVED_NAME3:-qwen3-embedding-0.6b}"
PORT3="${PORT3:-$((40000 + SLURM_JOB_ID % 10000))}"
MAX_LEN3="${MAX_LEN3:-8192}"
GPU_UTIL3="${GPU_UTIL3:-0.07}"
ARGS3="${ARGS3:---runner pooling}"
mkdir -p "$PD/runs" "$PD/serve"
test -s "$PD/.llm_api_key" || { echo "missing $PD/.llm_api_key"; exit 2; }

export PYTHONNOUSERSITE=1 OMP_NUM_THREADS=2
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
    FORWARDS=(-R "127.0.0.1:$PORT:127.0.0.1:$PORT")
    [ -n "$MODEL2" ] && FORWARDS+=(-R "127.0.0.1:$PORT2:127.0.0.1:$PORT2")
    [ -n "$MODEL3" ] && FORWARDS+=(-R "127.0.0.1:$PORT3:127.0.0.1:$PORT3")
    # one attempt, no retry loop (WCSS safety rule); the job's cgroup ends it with the job
    ssh -i "$TUNNEL_KEY" -o BatchMode=yes -o NumberOfPasswordPrompts=0 -o StrictHostKeyChecking=accept-new \
        -o ExitOnForwardFailure=yes -o ServerAliveInterval=30 -N \
        "${FORWARDS[@]}" ui.wcss.pl > "$PD/runs/${SLURM_JOB_ID}-tunnel.log" 2>&1 &
    ENDPOINT_HOST=localhost BIND=127.0.0.1   # reachable only through the tunnel
fi
{
    echo "$ENDPOINT_HOST $PORT $SLURM_JOB_ID $SERVED_NAME"
    [ -n "$MODEL2" ] && echo "$ENDPOINT_HOST $PORT2 $SLURM_JOB_ID $SERVED_NAME2"
    [ -n "$MODEL3" ] && echo "$ENDPOINT_HOST $PORT3 $SLURM_JOB_ID $SERVED_NAME3"
} > "$PD/serve/endpoint"
LOG="$PD/runs/${SLURM_JOB_ID}-serve.log"
echo "serving $MODEL as $SERVED_NAME on $(hostname -s) $BIND:$PORT (endpoint $ENDPOINT_HOST), log $LOG"

# API key read from a file by the shell; vLLM reads VLLM_API_KEY (never on the command line / in the log).
VLLM_API_KEY="$(cat "$PD/.llm_api_key")"
export VLLM_API_KEY
"${VLLM[@]}" serve "$MODEL" \
    --served-model-name "$SERVED_NAME" \
    --host "$BIND" --port "$PORT" \
    --max-model-len "$MAX_LEN" \
    --max-num-seqs "$MAX_SEQS" \
    --gpu-memory-utilization "$GPU_UTIL" \
    --enable-auto-tool-choice --tool-call-parser "$TOOL_PARSER" \
    --reasoning-parser "$REASONING_PARSER" \
    --default-chat-template-kwargs '{"enable_thinking": false}' \
    > "$LOG" 2>&1 &
PIDS=($!)
PREV_PORT=$PORT
trap 'kill -TERM "${PIDS[@]}" 2>/dev/null; wait' TERM INT

wait_healthy() {  # bounded (20 min): the previous server must be up before the next one profiles the GPU
    for _ in $(seq 120); do
        curl -fs -o /dev/null "http://127.0.0.1:$1/health" && return 0
        kill -0 "$2" 2>/dev/null || { echo "server on port $1 exited; see the logs in $PD/runs"; exit 1; }
        sleep 10
    done
    echo "server on port $1 not healthy after 20 min"; exit 1
}

if [ -n "$MODEL2" ]; then
    wait_healthy "$PORT" "${PIDS[0]}"
    LOG2="$PD/runs/${SLURM_JOB_ID}-serve2.log"
    echo "serving $MODEL2 as $SERVED_NAME2 on $BIND:$PORT2, log $LOG2"
    "${VLLM[@]}" serve "$MODEL2" \
        --served-model-name "$SERVED_NAME2" \
        --host "$BIND" --port "$PORT2" \
        --max-model-len "$MAX_LEN2" \
        --max-num-seqs "$MAX_SEQS2" \
        --gpu-memory-utilization "$GPU_UTIL2" \
        > "$LOG2" 2>&1 &
    PIDS+=($!)
    PREV_PORT=$PORT2
fi
if [ -n "$MODEL3" ]; then
    wait_healthy "$PREV_PORT" "${PIDS[-1]}"
    LOG3="$PD/runs/${SLURM_JOB_ID}-serve3.log"
    echo "serving $MODEL3 as $SERVED_NAME3 on $BIND:$PORT3, log $LOG3"
    # shellcheck disable=SC2086
    "${VLLM[@]}" serve "$MODEL3"         --served-model-name "$SERVED_NAME3"         --host "$BIND" --port "$PORT3"         --max-model-len "$MAX_LEN3"         --gpu-memory-utilization "$GPU_UTIL3"         $ARGS3         > "$LOG3" 2>&1 &
    PIDS+=($!)
fi
# the job ends when any server exits (no half-up state with a stale endpoint)
wait -n "${PIDS[@]}"
echo "a server exited (status $?); stopping"
kill -TERM "${PIDS[@]}" 2>/dev/null
wait
