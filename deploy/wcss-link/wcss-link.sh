#!/bin/sh
# wcss-link: hold one SSH local forward from this container to the vLLM server that the current
# acl-llm-serve job on WCSS exposes on the login node (reverse tunnel, see deploy/wcss/serve.sbatch).
#
#   0.0.0.0:LISTEN_PORT+i  ──ssh -L──►  ui.wcss.pl  ──►  <host_i>:<port_i>  (vLLM; i = endpoint line, one ssh -N)
#
# /health on LISTEN_PORT is vLLM's own /health, passed through the forward (no API key needed for it).
# WCSS safety: key auth only (no password prompts, ever), pinned host key, no tight loops, and on an
# authentication or host-key failure the container exits 78 and stays down. See README.md.
set -u

# ---- configuration -------------------------------------------------------------------------------
WCSS_HOST="${WCSS_HOST:-ui.wcss.pl}"
WCSS_USER="${WCSS_USER:-}"
WCSS_ACCOUNT="${WCSS_ACCOUNT:-}"
LISTEN_PORT="${LISTEN_PORT:-8001}"
MODEL_CHECK="${MODEL_CHECK-qwen3.8-27b}"      # expected served name of the first line (warning only); "" = off
ENDPOINT_CMD="${ENDPOINT_CMD:-cat}"           # cat | endpoint (forced command acl-ctl.sh on the cluster)
KEY_SRC=/run/secrets/wcss_key
KNOWN_HOSTS=/run/secrets/known_hosts
CHECK_PORT="${CHECK_PORT:-18001}"             # loopback-only port for checking a new endpoint before a swap
POLL_SECONDS="${POLL_SECONDS:-300}"           # endpoint re-read interval while a forward is up
BACKOFF_MIN="${BACKOFF_MIN:-60}"
BACKOFF_MAX="${BACKOFF_MAX:-900}"
MAX_LINES=8                                   # endpoint lines forwarded (LISTEN_PORT .. +7)
TICK=15                                       # liveness check of the local ssh process (no network traffic)

EX_CONFIG=78

log() { printf '%s wcss-link: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

cleanup() {
    [ -n "${FWD_PID:-}" ] && kill "$FWD_PID" 2>/dev/null
    [ -n "${CHK_PID:-}" ] && kill "$CHK_PID" 2>/dev/null
    [ -n "${RUN_DIR:-}" ] && rm -rf "$RUN_DIR"
}

die_config() {
    log "FATAL: $*"
    log "staying down (exit $EX_CONFIG); fix the configuration and start the container again"
    cleanup
    exit "$EX_CONFIG"
}

# validators: the values end up in ssh arguments / the remote command, so whitelist characters
is_name() { case "$1" in '' | *[!a-z0-9-]*) return 1 ;; esac; return 0; }
is_host() { case "$1" in '' | *[!A-Za-z0-9.-]*) return 1 ;; esac; return 0; }
is_port() {
    case "$1" in '' | *[!0-9]*) return 1 ;; esac
    [ "${#1}" -le 5 ] && [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}
is_int() { case "$1" in '' | *[!0-9]*) return 1 ;; esac; return 0; }

[ -n "$WCSS_USER" ] || die_config "WCSS_USER is not set"
[ -n "$WCSS_ACCOUNT" ] || die_config "WCSS_ACCOUNT is not set"
is_name "$WCSS_USER" || die_config "WCSS_USER must match [a-z0-9-]+"
is_name "$WCSS_ACCOUNT" || die_config "WCSS_ACCOUNT must match [a-z0-9-]+"
is_host "$WCSS_HOST" || die_config "WCSS_HOST must match [A-Za-z0-9.-]+"
is_port "$LISTEN_PORT" || die_config "LISTEN_PORT must be a port number"
is_port "$CHECK_PORT" || die_config "CHECK_PORT must be a port number"
[ "$LISTEN_PORT" -le $((65535 - MAX_LINES)) ] || die_config "LISTEN_PORT too high (needs LISTEN_PORT+$MAX_LINES)"
[ "$CHECK_PORT" -lt "$LISTEN_PORT" ] || [ "$CHECK_PORT" -ge $((LISTEN_PORT + MAX_LINES)) ] ||
    die_config "CHECK_PORT must be outside LISTEN_PORT..LISTEN_PORT+$((MAX_LINES - 1))"
for v in POLL_SECONDS BACKOFF_MIN BACKOFF_MAX; do
    eval "val=\$$v"
    is_int "$val" && [ "$val" -ge 10 ] || die_config "$v must be an integer >= 10"
done
case "$MODEL_CHECK" in *[!A-Za-z0-9._-]*) die_config "MODEL_CHECK must match [A-Za-z0-9._-]*" ;; esac
case "$ENDPOINT_CMD" in
    cat) REMOTE_CMD="cat /lustre/pd03/$WCSS_ACCOUNT/serve/endpoint" ;;
    endpoint) REMOTE_CMD="endpoint" ;;
    *) die_config "ENDPOINT_CMD must be 'cat' (default) or 'endpoint'" ;;
esac
TARGET="$WCSS_USER@$WCSS_HOST"

# ---- secrets: ssh refuses a private key readable by others, and the mount is read-only ------------
[ -r "$KEY_SRC" ] && [ -s "$KEY_SRC" ] ||
    die_config "private key $KEY_SRC is missing, empty or not readable by uid $(id -u)"
[ -r "$KNOWN_HOSTS" ] && [ -s "$KNOWN_HOSTS" ] ||
    die_config "pinned known_hosts $KNOWN_HOSTS is missing, empty or not readable by uid $(id -u)"

umask 077
RUN_DIR=""
for base in /dev/shm "${HOME:-/tmp}" /tmp; do
    if [ -d "$base" ] && [ -w "$base" ]; then
        RUN_DIR="$(mktemp -d "$base/wcss-link.XXXXXX" 2>/dev/null)" && break
        RUN_DIR=""
    fi
done
[ -n "$RUN_DIR" ] || die_config "no writable directory for the key copy (tried /dev/shm, \$HOME, /tmp)"
KEY="$RUN_DIR/id"
cp "$KEY_SRC" "$KEY" && chmod 600 "$KEY" || die_config "could not copy the private key to $RUN_DIR"

SSH_OPTS="-F /dev/null -T
 -o BatchMode=yes -o NumberOfPasswordPrompts=0
 -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no
 -o IdentitiesOnly=yes -o IdentityAgent=none -i $KEY
 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o GlobalKnownHostsFile=/dev/null
 -o UpdateHostKeys=no
 -o ConnectTimeout=20 -o ServerAliveInterval=30 -o ServerAliveCountMax=3
 -o LogLevel=ERROR"
# (word splitting of SSH_OPTS is intended; no value in it contains spaces: paths come from validated
#  defaults/env and mktemp)

FWD_PID="" FWD_DESC="" CUR="" HEALTH=""
FWD_ERR="$RUN_DIR/forward.err" CHK_ERR="$RUN_DIR/check.err" EP_OUT="$RUN_DIR/endpoint.out" EP_ERR="$RUN_DIR/endpoint.err"

on_signal() {
    log "stopping"
    cleanup
    exit 0
}
trap on_signal TERM INT HUP

# last lines of an ssh stderr file, printable characters only, bounded length (ssh never prints key material)
err_tail() { tail -n 3 "$1" 2>/dev/null | tr -cd '[:print:]\n' | cut -c1-240 | tr '\n' ' '; }

# authentication / host key problems never fix themselves: stop and stay down (never retry: 3 failed
# logins lock the account for 24 h, and a changed host key must be checked by a human)
fatal_if_auth() {
    if grep -q -e 'Permission denied' -e 'Too many authentication failures' "$1" 2>/dev/null; then
        die_config "authentication to $WCSS_HOST as $WCSS_USER was refused (Permission denied). Check the" \
            "authorized_keys line on WCSS (key, from= egress IP) and the key mounted at $KEY_SRC"
    fi
    if grep -q -e 'Host key verification failed' -e 'REMOTE HOST IDENTIFICATION HAS CHANGED' "$1" 2>/dev/null; then
        die_config "host key verification for $WCSS_HOST failed: the pinned key in $KNOWN_HOSTS does not match" \
            "or is missing. Verify the server's fingerprint out of band before updating it"
    fi
    if grep -q -e 'invalid format' -e 'bad permissions' -e 'UNPROTECTED PRIVATE KEY' "$1" 2>/dev/null; then
        die_config "the private key at $KEY_SRC cannot be used by ssh (format/permissions)"
    fi
}

BACKOFF="$BACKOFF_MIN"
wait_backoff() {
    log "retrying in ${BACKOFF}s"
    sleep "$BACKOFF" &
    wait $!
    BACKOFF=$((BACKOFF * 2))
    [ "$BACKOFF" -le "$BACKOFF_MAX" ] || BACKOFF="$BACKOFF_MAX"
}

# Read the endpoint file with one short ssh call. Sets EP_HOST EP_PORT EP_JOB EP_NAME EP_KEY.
# Returns 0 = endpoint found, 1 = no (matching) serve job, 2 = network/ssh error. Exits on auth failure.
read_endpoint() {
    # shellcheck disable=SC2086
    ssh $SSH_OPTS "$TARGET" "$REMOTE_CMD" </dev/null >"$EP_OUT" 2>"$EP_ERR"
    rc=$?
    if [ "$rc" -eq 255 ]; then # ssh's own failure (network, auth, host key); remote errors use other codes
        fatal_if_auth "$EP_ERR"
        log "could not reach $WCSS_HOST to read the endpoint: $(err_tail "$EP_ERR")"
        return 2
    fi
    # the file content is data: parse at most MAX_LINES lines, whitelist every field.
    # line i (0-based, counting non-empty lines) is forwarded to LISTEN_PORT + i
    malformed=0 i=0 EP_SPECS="" EP_KEY="" EP_DESC="" first_ok=""
    while IFS=' ' read -r h p j name _rest; do
        [ -n "$h" ] || continue
        [ "$i" -lt "$MAX_LINES" ] || break
        lport=$((LISTEN_PORT + i))
        if ! is_name "$h" || ! is_port "$p"; then
            malformed=$((malformed + 1))
            EP_KEY="$EP_KEY x"
            i=$((i + 1))
            continue
        fi
        is_int "$j" || j="?"
        case "$name" in '' | *[!A-Za-z0-9._-]*) name="?" ;; esac
        if [ "$i" -eq 0 ]; then
            first_ok=1 EP_JOB="$j" EP_HOST="$h" EP_PORT="$p" EP_NAME="$name"
        fi
        EP_SPECS="$EP_SPECS $lport:$h:$p"
        EP_KEY="$EP_KEY $h:$p"
        EP_DESC="$EP_DESC${EP_DESC:+, }:$lport -> $h:$p ($name, job $j)"
        i=$((i + 1))
    done <<EOF
$(head -n 16 "$EP_OUT" | tr -d '\r')
EOF
    [ "$malformed" -eq 0 ] || log "ignored $malformed malformed endpoint line(s)"
    if [ -z "$first_ok" ]; then
        if [ "$rc" -ne 0 ] || [ ! -s "$EP_OUT" ]; then
            log "no serve job running (endpoint missing or empty)"
        else
            log "no serve job running (first endpoint line is malformed; it must serve :$LISTEN_PORT)"
        fi
        return 1
    fi
    if [ -n "$MODEL_CHECK" ] && [ "$EP_NAME" != "$MODEL_CHECK" ]; then
        log "warning: first endpoint line serves '$EP_NAME', expected '$MODEL_CHECK' on :$LISTEN_PORT"
    fi
    return 0
}

# Start one `ssh -N` in the background. Sets STARTED_PID.
#   $1 = all:   -L 0.0.0.0:<LISTEN_PORT+i>:<host_i>:<port_i> for every endpoint line
#   $1 = check: -L 127.0.0.1:<CHECK_PORT>:<host_0>:<port_0> only (the line whose /health is checked)
# Returns 0 if it is still running after a few seconds (connected, forwards bound), 1 otherwise.
start_forward() {
    mode="$1" errf="$2" fwd_args=""
    if [ "$mode" = check ]; then
        fwd_args="-L 127.0.0.1:$CHECK_PORT:$EP_HOST:$EP_PORT"
    else
        for spec in $EP_SPECS; do fwd_args="$fwd_args -L 0.0.0.0:$spec"; done
    fi
    # shellcheck disable=SC2086
    ssh $SSH_OPTS -N -o ExitOnForwardFailure=yes -o GatewayPorts=yes $fwd_args "$TARGET" \
        </dev/null >/dev/null 2>"$errf" &
    STARTED_PID=$!
    n=0
    while [ "$n" -lt 8 ]; do
        sleep 1
        kill -0 "$STARTED_PID" 2>/dev/null || {
            wait "$STARTED_PID"
            fatal_if_auth "$errf"
            log "ssh forward ($mode) failed to start: $(err_tail "$errf")"
            STARTED_PID=""
            return 1
        }
        n=$((n + 1))
    done
    return 0
}

health() { # $1 = local port; 0 when vLLM answers /health with 200 through the forward
    curl -fsS -o /dev/null -m 10 --retry 3 --retry-connrefused --retry-delay 2 \
        "http://127.0.0.1:$1/health" 2>/dev/null
}

report_health() {
    if health "$LISTEN_PORT"; then now_h=up; else now_h=down; fi
    if [ "$now_h" != "$HEALTH" ]; then
        if [ "$now_h" = up ]; then
            log "upstream healthy: :$LISTEN_PORT/health -> 200"
        else
            log "upstream :$LISTEN_PORT not healthy through the forward; vLLM may still be starting or the job ended"
        fi
        HEALTH="$now_h"
    fi
}

describe() { echo "$EP_DESC"; }

# ---- main loop ------------------------------------------------------------------------------------
log "starting: $TARGET, account $WCSS_ACCOUNT, mode $ENDPOINT_CMD, endpoint line i -> 0.0.0.0:$LISTEN_PORT+i"
NEXT_READ=0
while :; do
    # 1. the forward died (connection lost, server keepalive timeout, job's tunnel gone at the sshd side)
    if [ -n "$FWD_PID" ] && ! kill -0 "$FWD_PID" 2>/dev/null; then
        wait "$FWD_PID"
        rc=$?
        fatal_if_auth "$FWD_ERR"
        log "forward ($FWD_DESC) exited with status $rc: $(err_tail "$FWD_ERR")"
        FWD_PID="" CUR="" HEALTH=""
        wait_backoff
        NEXT_READ=0
        continue
    fi

    now=$(date +%s)
    if [ "$now" -ge "$NEXT_READ" ]; then
        read_endpoint
        r=$?
        if [ "$r" -ne 0 ]; then
            if [ -z "$FWD_PID" ]; then
                wait_backoff
                NEXT_READ=0
                continue
            fi
            # keep a running forward on a transient error or an empty read; check again next period
            NEXT_READ=$((now + POLL_SECONDS))
        elif [ -z "$FWD_PID" ]; then
            # nothing to protect: bind the listen port directly
            if start_forward all "$FWD_ERR"; then
                FWD_PID="$STARTED_PID" CUR="$EP_KEY" FWD_DESC="$(describe)" HEALTH=""
                log "forward up via $WCSS_HOST: $FWD_DESC"
                NEXT_READ=$((now + POLL_SECONDS))
            else
                wait_backoff
                NEXT_READ=0
                continue
            fi
        elif [ "$EP_KEY" != "$CUR" ]; then
            # a new job published its endpoint: check it on a loopback port, then swap (short gap)
            log "endpoint changed: $(describe); checking /health of the first line on 127.0.0.1:$CHECK_PORT"
            ok=""
            if start_forward check "$CHK_ERR"; then
                CHK_PID="$STARTED_PID"
                health "$CHECK_PORT" && ok=1
                kill "$CHK_PID" 2>/dev/null
                wait "$CHK_PID" 2>/dev/null
                CHK_PID=""
            fi
            if [ -n "$ok" ]; then
                log "new endpoint healthy; swapping the forward"
                kill "$FWD_PID" 2>/dev/null
                wait "$FWD_PID" 2>/dev/null
                FWD_PID="" CUR="" HEALTH=""
                if start_forward all "$FWD_ERR"; then
                    FWD_PID="$STARTED_PID" CUR="$EP_KEY" FWD_DESC="$(describe)"
                    log "forward up via $WCSS_HOST: $FWD_DESC"
                    BACKOFF="$BACKOFF_MIN"
                else
                    wait_backoff
                    NEXT_READ=0
                    continue
                fi
            else
                log "new endpoint not healthy yet; keeping the current forward"
            fi
            NEXT_READ=$((now + POLL_SECONDS))
        else
            # same endpoint and the forward survived a whole period: a stable success
            BACKOFF="$BACKOFF_MIN"
            NEXT_READ=$((now + POLL_SECONDS))
        fi
        [ -n "$FWD_PID" ] && report_health
    fi

    sleep "$TICK" &
    wait $!
done
