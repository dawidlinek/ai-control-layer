# wcss-link

A sidecar that makes the vLLM servers of the current `acl-llm-serve` job on WCSS reachable inside the
compose network: endpoint line i is served on `http://wcss-link:(8001+i)`, so with today's job
`:8001` = qwen3.8-27b, `:8002` = bielik-11b, `:8003` = qwen3-embedding-0.6b (the order of the lines in
the endpoint file decides it). The gateway uses `LOCAL_LLM_BASE_URL=http://wcss-link:8001/v1`.

```
gateway ──► wcss-link:8001 ──ssh -L──► ui.wcss.pl ──► localhost:<port> ◄──reverse ssh── GPU node (vLLM)
```

The job (`deploy/wcss/serve.sbatch`) opens a reverse tunnel to the login node and writes
one `<host> <port> <jobid> <served name>` line per model to `/lustre/pd03/$WCSS_ACCOUNT/serve/endpoint`.
This sidecar reads the file over SSH and holds one `ssh -N` connection with one
`-L 0.0.0.0:(8001+i):<host_i>:<port_i>` per line (at most 8 lines).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `WCSS_USER` | (required) | cluster login, e.g. `dawlin1140` |
| `WCSS_ACCOUNT` | (required) | the PD that holds `serve/endpoint`, i.e. the account the serve job was submitted with |
| `WCSS_HOST` | `ui.wcss.pl` | login node |
| `LISTEN_PORT` | `8001` | port for endpoint line 0; line i listens on `LISTEN_PORT+i` (all interfaces of the container) |
| `MODEL_CHECK` | `qwen3.8-27b` | expected served name of the first line; a mismatch is logged as a warning (empty = no check) |
| `ENDPOINT_CMD` | `cat` | `cat`: run `cat <PD>/serve/endpoint`. `endpoint`: run the verb `endpoint` (for a key with a forced command, see below) |
| `POLL_SECONDS` | `300` | how often the endpoint file is re-read while a forward is up |
| `CHECK_PORT` | `18001` | loopback port used to check a new endpoint before switching to it |
| `BACKOFF_MIN` / `BACKOFF_MAX` | `60` / `900` | retry backoff in seconds |

Secrets (mounted read-only; the script copies the key to a private tmpfs file with mode 600 because the
mount cannot be chmod-ed):

- `/run/secrets/wcss_key`: the private key. It must be **readable by uid 10001** (the container user).
- `/run/secrets/known_hosts`: the pinned host key of `ui.wcss.pl`. `StrictHostKeyChecking=yes`; the
  sidecar never accepts or updates host keys.

`/health` on port 8001 is vLLM's own `/health` passed through the forward (vLLM does not require the
API key for it), i.e. the first endpoint line. The container is therefore healthy only while a job is up
and serving. **Do not make the
gateway `depends_on: condition: service_healthy` on this service**: the gateway must start (and degrade
per `policy/routing.yaml`) while no job is running.

## Behaviour

1. Every SSH call uses key auth only: `BatchMode=yes`, `NumberOfPasswordPrompts=0`, password and
   keyboard-interactive disabled, `IdentitiesOnly=yes`, `ConnectTimeout=20`, `ServerAliveInterval=30`,
   `ServerAliveCountMax=3`, `StrictHostKeyChecking=yes` with the pinned `known_hosts`. No password prompt
   can ever happen.
2. Read the endpoint with one short SSH call. The file content is treated as data: host must match
   `[a-z0-9-]+`, port must be digits in 1..65535, served name `[A-Za-z0-9._-]+`. A malformed line keeps
   its slot (port numbers of later lines do not shift) but is not forwarded.
3. Hold one `ssh -N -o ExitOnForwardFailure=yes -L 0.0.0.0:8001:<host_0>:<port_0> -L 0.0.0.0:8002:...`
   in the background. A process check runs every 15 s (local only); the endpoint is re-read every 5 min.
4. When the endpoint changes (a new job), open a second forward for the first line on `127.0.0.1:18001`,
   require `GET /health` = 200 through it, close it, then kill the old forward and start the new one with
   all lines. Only the first line's health is checked before the swap (the job starts the other servers
   after the first is healthy, so they may still be loading for a few minutes).
   **There is a gap of a few seconds (one SSH handshake) during the swap, and requests in flight on the old
   forward, including streams, are cut.** Acceptable for the demo. If the new endpoint is not healthy yet
   (vLLM takes about 4 min to start), the old forward stays and the check repeats at the next poll.
5. Network errors and forward exits: exponential backoff 60 s, 120 s, ... up to 15 min, reset once a
   forward has stayed up for a full poll period. A transient failure to re-read the endpoint never tears
   down a working forward.
6. No job (endpoint missing or empty, or its first line malformed): logs `no serve job running` and keeps
   checking with the same backoff. That is not an auth failure.
7. `Permission denied`, `Too many authentication failures`, `Host key verification failed`, or an
   unusable key: logs a clear message and **exits 78 and stays down** (compose `restart: "no"`). Never
   retried, because three failed logins lock the WCSS account for 24 h and a changed host key needs a
   human. Missing `WCSS_USER` / `WCSS_ACCOUNT` / secret files also exit 78.
8. Logs are plain lines on stdout. They never contain key material or the LLM API key (the sidecar never
   sees the API key: the gateway sends it through the forward).

This sidecar does **not** submit jobs. Keeping a serve job running (and on which billing account) is a
human decision; see `docs/prompts/wcss-hosting.md` for the planned `ensure` verb.

## Setup

### 1. Key pair (on the Coolify server, solvro-stacja-web)

```sh
mkdir -p ~/rogatka-wcss && cd ~/rogatka-wcss
ssh-keygen -t ed25519 -f id_ed25519 -N '' -C rogatka-coolify
sudo chown 10001:10001 id_ed25519 && sudo chmod 600 id_ed25519   # readable by the container user only
cat id_ed25519.pub                                                 # goes to WCSS, step 2
```

The private key never leaves this server and never goes into the repository.

### 2. authorized_keys on WCSS (user dawlin1140)

Find the server's public egress IP (as seen from the internet, e.g. from the office router or
`curl -s https://ifconfig.me` on the server) and append one line to `~/.ssh/authorized_keys` on
`ui.wcss.pl`:

```
restrict,port-forwarding,permitopen="localhost:*",from="<server egress IP>" ssh-ed25519 AAAA... rogatka-coolify
```

What these options do:

- `restrict` turns off port forwarding, agent forwarding, X11 forwarding, PTY allocation and
  `~/.ssh/rc`. It does **not** stop command execution: `ssh host 'cat <file>'` still runs (with no PTY),
  which is what the default `ENDPOINT_CMD=cat` mode needs. It also means this key can run *any*
  non-interactive command as dawlin1140, so treat it as a real login credential.
- `port-forwarding` turns local (`-L`) forwarding back on, and `permitopen="localhost:*"` limits it to
  `localhost` on any port. sshd compares the destination string the client asks for, and the endpoint
  file says `localhost` when the job uses the reverse tunnel, so this matches. (A job without
  `~/.ssh/acl_tunnel` publishes the node name instead; that is refused here, and the login node cannot
  reach compute nodes anyway.)
- `from=` accepts the key only from the server's IP. If that IP changes, logins fail with
  `Permission denied` and the sidecar exits 78 until the line is updated.

Hardening, once `~/acl/acl-ctl.sh` exists on the cluster: add a forced command and switch the sidecar
to `ENDPOINT_CMD=endpoint`:

```
restrict,port-forwarding,permitopen="localhost:*",from="<server egress IP>",command="/home/dawlin1140/acl/acl-ctl.sh" ssh-ed25519 AAAA... rogatka-coolify
```

With `command=`, every session runs only `acl-ctl.sh` (the requested command arrives in
`SSH_ORIGINAL_COMMAND`, so `cat ...` would be rejected by it), while `ssh -N -L ...` still forwards
because `-N` opens no session.

To revoke the key, delete its line from `authorized_keys`.

### 3. Pinned known_hosts

```sh
ssh-keyscan -t ed25519 ui.wcss.pl > known_hosts
ssh-keygen -lf known_hosts            # prints SHA256:... ui.wcss.pl (ED25519)
```

Compare the printed fingerprint with one obtained **out of band**: from a machine that already trusts
the host (`ssh-keygen -lF ui.wcss.pl` on a laptop that has logged in before) or from WCSS
documentation/support. Do not trust a scan alone; that is what pinning is meant to protect against. If
WCSS rotates its host key, the sidecar exits 78 with a host key message; re-verify and replace the file.

### 4. Where the files go in Coolify

The compose service mounts two secret files at `/run/secrets/wcss_key` and `/run/secrets/known_hosts`
(see `deploy/compose.coolify.yml` for the exact source paths). Either:

- keep them on the server outside the repository checkout (e.g. `~/rogatka-wcss/`) and point the compose
  secret / bind-mount sources there, or
- put them in `deploy/wcss-link/secrets/` of the server's checkout: that directory's `.gitignore` ignores
  everything, so they are never committed, but a fresh Coolify clone will not contain them.

Coolify's "Storages → file mount" also works, but it stores the content in Coolify's database as well; a
host file with mode 600 owned by uid 10001 keeps the key in one place. In every case the key file must be
readable by uid 10001 inside the container. Set `WCSS_USER`, `WCSS_ACCOUNT` (and `LOCAL_LLM_API_KEY` for
the gateway) as Coolify environment variables.

## Checks

```sh
docker compose logs -f wcss-link          # forward up / upstream healthy / no serve job running
docker compose exec wcss-link curl -fsS http://127.0.0.1:8001/health && echo ok
```

Exit status 78 means a human has to act (authentication, host key, or configuration). Read the last log
line, fix the cause, then start the container again.
