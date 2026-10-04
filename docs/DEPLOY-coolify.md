# Deploying Rogatka on Coolify

Public demo at `*.b.solvro.pl` on https://devops.solvro.pl (Coolify v4; its proxy terminates TLS).
Compose file: `deploy/compose.coolify.yml` (flat, no published ports, no bind mounts of repo files).

| Host | Service | Container port |
|---|---|---|
| https://rogatka.b.solvro.pl | `panel` (Rogatka Dashboard) | 3000 |
| https://rogatka-chat.b.solvro.pl | `librechat` | 3080 |
| https://rogatka-auth.b.solvro.pl | `keycloak` | 8080 |
| https://rogatka-api.b.solvro.pl | `gateway` (`/v1`, `/mcp` for remote OpenCode) | 8000 |

Everything else (postgres, librechat-mongo, feed-server, attacker-sink, mcp-*, wcss-link, bootstrap) is internal.

## 1. Create the resource

1. Project → New Resource → Public/Private Repository (GitHub App) → `dawidlinek/ai-control-layer`, branch `main`.
2. Build Pack: **Docker Compose**. Base Directory: **`/deploy`**. Docker Compose Location: **`/compose.coolify.yml`**.
   (The base directory must be `/deploy`: Coolify resolves relative paths against it, and the file uses `..`
   for the repo root, like the other compose files.)
3. Leave "Connect to Predefined Network" **off**.
4. Domains (per service, in the resource's General tab). The `:port` is the container port, not a public port:
   - panel `https://rogatka.b.solvro.pl:3000`
   - librechat `https://rogatka-chat.b.solvro.pl:3080`
   - keycloak `https://rogatka-auth.b.solvro.pl:8080`
   - gateway `https://rogatka-api.b.solvro.pl:8000`
   - all other services: no domain.

## 2. Environment variables

Generate secrets locally with `make env` (or `uv run python scripts/dev.py env`) and paste the values into the
resource's Environment Variables (Developer view accepts `.env` text). Use fresh values, not your dev ones.

Required (the deploy fails without them): `POSTGRES_PASSWORD`, `KC_ADMIN_PASSWORD`, `DEMO_USER_PASSWORD`,
`KC_PANEL_SECRET`, `PANEL_AUTH_SECRET`, `KC_LIBRECHAT_SECRET`, `KC_AGENT_RESEARCH_BOT_SECRET`,
`LIBRECHAT_APP_SECRET`, `ACL_VALUE_HASH_SALT`, `ACL_API_KEY_PEPPER`, `FEED_ADMIN_TOKEN`.

Models: `GEMINI_API_KEY` (cloud), `LOCAL_LLM_API_KEY` (vLLM key on WCSS). Defaults already point the local lines at
the sidecar: `LOCAL_LLM_BASE_URL=http://wcss-link:8001/v1` (`qwen3.8-27b`, also the judge),
`LOCAL_PL_BASE_URL=http://wcss-link:8002/v1` (`bielik-11b`). `LOCAL_EMBED_MODEL` stays empty: embeddings go through
the `local` connector (port 8001); serving `qwen3-embedding-0.6b` from wcss-link:8003 needs its own connector in
`policy/models.yaml` first.

Optional: `WCSS_USER` (default `dawlin1140`), `WCSS_ACCOUNT`, `ACL_DETERMINISTIC` (default 0; 1 = mock models),
`PUBLIC_PANEL_URL` / `PUBLIC_CHAT_URL` / `PUBLIC_AUTH_URL` (default to the hosts above; change together with the
Coolify domain). `PUBLIC_API_URL` is not read by any container; it is the gateway URL to give OpenCode users.

## 3. WCSS key and known_hosts

`wcss-link` bind-mounts two files: `./wcss-link/secrets/id_ed25519` → `/run/secrets/wcss_key` and
`./wcss-link/secrets/known_hosts` → `/run/secrets/known_hosts`. Coolify creates these paths under
`/data/coolify/applications/<uuid>/` and may create them as empty directories on the first deploy. Fix: resource →
Storages → the two `wcss-link` mounts → "Convert to file" (if shown) → paste the private key / the known_hosts
line(s) → Save → Redeploy. Alternative with shell access to the server: put the files somewhere root-only and set
`WCSS_KEY_FILE` / `WCSS_KNOWN_HOSTS_FILE` to their absolute paths.

`wcss-link` has `restart: "no"`: it does its own backoff and exits with code 78 on SSH auth failure. A stopped
`wcss-link` in Coolify is the alert: fix the key, then redeploy. The cloud models keep working meanwhile.

## 4. First boot

- `bootstrap` runs once per deploy and exits 0 (Coolify may show it as exited / the resource as degraded; expected).
  It seeds the `policy` volume from the repo **only when empty**, refreshes the insights seed and creates the
  `keycloak` database. Panel policy edits therefore survive redeploys; repo changes to `policy/` do NOT reach a
  running deployment. To reset policy to the repo version: stop, delete the `policy` volume, redeploy.
- Keycloak imports `realm-export.json` **only when the realm does not exist** (empty `keycloak` DB). Later changes
  to the realm file, secrets or `PUBLIC_*_URL` need either a manual change in the admin console
  (https://rogatka-auth.b.solvro.pl/admin, user `admin` / `KC_ADMIN_PASSWORD`) or dropping the `keycloak`
  database and redeploying. Same for `DEMO_USER_PASSWORD` and the client secrets.
- Keycloak's first start takes ~1–2 min (build step + import); panel and LibreChat wait for its healthcheck.
- LibreChat and the panel reach Keycloak's public HTTPS URL from inside their containers (OIDC discovery, `iss`).
  That needs hairpin access from the server to `rogatka-auth.b.solvro.pl`; if login fails with a discovery error,
  check `docker exec <librechat> wget -qO- https://rogatka-auth.b.solvro.pl/realms/acl/.well-known/openid-configuration`.

## 5. Verification checklist

1. `https://rogatka-auth.b.solvro.pl/realms/acl/.well-known/openid-configuration` → `issuer` is the https URL.
2. Panel: https://rogatka.b.solvro.pl → sign in as `adam` (admin) → dashboard loads, Traffic shows events.
3. LibreChat: https://rogatka-chat.b.solvro.pl → "Sign in with company SSO" → `anna` (developers) and then `jan`
   (credit-analysts): the model lists differ according to policy.
4. API with a token (demo client with password grant):
   ```sh
   TOKEN=$(curl -s https://rogatka-auth.b.solvro.pl/realms/acl/protocol/openid-connect/token \
     -d grant_type=password -d client_id=acl-e2e -d username=anna -d "password=$DEMO_USER_PASSWORD" | jq -r .access_token)
   curl -s https://rogatka-api.b.solvro.pl/v1/models -H "Authorization: Bearer $TOKEN" | jq '.data[].id'
   curl -s https://rogatka-api.b.solvro.pl/v1/chat/completions -H "Authorization: Bearer $TOKEN" \
     -H 'Content-Type: application/json' \
     -d '{"model":"local","messages":[{"role":"user","content":"17*23? Answer with the number only."}]}' | jq -r '.choices[0].message.content'
   # expect 391 (proves gateway -> wcss-link -> WCSS vLLM)
   ```
5. Remote OpenCode: gateway `https://rogatka-api.b.solvro.pl`, issuer `https://rogatka-auth.b.solvro.pl/realms/acl`,
   client `opencode` (public, device flow); device page `https://rogatka-auth.b.solvro.pl/realms/acl/device`.

## 6. Pause / rollback

- Pause: resource → Stop (volumes are kept). Start brings it back with the same data.
- Rollback: Deployments tab → pick an earlier successful deployment → Redeploy (images are rebuilt from that
  commit; volumes, including policy and the Keycloak DB, are not rolled back).
- Model outage only: set `ACL_DETERMINISTIC=1` and redeploy the gateway to demo with mock models.
- Full reset: stop, delete the volumes (`pgdata`, `policy`, `audit`, `librechat_mongo`, ...), redeploy.

Security notes for a public demo: the `acl-e2e` client allows the password grant for every demo user, and the
Keycloak admin console is public; both are protected only by generated passwords. Disable `acl-e2e` in the admin
console after verification if the demo does not need it.
