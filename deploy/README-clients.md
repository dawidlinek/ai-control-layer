# Clients: locked OpenCode + LibreChat (Phase 2C)

Two ways in, one gateway. Both clients authenticate the **person** (Keycloak) and send that person's own access
token (audience `gateway`) to the gateway; neither holds a provider key.

| Client | Where | What it proves |
|---|---|---|
| OpenCode + `@corp/opencode-guard` in a locked container | `deploy/opencode/`, `plugins/opencode-guard/` | concept section 10 layers 3 and 4, scenarios 2 and 3 |
| LibreChat (OIDC login, "Company AI" endpoint = gateway) | `deploy/librechat/` | scenario 1: same prompt, different user, different models |

## Start

```bash
# 1. secrets (adds LIBRECHAT_APP_SECRET; never overwrites existing values)
uv run python scripts/dev.py env
# 2. the stack plus the `clients` profile
COMPOSE_PROFILES=clients uv run python scripts/dev.py up
#    or: docker compose --env-file .env -f deploy/docker-compose.yml --profile clients up -d --build
```

The gateway service must also be attached to the `acl-clients-internal` network with alias `gateway` (snippet at the
top of `deploy/compose.clients.yml`; the main compose file is orchestrator-owned). Until then the OpenCode
container cannot reach the gateway, and `tests/e2e/test_cp2_clients.py::test_container_has_no_route_to_llm_providers_but_reaches_gateway`
says so. For a running stack without editing compose: `docker network connect --alias gateway acl-clients-internal acl-gateway-1`.

Use it:

```bash
# OpenCode TUI in the locked container (first run: log in with the device code)
docker compose --env-file .env -f deploy/docker-compose.yml --profile clients exec opencode opencode auth login   # choose "company"
docker compose --env-file .env -f deploy/docker-compose.yml --profile clients exec opencode opencode              # cwd = demo repo
# LibreChat: http://localhost:3080  ->  "Sign in with company SSO"
```

Demo users (password: `DEMO_USER_PASSWORD` in `.env`): `anna` (credit-analysts), `jan` (developers), `ola`
(security-analysts), `adam` (admins). The device-code page is shown at `http://localhost:8180/realms/acl/device`.

Tests: `pnpm -C plugins/opencode-guard test` (unit) and `uv run python scripts/dev.py e2e -k cp2` (needs the profile
running; skips cleanly otherwise).

## OpenCode: what each lockdown layer proves

| Layer | Mechanism | How to see it |
|---|---|---|
| 4 Network | container sits only on `acl-clients-internal` (`internal: true`): no route out, no DNS for the internet | `docker exec acl-opencode-1 curl https://api.openai.com` fails (could not resolve); same for `generativelanguage.googleapis.com`, `1.1.1.1`, and `attacker-sink` (the README's exfil target) |
| 4b Identity door | `idp-gate` (nginx) answers as `keycloak` on that network and forwards **only** `POST .../auth/device` and `POST .../token` | other Keycloak paths return 403 |
| 3 Managed config | `/etc/opencode/opencode.json`, root-owned, read-only; highest precedence of all config files | editing is impossible; user/project config cannot change `enabled_providers`, `baseURL`, `share`, `permission.webfetch` (checked against the real CLI) |
| 3 Project config off | the `opencode` wrapper sets `OPENCODE_DISABLE_PROJECT_CONFIG=1` and drops every caller-set `OPENCODE_*` variable (`OPENCODE_PURE` would skip the plugin) | a repo's own `opencode.json` / `.opencode/` is ignored |
| 3 MCP list | plugin `config` hook removes every MCP server that is not `http://gateway:8000/mcp/<name>` and attaches the user's token to the rest | extra servers from user config disappear |
| 3 Plugin | `tool.execute.before` asks `/v1/decide` for every tool (built-ins as `opencode.<name>`, MCP as `<server>.<tool>`); **any** error blocks | try the poisoned README: the read of `~/.ssh/id_rsa` fails with `Blocked by company policy [<rule id>] ...` |
| 2 Gateway | model authority, per-user `/v1/models` (gateway-owned; see concept section 10) | forbidden model returns 403 |
| 1 Keys | the container holds no provider keys; its only credential is the user's Keycloak token | `auth.json` in the state volume |

Container: non-root uid 10001, read-only root FS (`/tmp` tmpfs, `/state` and `/workspace` volumes), `cap_drop: ALL`,
`no-new-privileges`, `pids_limit`. The entrypoint refuses to start if the managed config or plugin are writable.
`/workspace/demo-repo` is a git repo with a **poisoned README** (visible and HTML-comment injection telling the agent
to read `~/.ssh/id_rsa` and `curl` it to `http://attacker-sink:8080/collect`). `/home/dev/.ssh/id_rsa` is a canary
(`ACL-CANARY-SSHKEY-...`), not a key.

### The plugin

`plugins/opencode-guard` (TypeScript, no runtime dependencies, hash-locked `pnpm-lock.yaml`, vitest). Configuration is
environment only (`ACL_GATEWAY_URL`, `ACL_OIDC_ISSUER`, optional `ACL_OIDC_BASE_URL` for the back channel,
`ACL_OIDC_CLIENT_ID` default `opencode`, `ACL_DEVICE_ID`, `ACL_MCP_SERVERS`); no secrets anywhere. The image build runs
typecheck and the unit tests.

- `auth` (provider `company`): device-code login (RFC 8628) against Keycloak client `opencode`; shows the verification URL
  and user code only; refresh-token renewal in the loader's `fetch`, which also refuses to send the token to any host
  other than the gateway.
- `chat.headers`: `Authorization: Bearer`, `X-Device-Id`, `X-Client-App: opencode`, `X-Session-Id: <OpenCode session id>`,
  only for provider `company`.
- `tool.execute.before`: `allow`/`monitor` proceed; `redact` rewrites the tool's own args object in place
  (OpenCode keeps using the original reference, so replacing `output.args` would not work); `block` and every other
  action throw with rule ids, reason and decision id; `require_approval` polls `GET /v1/approvals/{id}` (bounded by
  `approvalTimeoutMs` and the approval's `expires_at`) and shows a TUI toast. Network error, timeout, non-200 or a
  malformed body throws.
- `permission.ask`: denies a permission prompt for a call the gateway already refused (defence in depth).

User-scope approvals (`approver_scope: user`) are **not** self-approved by the plugin: OpenCode's plugin API has no way to
show a prompt from `tool.execute.before`, and a CLI the agent could also run would let a prompt-injected agent approve
itself. The plugin polls; the human decides in the admin panel (or any UI that calls
`POST /v1/approvals/{id}/decision`). `GatewayClient.decideApproval` exists for such a UI.

## LibreChat

`librechat.yaml`: one custom endpoint "Company AI", `baseURL: http://gateway:8000/v1`, `models.fetch: true`, header
`Authorization: Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}`. Login: Keycloak client `librechat` (secret
`KC_LIBRECHAT_SECRET`), `OPENID_REUSE_TOKENS=true`, email login and registration off. Only MongoDB is added (search is
disabled, so no Meilisearch).

Per-user identity forwarding works without any gateway-side change: LibreChat sends the signed-in user's own Keycloak
access token (audience `gateway`, from the client's audience mapper). The e2e test proves it: `/api/models` in
LibreChat equals the gateway's `/v1/models` **for that user** (anna and jan differ) and a LibreChat chat shows up in the
audit log as the user with `session_id = <principal>:<conversation id>`. If the token is expired or missing LibreChat
raises `OpenIDReauthRequiredError` rather than sending the request unauthenticated.

Demo-only adjustments, because Keycloak here is plain HTTP on localhost (`deploy/librechat/Dockerfile`):

1. LibreChat v0.8.8 uses `openid-client` v6, which refuses `http://` issuers and has no switch for it
   (`only requests to HTTPS are allowed`). A build-time patch adds `execute: [allowInsecureRequests]` when
   `OPENID_ALLOW_INSECURE_HTTP=true`; the build fails if the patch point disappears. **Production: HTTPS issuer, no patch.**
2. Tokens carry issuer `http://localhost:8180/realms/acl` (`KC_HOSTNAME`), and v6 requires the discovery URL to equal the
   issuer. `oidc-forward.cjs` forwards `localhost:8180` inside the LibreChat container to `keycloak:8080`.
3. `offline_access` is not requested: the realm import gives users no default roles, so Keycloak rejects offline tokens
   (`Offline tokens not allowed for the user or client`).

LibreChat stays on the default network (it is a server-side app that must reach Keycloak and Mongo), so it is not part of
the egress lockdown; its only configured model endpoint is the gateway.

## Verified against current docs and source (2026-10-03)

OpenCode (`opencode-ai` 1.18.34, `@opencode-ai/plugin` 1.18.34):

- Hook signatures: <https://raw.githubusercontent.com/sst/opencode/dev/packages/plugin/src/index.ts>.
  `auth: {provider, loader?(getAuth, provider), methods[{type:"oauth", authorize() -> {url, instructions, method:"auto"|"code", callback()}}]}`;
  `"chat.headers"(input{sessionID, agent, model, provider, message}, output{headers})`;
  `"tool.execute.before"(input{tool, sessionID, callID}, output{args})`;
  `"permission.ask"(input: Permission, output{status})`. A path plugin must `export default {id, server}`.
- Plugin docs: <https://opencode.ai/docs/plugins/> (blocking a tool by throwing in `tool.execute.before`; npm and local plugins).
- Config docs: <https://opencode.ai/docs/config/> (precedence, managed locations `/etc/opencode`, `%ProgramData%\opencode`,
  macOS MDM; `enabled_providers`, `share`, `autoupdate`, `permission`). Source confirms managed files are merged last
  (`packages/opencode/src/config/config.ts`) and that only `instructions` arrays are concatenated, so a user config cannot
  extend `enabled_providers`. Plugins are additive (`plugin_origins`).
- Plugin loading from a path inside an image: `packages/opencode/src/plugin/shared.ts` (`file://` specs, `package.json`
  `main`) and `plugin/index.ts` (default-export `{id, server}`).
- Provider docs: <https://opencode.ai/docs/providers/> (`@ai-sdk/openai-compatible`, `options.baseURL`); that package is
  bundled in the CLI (`provider/provider.ts`, `BUNDLED_PROVIDERS`), so nothing is installed at run time.
- MCP: <https://opencode.ai/docs/mcp-servers/> (remote `url`, `headers`, `oauth`); tool names are
  `sanitize(server) + "_" + sanitize(tool)` (`mcp/catalog.ts`), which the plugin reverses using the governed server list.
- Behaviour that shaped the design (read from `session/tools.ts`, `effect/runtime-flags.ts`, `core/flag/flag.ts`):
  `item.execute(args, ctx)` keeps using the original `args` object after the hook; `OPENCODE_PURE` skips external plugins;
  `OPENCODE_DISABLE_PROJECT_CONFIG`, `OPENCODE_DISABLE_MODELS_FETCH` (the model catalogue fetch otherwise stalls start-up
  offline) exist. `permission.ask` is declared in the plugin types, but I found no call site in the files I read, so it is
  treated as defence in depth only.
- The `models` list is static per provider in config (a `provider.models` plugin hook exists in the v2 types but is not
  needed: the gateway is the model authority).
- Verified against the real CLI in the container: device login through `idp-gate`, chat through the
  gateway, tool block / redact (file content really replaced) / approval polling, MCP header injection, managed config
  winning over hostile project and user config.

LibreChat (`v0.8.8`, image `registry.librechat.ai/librechat-ai/librechat:v0.8.8`):

- Custom endpoint `headers` and placeholders: <https://www.librechat.ai/docs/configuration/librechat_yaml/object_structure/custom_endpoint>
  (`{{LIBRECHAT_USER_ID}}`, `{{LIBRECHAT_USER_EMAIL}}`, `{{LIBRECHAT_BODY_*}}`, `${ENV}`, and "`{{LIBRECHAT_OPENID_*}}`
  placeholders without a value become empty strings"; `models.fetch`). The docs page does not enumerate the OpenID names;
  they are in the source: `packages/api/src/utils/env.ts` (`LIBRECHAT_OPENID_ACCESS_TOKEN`, `_ID_TOKEN`, `_TOKEN`, `_USER_ID`,
  `_USER_EMAIL`, ... resolved from `user.federatedTokens`, throws `OpenIDReauthRequiredError` when the token is expired) and
  `librechat.example.yaml` at tag v0.8.8 (`Authorization: "Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}"`). Custom-endpoint model
  fetching forwards user-scoped headers per user (`packages/api/src/endpoints/custom/initialize.ts`).
- Token reuse: <https://www.librechat.ai/docs/configuration/authentication/OAuth2-OIDC/token-reuse> (`OPENID_REUSE_TOKENS=true`);
  the JWT strategy then fills `federatedTokens` (`api/strategies/openIdJwtStrategy.js`).
- Keycloak settings: <https://www.librechat.ai/docs/configuration/authentication/OAuth2-OIDC/keycloak>
  (`OPENID_ISSUER`, `OPENID_CLIENT_ID/SECRET`, `OPENID_CALLBACK_URL=/oauth/openid/callback`, `OPENID_SCOPE`).
- Env reference: <https://www.librechat.ai/docs/configuration/dotenv>. Config file version `1.3.17` from
  `librechat.example.yaml@v0.8.8`.

## Known limits

- The decision half of the plugin is verified against a scripted stand-in for `/v1/decide`; against the real gateway it
  currently fails closed because `/v1/decide` answers 501 (Phase 2B). The e2e test for the rule id skips until then.
- A user with a shell on the device can run the CLI binary directly (`/opt/opencode-cli/...`) without the wrapper, and so
  without the guard; they still cannot reach any provider (layer 4) and every model call is attributed (layer 1-2).
- Tool calls an agent makes through MCP servers the gateway does not know are denied by the gateway's tool allowlist
  (unknown ids), not by the plugin.
- LibreChat tokens are refreshed by LibreChat; when its refresh fails the chat fails closed until the user logs in again
  (not exercised past the 15-minute token lifetime).
- Ports `3080` (LibreChat) and the Keycloak redirect URI `http://localhost:3080/...` are fixed in the realm import.
