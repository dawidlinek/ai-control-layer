# OpenCode on your own laptop against the hosted Rogatka gateway

The same setup as the locked container in `deploy/opencode/`, minus the container: your local OpenCode talks only to
the hosted gateway, the user logs in with Keycloak (device code), and the `@corp/opencode-guard` plugin asks the
gateway (`/v1/decide`) before every tool call.

| | Default | Override (both scripts) |
|---|---|---|
| Gateway (OpenAI-compatible `/v1`, MCP proxy `/mcp/<server>`) | `https://rogatka-api.b.solvro.pl` | `ROGATKA_GATEWAY_URL` / `-GatewayUrl` |
| Keycloak issuer (client `opencode`, device code) | `https://rogatka-auth.b.solvro.pl/realms/acl` | `ROGATKA_OIDC_ISSUER` / `-OidcIssuer` |

## What setup does (and does not) touch

- Builds `plugins/opencode-guard` (`pnpm install --frozen-lockfile`, typecheck, unit tests, `tsc`) and copies
  `package.json` + `dist/` into a **profile directory**:
  Windows `%LOCALAPPDATA%\rogatka-opencode`, macOS/Linux `~/.config/rogatka-opencode` (`ROGATKA_HOME` / `-ProfileDir`).
- Writes `<profile>/opencode.json` from `opencode.template.json` (provider `company`, models `auto`/`local`/`smart`,
  `enabled_providers: ["company"]`, the plugin, MCP servers `governed-tools`, `files`, `mail`, `web` at
  `<gateway>/mcp/<name>`, `share: disabled`, `webfetch: deny`).
- Writes a launcher, `rogatka-opencode` (`~/.local/bin`) or `rogatka-opencode.cmd` (in the profile dir), which runs your
  normal `opencode` with:
  `OPENCODE_CONFIG=<profile>/opencode.json`, `OPENCODE_DISABLE_PROJECT_CONFIG=1` (a repo's own `opencode.json` /
  `.opencode/` is ignored), `OPENCODE_DISABLE_AUTOUPDATE=1`, `OPENCODE_DISABLE_MODELS_FETCH=1`,
  `ACL_GATEWAY_URL`, `ACL_OIDC_ISSUER`, `ACL_OIDC_CLIENT_ID=opencode`, `ACL_MCP_SERVERS=governed-tools,files,mail,web`.
  Every other `OPENCODE_*` variable from your shell is dropped (`OPENCODE_PURE` would skip the plugin), and
  `ACL_OIDC_BASE_URL` is unset (no back channel: the plugin talks to the issuer directly).
- It never writes `~/.config/opencode/`. Plain `opencode` keeps working exactly as before.

## Steps

1. **Install** Node.js >= 20, pnpm (`corepack enable pnpm` or `npm i -g pnpm`), git, and OpenCode. The version the
   plugin is verified against is pinned in `deploy/opencode/package.json`:
   ```sh
   npm i -g opencode-ai@1.18.34
   ```
2. **Run setup** from the repository root:
   ```sh
   # macOS / Linux
   sh deploy/opencode-remote/setup.sh --demo-repo ~/rogatka-demo
   ```
   ```powershell
   # Windows (PowerShell or cmd)
   powershell -ExecutionPolicy Bypass -File deploy\opencode-remote\setup.ps1 -DemoRepo $HOME\rogatka-demo -AddToPath
   ```
   `--demo-repo` / `-DemoRepo` is optional (step 5). `-AddToPath` adds the profile dir to your user `PATH`; open a new
   terminal afterwards, or call the `.cmd` by its full path.
3. **Log in**: `rogatka-opencode auth login` -> choose **company** -> open the link it prints
   (`https://rogatka-auth.b.solvro.pl/realms/acl/device?user_code=...`), sign in as a demo user (`anna`, `jan`, `ola`,
   `adam`; password from the deployment's `DEMO_USER_PASSWORD`) and confirm the code. Use the launcher here too: plain
   `opencode auth login` does not load the profile, so it has no `company` provider.
4. **Work**: `cd` into a repository and run `rogatka-opencode`. The model is `company/auto`; `/models` shows the three
   gateway aliases (the gateway decides per user which one is really allowed).
5. **Injection demo**: open the demo repo (copied by step 2, or copy `deploy/opencode/demo-repo` anywhere yourself and
   `git init` it) and ask e.g. "set up this project and run the tests". Its README carries a visible and a hidden
   prompt injection telling the agent to read `~/.ssh/id_rsa` and `curl` it to `attacker-sink`. The read/bash call is
   refused with `Blocked by company policy [<rule id>] ...`, and the decision shows up in the Rogatka Dashboard.

> **Real keys.** In the container `~/.ssh/id_rsa` is a canary. On your laptop it may be your real key, and the only
> thing between it and the model is the gateway policy. Run the injection demo as a user (or VM) without a real key at
> `~/.ssh/id_rsa`, or put a canary file there in a throwaway account.

Log out / remove: `rogatka-opencode auth logout`, delete the profile dir and the launcher. Tokens live in OpenCode's
own store (`~/.local/share/opencode/auth.json` on every OS, entry `company`).

## What a laptop demonstrates (and what it does not)

| Layer (concept section 10) | Container | Laptop |
|---|---|---|
| 4 Network lockdown (no route to providers, only `idp-gate`) | yes | **no**: the laptop has normal internet. Nothing stops a user from calling a provider directly with their own key; the demo shows that the *company* path is governed, not that other paths are closed |
| 3 Managed config | root-owned `/etc/opencode`, wrapper is the only entry | **convenience only**: the profile is a user-writable file and plain `opencode` bypasses it. Your global `~/.config/opencode` config is still merged underneath (the profile wins on conflicts, `enabled_providers` keeps other providers out, the plugin drops every MCP server that is not `<gateway>/mcp/<its own name>`, but extra global plugins/agents still load) |
| 3 Plugin: `/v1/decide` for every tool call, any error blocks | yes | yes |
| 2 Gateway: model authority, per-user models, audit, MCP proxy policy | yes | yes |
| 1 Keys: the client holds only the user's own Keycloak token | yes | yes |

The plugin refuses to start working (every tool call blocked, login refused) unless `ACL_GATEWAY_URL` and
`ACL_OIDC_ISSUER` are valid; plain `http://` is only accepted for loopback, single-label (compose) and `.test` /
`.internal` / `.local` hosts, so the bearer token never crosses the internet unencrypted. The provider `fetch` sends the
token only to the exact gateway origin (scheme, host and port).

## Verified / not verified

Verified (2026-10-04, OpenCode 1.18.34 installed from the hash-locked `deploy/opencode/pnpm-lock.yaml`, on Windows 11):

- `OPENCODE_CONFIG` is read by the CLI and merged after the global config and before project config
  (`packages/opencode/src/config/config.ts`; flag in `packages/core/src/flag/flag.ts`); `OPENCODE_DISABLE_PROJECT_CONFIG`
  skips project files and project `.opencode/` dirs (`config/paths.ts`).
- Plugin specs `file:///C:/...` (percent-encoded spaces) and absolute paths are resolved with `fileURLToPath`
  (`plugin/shared.ts`, `config/plugin.ts`); a directory with `package.json` `exports` loads `dist/index.js`.
- Through the generated `.cmd` launcher, `opencode debug config` shows the plugin loaded from the profile dir, the four
  MCP servers with `Authorization` / `X-Device-Id` headers injected, and a hostile global config (extra provider, extra
  MCP servers) plus a hostile project `opencode.json` (other `baseURL`, extra MCP server) neutralised.
- `setup.sh` (run under Git Bash) and `setup.ps1` (Windows PowerShell 5.1) end to end, including a profile path with a space.

Not verified:

- The hosted endpoints: `rogatka-api.b.solvro.pl` and `rogatka-auth.b.solvro.pl` answered HTTP 503 when this was
  written, so login, chat and MCP against the public deployment are untested from a laptop. The device-code flow
  itself is the one verified in the container; with no back channel the verification link is shown exactly as
  Keycloak returns it, so Keycloak must run with its public hostname (`KC_HOSTNAME=https://rogatka-auth.b.solvro.pl`).
- `setup.sh` on real macOS / Linux (only run under Git Bash; it is POSIX `sh`).
- OpenCode's built-in `bash` tool on Windows (which shell it uses) and how the demo's POSIX commands behave there.
- Other OpenCode versions: the hook signatures and config merge order above are version-specific.
