# Deploying the clients to a real fleet (documentation only)

The demo container is the same configuration that a company would push to laptops. Nothing here has been deployed to
a real fleet.

## OpenCode (developers)

| Piece | Windows | macOS | Linux (demo) |
|---|---|---|---|
| Managed config (`deploy/opencode/opencode.json`, baseURL → `https://ai-gateway.corp/v1`) | `%ProgramData%\opencode\opencode.json`, ACL: Administrators full, Users read; pushed by Intune/GPO | MDM configuration profile (managed preferences); OpenCode reads managed settings with highest precedence | `/etc/opencode/opencode.json`, root-owned 0444 |
| Guard plugin `@corp/opencode-guard` | `%ProgramData%\opencode\plugins\opencode-guard` (read-only), referenced as `file:///C:/ProgramData/opencode/plugins/opencode-guard` | `/Library/Application Support/opencode/plugins/opencode-guard` | `/opt/opencode-guard` |
| Pinned CLI + wrapper (drops `OPENCODE_*` overrides, disables project config) | Intune Win32 app; wrapper `opencode.cmd` first on `PATH` | pkg via MDM; wrapper in `/usr/local/bin` | `deploy/opencode/opencode-wrapper.sh` |
| Plugin settings | system env `ACL_GATEWAY_URL`, `ACL_OIDC_ISSUER`, `ACL_PANEL_URL` | `launchctl setenv` from the profile | compose `environment:` |
| Egress rule | Windows Firewall / Defender for Endpoint + corporate proxy: deny LLM provider domains (`api.openai.com`, `generativelanguage.googleapis.com`, `api.anthropic.com`, ...) for all apps; allow `ai-gateway.corp` | same via the proxy / DNS filter (e.g. Zscaler, Umbrella) | `acl-clients-internal` network, `internal: true` |

Login is the Keycloak device-code flow (client `opencode`, public, device grant only). In production Keycloak
federates AD/Entra ID; the plugin needs only the issuer URL. There are no secrets on the device: the only credential is
the user's own refresh token in the OpenCode auth store.

## LibreChat (everyone else)

Server-side app behind company SSO: OIDC client `librechat` (confidential, secret from the vault), `OPENID_REUSE_TOKENS=true`,
custom endpoint `baseURL` = the gateway with `Authorization: Bearer {{LIBRECHAT_OPENID_ACCESS_TOKEN}}`, so every request
carries the person's own token, and `/v1/models` (personalised, including published skills) drives the model menu.
Production uses an HTTPS issuer, so the demo's `http://` issuer patch and the `oidc-forward` shim are not built
(`OPENID_ALLOW_INSECURE_HTTP` unset). Email login and registration stay off.

## What each lockdown layer (concept §10) proves

| Layer | Proof on a fleet | Proof in the demo |
|---|---|---|
| 1 Users never hold provider keys | key lives only in the gateway's secret store; endpoint scan finds none | container env/state has only the Keycloak token (`test_cp2_clients.py`) |
| 2 Gateway is the model authority | forbidden model → 403 + incident; confidential → local whatever is requested | `test_clients_live.py` demo 1 (PESEL → local), CP1 403 test |
| 3 Managed config + plugin | user/project config cannot change provider, MCP list, sharing; every tool goes through `/v1/decide` | demo 2/3 (rule ids in the TUI), hostile config test in CP2 |
| 4 Egress control | `curl api.openai.com` fails from every managed device, including the browser | `docker exec acl-opencode-1 curl https://api.openai.com` fails |

Residual risk: a local admin can bypass layer 3 (run the CLI without the wrapper); layers 1, 2 and 4 still hold and
every model call stays attributed.
