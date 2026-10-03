# CP2 — Agents, tools, clients, budgets

*2026-10-03 · orchestrator*

## Acceptance

| Criterion | Status |
|---|---|
| Demo scenarios 2, 3, 4, 6, 7, 12 run end to end, scripted in `tests/e2e/` | **Done** — full e2e suite **22/22** on the live compose stack (17 containers healthy), gateway in deterministic-model mode |
| `make lint && make test` | **Green** — lint clean, contracts in sync |
| Security review of Phase 2 critical modules | see § Security review |

| Scenario | Evidence (e2e) |
|---|---|
| 2 Lockdown | locked OpenCode container cannot reach `api.openai.com` / Gemini, reaches only the gateway; forbidden model → 403 + incident (CP1) |
| 3 Poisoned repository | `~/.ssh/id_rsa` read denied (SIG-PATH-SSH-KEYS-01 + SEC-TOOL-01); send after untrusted README + sensitive data blocked/held by SEC-FLOW-01 (Rule of Two) with every semantic control disabled |
| 4 Supply chain | feed rule added live → next matching request blocked (CP1); `pip install litellm==1.82.8` signature in the seed bundle |
| 6 MCP rug pull | description change → tool quarantined, `mcp_drift` + `mcp_rug_pull` incident, calls blocked until admin re-approval |
| 7 Runaway agent | repeat-call detector + GPU-second budget trip, breaker opens, `budget_breach` events |
| 12 Admin User 360 | deny grant on `opencode.bash` → next `/v1/decide` blocked with rule id; revocation restores access |
| 13 Core banking (bonus) | permitted columns pseudonymised; stacked `; DROP` and out-of-scope columns blocked; canary rows never leave; attacker sink empty |
| 1 / LibreChat | Keycloak login; each user's own token forwarded → personalised model lists; chats audited as the signed-in user |

## Test counts

- Deterministic: **1 513** — 1 001 gateway unit (parallel), 29 policy-service (serial), 483 system incl. **328/328 case cells**
  (Wilson 95 % CI 98.8–100 %); case lint 1 warning (SEC-TAINT-01 has no YAML cases: the harness can't assert labels yet).
- E2E: **22/22**. OpenCode guard plugin (TypeScript): 78 unit tests.

## What was built (Phase 2)

| Task | Delivered |
|---|---|
| 2A MCP proxy + servers | `/mcp/{server}` Streamable HTTP proxy (stdio wrapper), allowlist + identity binding, tools/list pinning + description scan + collisions + personalised lists, per-call policy via `evaluate_point`, result scanning, canary redaction, sampling denied, header/body consistency, no token passthrough; 6 demo servers (governed, files, mail, web, core-banking, rug-pull) |
| 2B Taint / tools / decide / approvals | SEC-TOOL-01 (catalogue, grants, tiers, allowlist mode, confinement, pinned schemas, path/command/url/recipient/sql/package checkers), SEC-FLOW-01 Rule of Two, SEC-TAINT-01, `/v1/decide` (fail closed), approvals with time-boxed elevation, plugin-bypass detection |
| 2C Clients | opencode-guard plugin (device flow, headers, decide before every tool, fail closed), locked container on an internal network with an IdP gate, LibreChat with OIDC and per-user token forwarding |
| 2D Budgets & loops | hierarchical ledger (org→group→user→agent→session), SEC-BUDGET-01 (pre-dispatch, soft/hard, degrade-to-local marked degraded, breakers), SEC-LOOP-01 (repeat, no-progress, steps/depth, spend spike) |
| Orchestrator seams | session store with monotonic labels, `evaluate_point`/`commit_decision`, flow hooks, admin routes split per owner, compose fragments |

## Orchestrator review fixes during integration

- **Approvals were never redeemable**: an approved hold (incl. Rule-of-Two holds approved by an admin) was held again
  forever. New `approvals.redeem()` — only `require_approval` → re-composed decision, only for an approved row matching
  exactly (session, tool, args_hash) whose rule ids cover every holding rule; approve-once consumed atomically.
- **Rule of Two missed sensitive data inside the sink call itself** (untrusted session + PESEL in a `mail.send` body).
  The pipeline now publishes running labels (session ∪ data detected in this payload); SEC-FLOW-01 runs in `decide`.
- SQL scope parser crashed on the documented policy shape (failed closed); fixed.
- PII in tool-call arguments is detected (raises the session class) but not rewritten by default
  (`tool_call_action: monitor`): a legitimate `send_email` must not arrive as `<EMAIL_1>`; exfiltration via tools is
  governed by SEC-TOOL-01 checkers, SEC-EXFIL-01 and SEC-FLOW-01.
- Budget-driven local routing passed explicitly from the decision (replaced a ContextVar side channel).
- Gateway joins the clients' internal network; OpenCode built-ins catalogued (`skill` = confirm).

## Security review (CP2)

Reviewer subagent on SEC-TOOL-01 checkers, taint/Rule of Two, approvals/decide/redeem, MCP proxy, budgets.
12 confirmed + 2 plausible findings; all four highs break Rule of Two or tool containment with no AI involvement.

| # | Sev | Finding | Status |
|---|---|---|---|
| 1 | high | MCP path set approver scope `user` when SEC-TOOL-01 was `decided_by` even with a SEC-FLOW-01 co-hold → user self-approved a Rule-of-Two hold | fixed |
| 2 | high | safe-listed test runners (`pytest`, `npm test`, …) execute repo code an untrusted session just wrote → exfil allowed | fixed |
| 3 | high | `opencode.patch` had no checkers (writes to `~/.bashrc`, git hooks, `/etc/profile.d`) | fixed |
| 4 | high | safe-listed commands that execute/write via glued/prefixed flags (`rg --pre=`, `sort --compress-program=`, `git grep -O`, `sort -o…`) | fixed |
| 5 | high | MCP IFC sessions per upstream server / per request → cross-server trifecta invisible | fixed |
| 6 | med | shell egress detection misses (`git -C . push`, busybox, `node -e`, `python3 x.py`) → admin hold became user-approvable | fixed |
| 7 | med | approve-once double spend on the MCP `?wait=` path | fixed |
| 8 | med | SQL column scope bypass through joins (unqualified column) | fixed |
| 9 | med | recipient lists with an unparseable address passed | fixed |
| 10 | med | Windows filename aliases (`.env.`, `.env::$DATA`) defeat protected paths | fixed |
| 11 | low | privileged requester can approve their own admin-scope hold | fixed |
| 12 | low | elevation waives every SEC-TOOL-01 hold incl. inline-code/persistence in tainted sessions | fixed |
| a | plaus. | base64 MCP resource blobs not decoded before scanning | real; fixed |
| b | plaus. | MCP tool annotations not pinned (flip after pinning undetected) | real; fixed |

Sound (checked): `/v1/decide` fails closed; deterministic controls fail closed; final blocks never relaxed; `redeem` binding
and atomic consumption; user-scope decision rules; principal-namespaced sessions; URL checker (userinfo, `#@`, metadata IPs,
octal hosts); SQL stacked/write/file/sleep functions; path `..`/`%2e`/`~`/drive case; `curl|sh` + decode-to-shell pipes;
hidden MCP tools can't be called; sampling refused; drift covers name/description/schema; budget/loop `inspect()` read-only.

All findings fixed with regression tests that failed before the fix (merged 2026-10-03). **Full-suite + e2e re-run after
the last merge is still pending** (fix branches each passed `dev.py test` + `lint` on their own).

## Decisions recorded

- Panel (Rogatka Dashboard) starts after CP2 approval; keep the Python rules engine (no OPA); no extra reporting
  elements; build a read-only session view behind "Open full conversation / session".
- Rule of Two is intentionally not `locked` (monitor preset stays log-only); SEC-SECRET-01 is.
- `opencode.bash` default tier `allow` with a per-call command checker (unknown commands → approval).
- `opencode.read` / `files.read_file` are `reads_untrusted` + `touches_sensitive` (repo content is untrusted).

## Not done / risks

- **Live model**: `.env` now has `ACL_DETERMINISTIC=0` and `LOCAL_LLM_BASE_URL=http://host.docker.internal:8001/v1`,
  but no tunnel is listening on :8001 → local-model calls return 502 until the WCSS link runs. The newer WCSS tooling
  described in `docs/prompts/wcss-hosting.md` (apptainer image, reverse tunnel, `wcss-link` sidecar) is **not on main**.
- Budget blocks answer HTTP 403 (not 429); loop history in memory; per-user response cache deferred.
- SEC-TAINT-01 has no YAML cases (harness can't assert `labels_after`); approve-once consumption is unit-covered only
  indirectly (a third identical call is also a SEC-LOOP-01 repeat).
- MCP: no GET server→client stream; image/audio result blocks not inspected; sessions in memory (single replica).
- LibreChat demo workarounds: patched to accept an `http://` issuer, no `offline_access`.
- Seed CVE ids in the feed bundle still to verify against NVD.

## Next (after approval): panel track

See `docs/prompts/next-session.md`.
