# CP3-panel — Rogatka Dashboard screens

*2026-10-04 · cloud session A (branch `main-k95m17`, based on `main` fc66307)*

## Acceptance

| Criterion | Status |
|---|---|
| All 12 screens + session view render with demo data (mock API) | **Done**: every route in HANDOFF §2 plus `/sessions/[id]` |
| Key flows work against the mock API (F1–F8, F10, F11) | **Done**, with the gaps listed below (F11 "Add rule" has no admin route) |
| `pnpm -C panel typecheck / lint / test / build` | **Green**: 341 Vitest tests in 37 files; build in normal and mock mode; no MSW code in the normal build (`grep -rl "\[MSW\]" .next/static` is empty) |
| `pnpm -C panel e2e` (Playwright, mock mode) | **Green**: 44/44 (shell 18 + one spec file per screen) |
| `uv run python scripts/dev.py test` + `lint` | **Green**: 1 269 gateway unit + 29 policy-service + 526 system (369/369 case cells); lint clean, no contract drift. The policy-watcher timing tests in `test_1b_policy_service.py` pass here: the local failures came from CPU load. |
| Browser walk-through, dark + light, 1440 px and 600 px | **Done**: 17 views (screens, tabs and key sidebars) screenshotted against the mock production build. No page errors. One layout bug was found and fixed: table header labels pushed the page sideways at 600 px. |

## What was built

Each screen has its own feature folder `panel/src/features/<screen>/`, a thin route page, mock data and handlers for its domain(s), component tests and one Playwright spec (`panel/e2e/<screen>.spec.ts`).

| # | Screen | Highlights |
|---|---|---|
| 1 | Traffic `/traffic` | Paged past requests (`before_seq`). Every filter is in the URL (range, decision, who, point, group, data class, q, hide allowed). Session-label chip. Trace sidebar: sentence, facts, "Session confidential since … · local only", Open full conversation/session, *What the model saw* (only when content changed), step timeline with expandable controls. 12 prototype events plus background traffic |
| 2 | Session view `/sessions/[id]` | Read-only redacted transcript; decision + rule chips per turn; links back to each trace; friendly not-found |
| 3 | Policies `/policies` | Rules (lock icon for org locks). SEC-PI-01 threshold and SEC-SESSION-01 threshold → dry-run impact → Publish as v9 → header updates. YAML tab: Monaco, file switcher, JSON-Schema check as you type, Validate, Save as vN, 409 conflict, invalid-on-disk banner. History tab: diff and rollback |
| 4 | Users & groups `/users` | People: Access list with sources, inline + Grant / Revoke / Restore, "Their clients see", recent activity. Groups: strictness, models, tools, cloud ceiling (LOCK-01), budget → preview summary → Save as policy v9 |
| 5 | Grants `/grants` | Quick filters (+ "Ended", so expired grants and "Grant again…" can be reached), sidebar history, new-grant form with the LOCK-01 ceiling check, revoke |
| 6 | Approvals `/approvals` | Live countdown / auto-deny pill, red flags, preview (diff, e-mail, plan), numbered Rule-of-Two reasons, Deny (primary red) / Approve once / Approve for 5·15·60 m, reason required, inline consequence, badge updates |
| 7 | Incidents `/incidents` | Tabs, filters, Assigned to me, assign, status, notes timeline; typed evidence for MCP rug pull (hash + description diff + finding chips) and budget breach (breaker states, GPU-s meter); type-specific actions on real endpoints |
| 8 | Models & connectors `/models` | Connector cards with kill switch (reason dialog → degraded message). NEW lineup only (gemini/flash, gemini/pro, local/qwen3.8-27b, local/loan-memo). Who can use it, How auto picks it, Guard models section |
| 9 | Tools & MCP `/tools` | Tabs and filters, quarantined diff → inc-0057, approved versions, re-approve / keep quarantined with reason, OpenCode built-ins |
| 10 | Known threats `/threats` | Feed status bar + Sync now, Signatures with sidebar and recent hits, Model files from `/artifacts` |
| 11 | Budgets & spend `/budgets` | Today / This month, three summary cards, tree with meters and breakers (live countdown), default selection `s_77c1`, reset breaker, by model, "Limit set in budgets.yaml Lx" |
| 12 | Overview `/` | What is happening (stacked chart by decision, legend totals, Notable now), Are we safe (open incidents by severity, top OWASP risks), What is it costing (USD and GPU-s with forecast, cost by model); range switch |
| 13 | Automation Insights `/insights` | Repeated tasks → draft skill → try with an example → Publish skill → "Saved as policy v9"; Skills tab; Specialist tab states plainly that `local/loan-memo` is prompt-configured on the local Qwen, with no fine-tune |

Shared changes made by the lead (all additive):
- Response type aliases and query keys for every domain (`lib/api/types.ts`, `lib/api/hooks.ts`).
- `DataTable` scroll box is `relative`.
- App icon (`src/app/icon.svg`).
- Optional `PLAYWRIGHT_CHROMIUM_PATH` in `playwright.config.ts`, for containers with a pre-installed Chromium.

## Contract changes

**None.** All nine API gaps from `docs/prompts/panel-remaining.md` were worked around in the panel. `contracts/` stayed untouched because sessions B, C and D build on it in parallel. Each workaround tolerates a real gateway that does not send the extra data: the screen leaves that detail out instead of breaking.

| Gap | Workaround in the panel | Suggested contract change (orchestrator) |
|---|---|---|
| No totals / page counts | Fetch with a high limit and page in the browser; events use `before_seq` + `hasNext` | `total` on list responses or an `X-Total-Count` header |
| No count endpoint for badges | Count client-side (unchanged from the foundation) | `GET /metrics/counts` |
| No tool-argument preview on `EventSummary` | Sidebar reads a demo `command` from the audit record; the list shows the tool name | `EventSummary.tool_preview` |
| Untyped `Incident.detail` | Tolerant typed readers per category (`features/incidents/readers.ts`) | Typed `detail` per category |
| `Approval` lacks approver label, data class, client, red flags, preview | Demo data is encoded in `arguments_preview` / `reason`, then parsed by tolerant readers; the approver label comes from `approver_scope` | Typed fields: `approver_label`, `data_class`, `client`, `flags[]`, `preview{type,body}`, `reasons[]` |
| Server-default fields optional in generated types | `Resp<T>` (foundation) | Generate the schema in serialization mode |
| No group members / Keycloak link | Members derived from `/users` filtered by group; Keycloak links disabled | `GET /groups/{name}/members`, `keycloak_url` in settings |
| No admin route to add a feed rule, none to list signatures | Signatures are a fixed demo list (noted under the table); **+ Add rule is disabled** | `GET /feed/signatures`, `POST /feed/rules` (proxy to the feed server) |
| SSE summaries: default threshold, no `client_ref` | Rows from SSE show without the client reference until the list refetches | Fill both in the SSE path |

Further gaps the screen agents found (actions are disabled with the title "Not available in the admin API yet" unless noted):
- **Traffic:** Replay with live policy, Add to incident. `/events/{id}/trace` accepts an event id only, not a trace id.
- **Grants:** extend and edit; there is no "budget" grant type.
- **Rollback:** the policy rollback route takes no body, so the required reason is collected in the panel but never sent or stored.
- **Policies:** there is no rules endpoint (rules are read from `controls.yaml`), no per-rule hits beyond overview `top_rules`, and no test-suite figures in the dry-run response.
- **Models:** connectors report p50, not p95. Model sidebar extras ride in `ModelInfo.tags`. Add connector, Turn off model, Add MCP server and Remove server have no endpoints.
- **Budgets:** `BudgetNode` lacks forecast, hourly spend, split by model and the limit's source; demo data rides in extra `usage` keys. Change limit… links to the YAML instead.
- **Insights:** no skills or specialist endpoints, and Dismiss has no endpoint. Publishing a skill does not return the new policy version (the panel re-reads `/policy`).
- **Incidents / Approvals:** Remove server and Export evidence have no endpoints.
- **Kill switch:** it is in-memory in the gateway and creates no policy version, so "Saved as policy v9" appears only when a new version really exists.

Known limitations:
- `monaco-yaml` is not wired. Its worker import breaks `next build` with monaco-editor 0.57 unless `next.config.ts` gets a webpack alias. The YAML tab instead validates against `/policy/schema` with a small parser in `features/policies/` (checked against all six real policy files).
- Lines under an org lock are marked in the editor but not read-only; the server rejects such edits with 422.
- Two-person approval and GitOps mode are not built.

## What the integrator must verify locally (needs the stack)

1. Real Keycloak login with client `panel` (redirect URI on port 3000), roles from the realm (`acl-admin` / `acl-analyst` / `acl-viewer`), and sign-out.
2. SSE through the panel proxy (`/admin/v1/events/stream`) against the gateway: new rows appear on Traffic; incident and approval badges update.
3. Group save and policy publish → new version → gateway hot reload; rollback; YAML save with a stale version → 409; an invalid file edited on disk → banner.
4. Every screen against the real admin API. Readers must tolerate missing demo-only fields (approval details, incident evidence, budget extras, model tags).
5. `docker compose --profile panel up` (`deploy/compose.panel.yml`, `panel/Dockerfile`).
6. Optionally, wire `monaco-yaml` with the webpack alias above and confirm the build.

## Open decisions for the user

1. **Developers reach Gemini through `auto`:** `auto` grants its routing targets, so only picking `smart` by name needs a grant. Keep it, or give developers a local-only router alias?
2. **Session D** (`docs/prompts/cloud-d-semantic.md` item 9) should build on the existing complexity routing (`acl/routing/complexity.py`), not redo it.
3. **Keycloak realm vs personas:** the realm has Jan in credit-analysts and Anna in developers, the reverse of HANDOFF §6. The panel mock follows HANDOFF.
4. **Contract extensions:** add the typed fields above (approvals, incidents, feed rules, totals) before the integration pass?
