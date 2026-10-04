# CP3-panel — Rogatka Dashboard screens

*2026-10-04 · cloud session A (branch `main-k95m17`, based on `main` fc66307)*

## Acceptance

| Criterion | Status |
|---|---|
| All 12 screens + session view render with demo data (mock API) | **Done**: every route in HANDOFF §2 plus `/sessions/[id]` |
| Key flows work against the mock API (F1–F8, F10, F11) | **Done**, with the gaps listed below (F11 "Add rule" has no admin route) |
| `pnpm -C panel typecheck / lint / test / build` | **Green**: 341 Vitest tests in 37 files; build in normal and mock mode; no MSW code in the normal build (`grep -rl "\[MSW\]" .next/static` is empty) |
| `pnpm -C panel e2e` (Playwright, mock mode) | **Green**: 44/44 (21 shell + 23 in the screen specs) |
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

## Integration against the real stack (local, 2026-10-04)

*Local integrator session on `main`, after merging `main-k95m17`. Lead + Sonnet subagents, one commit per piece.*

### Verified on the real stack (gateway + Keycloak + feed server in docker, panel `pnpm dev`)

| Check | Result |
|---|---|
| Keycloak login with client `panel`, sign-out | **Works.** Redirect → realm login → back to the panel; `adam` (`acl-admin`) gets the admin UI. A second redirect URI `http://localhost:3005/*` was added for a dev panel when port 3000 is taken |
| SSE through the panel proxy `/admin/v1/events/stream` | **Works after a fix.** The gateway sends named frames (`event: event`); `useEventStream` only listened to `onmessage`, so no live row ever arrived (Traffic, and the incident/approval badges). Fixed in `lib/api/sse.ts`; the mock stream now sends named frames too |
| Traffic, trace sidebar, session link | **Works after a fix.** The list asked for all audit events, so `policy_change` and admin events showed as blank rows; it now asks for `event_type=decision` and SSE drops non-decision events |
| Policy file save → new version → hot reload | **Works:** `PUT routing.yaml` → v37, `/policy` reports the new version within 2.5 s |
| YAML save with a stale version | **409** `stale_version` with the current version in `details` |
| Rollback with a reason | **Works:** `{reason}` stored, shown in History (`rollback to version #36 (…): <reason>`), a 1-character reason → 422 |
| Invalid file on disk → banner, last good version kept | Covered by `test_1b_policy_service.py` and the panel banner test; not re-run live (the running gateway mounted another worktree's `policy/`) |
| Overview, Incidents, Approvals, Users, Grants, Models, Tools, Threats, Budgets, Insights with real data | Render without errors. Fixed: OWASP ids shown twice (names now from a static OWASP LLM 2025 / Agentic table), dozens of idle `agent session` budget nodes (hidden behind "Show N idle sessions", ids shortened), Insights 501 shown as an error and retried 9× (empty state; the default query retry now skips 4xx/501) |
| Light and dark | Light is the default now (STYLEGUIDE); dark still works |
| Bielik on WCSS | `model: bielik` answers from `local/bielik` (host :8002, `bielik-11b`). `auto` sends "Wyjaśnij krótko, czym jest art. 415 Kodeksu cywilnego." to Bielik and English prompts to Gemini Flash; "Jakie są przesłanki odpowiedzialności z art. 471 KC?" still goes to Flash (the lexical matcher misses that wording; the CP3 integration session is building a Polish-legal detector) |

Real data notes: the users list only has people the gateway has seen (no Keycloak directory sync); semantic controls
(SEC-PI-01, SEC-SIM-01, NER, judges) are disabled in `controls.yaml`, so an injection prompt is allowed by the deterministic
tier alone (session D's scope); local connector health is `unreachable` whenever the WCSS tunnel is down.

### Contract gaps closed (additive; contracts regenerated, no drift)

| Gap | Change | Commit |
|---|---|---|
| Approval details parsed from `arguments_preview` / `reason` | `Approval.approver_label`, `data_class`, `client`, `flags[]`, `preview{type,body}`, `reasons[]` | a16b358, panel fe560e8 |
| Untyped `Incident.detail` | `Incident.evidence`, a union on `kind` built at read time (old rows too); `detail` unchanged | a16b358, panel fe560e8 |
| Rollback reason never sent | `POST /policy/versions/{id}/rollback` body `{reason}` (3–500), `PolicyVersion.reason`, migration `3p_policy_version_reason` | a16b358, panel fe560e8 |
| No signatures list, no "+ Add rule" (F11) | `GET /feed/signatures` (bundle + offline baseline, 24 h hits), `POST /feed/rules` (proxied to the feed server's `POST /entries`, then synced; audit without the pattern) | 5e66a48 |
| No totals | `X-Total-Count` on `/users`, `/grants`, `/incidents`, `/approvals`, `/feed/signatures` | 5e66a48 |
| No count endpoint for badges | `GET /metrics/counts` → `{open_incidents, pending_approvals, quarantined_tools}` | 5e66a48 |
| SSE summaries thinner than list rows | Live rows are built like `/events` rows (session label threshold, `client_ref`) | 5e66a48 |
| No tool preview | `EventSummary.tool_preview` (masked, ≤ 120 chars) | 5e66a48 |

Still deferred: totals on `/events` (cursor paging), grant extend/edit, replay / add-to-incident, budget forecast / by-model /
limit source, group members + Keycloak URL, rule delete from the panel, schema generation in serialization mode.

### Decisions taken with the user

1. **Model choice:** users pick cloud (`flash`/`smart`, `pro`/`smart-pro`), local (`qwen`/`local`, `bielik`) or `auto`.
   Sensitive data still escalates: a confidential request on a cloud pick is rerouted local (LOCK-01). Admin routing rules
   are specialist examples in `models.yaml` (e.g. Polish legal text → `local/bielik`, kNN-style lexical matcher).
   Bielik runs on its own vLLM server on WCSS (connector `local-pl`, `LOCAL_PL_BASE_URL`, `LOCAL_BIELIK_MODEL`).
2. **Realm vs personas:** the realm now follows HANDOFF §6 (Jan in developers, Anna in credit-analysts); e2e users swapped.
3. **Two-person approval, GitOps mode:** deferred.
4. **Look:** `docs/ux/STYLEGUIDE.md` agreed and applied (light default, red brand marks only, ink primary buttons, Deny the
   only red button, Instrument Sans, 14 px body).

### Smaller panel items done

Shared `DiffBox`, `useNow`, `EffectChip`, `ToolStatusChip`, `TextLink`/`linkClass` and a Radix `Select` in
`components/`; `Segmented disabled`; `renderApp({ urlMemory })` replaces the two local URL helpers; Vitest capped at half
the cores with longer async timeouts (the full suite timed out under load on a 22-thread host).
Not done: `monaco-yaml` wiring and read-only org-lock lines (the server still rejects such edits with 422).

## Open decisions for the user (cloud handoff; answered above)

1. **Developers reach Gemini through `auto`:** `auto` grants its routing targets, so only picking `smart` by name needs a grant. Keep it, or give developers a local-only router alias?
2. **Session D** (`docs/prompts/cloud-d-semantic.md` item 9) should build on the existing complexity routing (`acl/routing/complexity.py`), not redo it.
3. **Keycloak realm vs personas:** the realm has Jan in credit-analysts and Anna in developers, the reverse of HANDOFF §6. The panel mock follows HANDOFF.
4. **Contract extensions:** add the typed fields above (approvals, incidents, feed rules, totals) before the integration pass?
