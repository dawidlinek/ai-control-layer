# Rogatka Dashboard — what is left (state 2026-10-04 03:00)

Scope and look: `docs/ux/HANDOFF.md` (wins over older UX docs). Conventions for screen work: `panel/ARCHITECTURE.md`.

## Done (on local `main`, not pushed)

**Backend (step 1, `feat/panel-backend` merged)**
- SEC-SESSION-01: confidential session → every later request local-only; `x-acl-session-label` header; route reason
  cites the rule; `SessionLabels.since`; 13 YAML cases + integration test + live-stack e2e (`tests/e2e/test_cp3_session_label.py`).
- Model lineup: `local/qwen3.8-27b` (aliases local, fast), `gemini/flash` (smart), `gemini/pro` (smart-pro),
  prompt-configured specialist `local/loan-memo`; `auto` picks Flash / Pro by a deterministic complexity score
  (`acl/routing/complexity.py`, bands in `routing.yaml`).
- Seed fixes: developers without `smart`; credit-analysts get `opencode.read/edit/bash`; `operations` group;
  demo secret in `mcp-servers/files/workspace/config/settings.py` (story F6 no longer touches `.env`).
- Admin API for the panel: enriched `EventSummary` (summary sentence from templates, changed_steps, session_label,
  client_ref, applied, tokens, …), `GET /events/{id}/trace`, `GET /sessions/{id}/transcript` (redacted only),
  users `preset` + `stats_7d`, `/users/{id}/activity`, groups `settings` + `stats_today` + preview / save as a new
  policy version, overview timeline + cost by model + budget figures, model day stats + role.

**Panel foundation (`panel/`, merged)**
- Next.js 15 + TS + Tailwind v4 + shadcn-style UI, HANDOFF tokens (dark default + light, no flash), shell (logo,
  sidebar with Incidents/Approvals badges, profile menu with theme switch, shortcuts dialog, sign-out).
- 30+ shared primitives in `src/components/rogatka` (DecisionBadge, RuleChip, DataTable, ListWithSidebar,
  StepTimeline, Meter, FilterRow, Pagination, StatusBox, …), typed API client (openapi-fetch), `/admin/v1` proxy with
  bearer token + SSE streaming, `useEventStream`, Auth.js Keycloak (+ dev mode as Katarzyna Wójcik), role helpers.
- MSW mock API: working handlers for events (few), incidents (7 open), approvals (3), policy status, users (current
  user); empty stubs for the other domains.
- 170 Vitest + 21 Playwright shell tests; `panel/Dockerfile`, `deploy/compose.panel.yml` (profile `panel`).
- Verified in the browser pane: shell, badges, profile menu, light/dark switch.

## Left to do

### 1. Screens (all 12 + session view are placeholders)

Each = feature folder `src/features/<screen>/`, thin route page, mock data + handlers for its domain(s), component
tests for its key interactions, one Playwright spec. Data/copy from `docs/ux/design-reference/*.dc.html`.

| # | Screen | Route | Mock domains | Key interactions / flow |
|---|---|---|---|---|
| 1 | Traffic + trace sidebar (hero) | `/traffic` | events | filters in URL, hide allowed, session-label chip, trace sidebar: sentence, facts, model saw, step timeline with expandable controls, "Open full conversation / session →" — F1 |
| 2 | Session view (read-only) | `/sessions/[id]` | events | redacted turns, decision + rules per turn, link back to trace — F1 |
| 3 | Policies (Rules / YAML / History) | `/policies` | policy | SEC-PI-01 threshold → dry-run impact → Publish as v9; SEC-SESSION-01 rule; Monaco + monaco-yaml with schema; invalid-on-disk banner; 409 conflict; history diff + rollback — F2, F3 |
| 4 | Users & groups (People / Groups) | `/users` | users | access list with sources, + Grant / Revoke, "their clients see", recent activity; group management (preset, models, tools, cloud ceiling, budget) → preview → Save as policy vN — F4, F5 |
| 5 | Grants | `/grants` | grants | quick filters, sidebar history, new grant form with ceiling check, extend / revoke |
| 6 | Approvals | `/approvals` | approvals | countdown, what it wants to do + red flags, why held (Rule of Two reasons), Deny / Approve once / Approve for 5·15·60 m — F6 |
| 7 | Incidents | `/incidents` | incidents | assign to me, status, notes; typed evidence: MCP rug-pull diff, budget breaker states; do-something buttons — F7, F8 |
| 8 | Models & connectors | `/models` | models | kill switch with reason → degraded message; model sidebar (who can use it, how auto picks it); guard models section; NEW lineup only |
| 9 | Tools & MCP | `/tools` | tools | quarantined tool diff → incident, approved versions, re-approve — F7 |
| 10 | Known threats (Signatures / Model files) | `/threats` | feed | sync now, add rule (demo feed server) → bundle +1 — F11 |
| 11 | Budgets & spend | `/budgets` | budgets | tree with bars/breakers, default selection `s_77c1`, reset breaker, by model — F8 |
| 12 | Overview | `/` | overview, events | 3 panels (what is happening / are we safe / what is it costing), range switch, Recharts |
| 13 | Automation Insights | `/insights` | insights | repeated tasks → draft skill → publish; specialist tab honest about `local/loan-memo` (prompt-configured, no fine-tune) — F10 |

Partial work exists only for #1/#12 (uncommitted, worktree `.claude/worktrees/agent-aa98972f5bf0d1690`).

### 2. API gaps found while building (decide: extend the contract or derive in the panel)
1. No totals / page counts on list endpoints (designs show page numbers and tab counts).
2. No count endpoint for sidebar badges (panel lists and counts client-side).
3. `EventSummary` has no tool-argument preview (e.g. `bash: git push`).
4. `Incident` evidence is the free-form `detail` map (rug-pull diff, breaker states) — typed readers needed in the panel.
5. `Approval` lacks approver label, data class, client, red-flag details, preview type.
6. Fields with server defaults are optional in the generated types (worked around with `Resp<T>`).
7. No group-members / Keycloak link endpoint.
8. No admin route to add a feed rule (Known threats "Add rule" must call the demo feed server).
9. SSE summaries use the default SEC-SESSION-01 threshold and carry no `client_ref`.

### 3. Verification before the CP3-panel report
- `pnpm -C panel typecheck && lint && test && build` (normal and mock mode; check no MSW chunk ships:
  `grep -rl "\[MSW\]" panel/.next/static` must be empty), full `pnpm -C panel e2e`.
- Browser walk-through of every screen (dark + light, 1440 px and narrow) and flows F1–F8, F10, F11
  (F9 break-glass and F12 reports belong to dropped screens).
- Backend: `uv run python scripts/dev.py test` on a quiet machine (policy-watcher timing tests not yet re-run),
  `dev.py lint`.
- Integrator (needs the local stack): real Keycloak login with client `panel` (port 3000 redirect URI), SSE through
  the panel proxy against the gateway, group save / policy publish → hot reload, `docker compose --profile panel up`.
- CP3-panel report in `docs/checkpoints/` (built, screenshots list, test counts, contract changes, integrator checks).

### 4. Open decisions for the user
- Developers reach Gemini through `auto` (by design: `auto` grants the routing targets); only picking `smart` by name
  needs a grant. Keep, or give developers a local-only router alias?
- Session D (`docs/prompts/cloud-d-semantic.md` item 9) should build on the existing complexity routing, not redo it.
- Keycloak realm has Jan in credit-analysts and Anna in developers — the reverse of the HANDOFF personas.
- Push `main` so cloud sessions B/C/D can rebase.
- Execution approach for the screens (shared checkout + one dev server + 3 agents at a time recommended).
