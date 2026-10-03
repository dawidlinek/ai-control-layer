# Cloud session A — backend deltas, then the Rogatka Dashboard

> Paste everything below the line into a new cloud session on `github.com/dawidlinek/ai-control-layer`.

---

You are the lead engineer for **Rogatka** (repo name: ai-control-layer), a company-wide AI gateway. Phases 0–2 are done
and on `main` (CP0–CP2 in `docs/checkpoints/`). Read, in order: `docs/prompts/cloud-README.md` (rules for parallel
cloud sessions — binding), `CLAUDE.md` (repo conventions — binding), `docs/checkpoints/CP2.md`, `docs/ux/HANDOFF.md`
(the panel's final scope, look and API needs — wins over older UX docs), then `docs/CONCEPT.md` as needed.

You may run parallel sub-tasks in isolated worktrees for the screens; you own merging them. Each must stay inside its
owned paths and pass `dev.py test` + `lint` before you merge it.

## Step 1 — backend + contract changes (own PR `feat/panel-backend`, merge first; sessions B/C rebase on it)

From `HANDOFF.md` §7–8 (decisions already made by the user):
1. Model lineup: Gemini Flash (fast cloud, alias `smart`) + **Gemini Pro** (strong cloud; router picks by complexity
   band) + local **Qwen3.8-27B** (`qwen3.8-27b`, all confidential work). No Bielik. Keep the `auto` → specialist
   mechanism but no fine-tuned specialist in the demo. Model names only via `env:` refs in `policy/models.yaml`.
2. **SEC-SESSION-01** (new control or router rule): once a session's high-water mark (session labels, `acl.sessions`,
   monotonic) is ≥ confidential (threshold editable in policy), every later request in that session routes
   local-only; trace and response header say why. Paired YAML cases (≥5/≥5).
3. Admin API additions (contract change → `dev.py contracts`): on events `sessionLabel {dataClass, trust, since}`,
   plain-language `summary` (deterministic template per rule/decision type filled from the decision record — never an
   LLM), `changedSteps`, client conversation/session reference; user stats (requests / tokens in·out / blocks, 7 d);
   group stats + editable group settings (preset, models, tools, max cloud data class, daily budget) saved through the
   policy service as a new policy version (draft → validate → impact via dry-run → publish); overview cost by model;
   **session transcript endpoint** for the session view (redacted turns + decision per turn; raw content never).
4. Seed policy fixes (`docs/ux/README.md` C2–C4): remove `smart` from `developers` (so a personal grant matters);
   credit-analysts get `opencode.bash`; one tool-naming scheme; the agent demo story must not read `.env`.
5. Keep the deterministic-gates rule: none of these may relax an enforcement decision.

## Step 2 — Rogatka Dashboard (`panel/`, PR `feat/panel`)

- Next.js (App Router) + TypeScript, shadcn/ui on Radix + Tailwind, TanStack Table/Query, Recharts, Monaco +
  monaco-yaml, nuqs, react-hook-form + zod, Auth.js with Keycloak (client `panel`, roles `acl-admin` / `acl-analyst` /
  `acl-viewer` from the token), generated typed client from `contracts/admin-api.openapi.yaml`, SSE for live updates.
  pnpm with a lockfile. Licences must be permissive (MIT/ISC/Apache).
- 12 screens + the read-only **session view** behind "Open full conversation / session →", in the build order of
  `HANDOFF.md` §11 (shell + tokens + decision badge / rule chip / list-and-sidebar → Traffic with trace sidebar →
  Policies → Users & groups + Grants → Approvals → Incidents → Models & connectors → Tools & MCP → Known threats →
  Budgets → Overview → Automation Insights). Copy, demo data, tokens and icons come from
  `docs/ux/design-reference/*.dc.html` (prototype format, not production code). UI language English; product name
  **Rogatka** everywhere in UI copy. Dark default + light theme.
- The Automation Insights screen is built against the insights contract; session B builds that backend in parallel.
- Develop against a mock API (e.g. MSW handlers generated from the OpenAPI examples) so the panel runs without the
  gateway; add a `panel` service to `deploy/compose.clients.yml`-style fragment (`deploy/compose.panel.yml`, included
  from the main compose) for the integrator to run against the real stack.
- Tests: component tests for the shared primitives and each screen's key interaction; Playwright e2e against the mock
  API (`pnpm -C panel test`, `pnpm -C panel e2e`).

## Checkpoint (CP3-panel) — stop and report

Step 1 merged; all 12 screens + session view render against the mock API with the demo data; key flows from
`docs/ux/02-flows.md` that still exist (ignore dropped screens) work; `dev.py test` + `lint` green; panel tests green.
Report: what was built, screenshots list, test counts, contract changes, what the integrator must verify locally
(real Keycloak login, SSE against the gateway, policy publish → hot reload).
