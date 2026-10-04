# Handoff: finish the Rogatka Dashboard locally (integration with the real stack)

You are the local integrator for the Rogatka Dashboard (`panel/`) in repo `ai-control-layer`. A cloud session built all
12 screens + the session view against the MSW mock API. Your job: make the panel work against the real gateway, close
the API gaps, and get it merged.

## Start here
1. `git fetch origin main-k95m17 && git checkout main-k95m17` (or merge it into local `main`). Last cloud commit: `507fc37`.
   The branch is `main` @ fc66307 plus the panel screens; nothing there touches `gateway/`, `policy/` or `contracts/`.
2. Read, in order: `CLAUDE.md` (binding), `docs/checkpoints/CP3-panel.md` (what was built, every API gap, what to verify),
   `panel/ARCHITECTURE.md` (panel conventions, mock layer, ownership), `docs/ux/HANDOFF.md` (scope and look).
3. `pnpm -C panel install`, then establish the baseline:
   - `pnpm -C panel typecheck && pnpm -C panel lint && pnpm -C panel test && pnpm -C panel build`
   - `pnpm -C panel e2e` (mock mode, port 3100)
   - `uv run python scripts/dev.py test` and `uv run python scripts/dev.py lint`

   Cloud state: 341 Vitest, 44/44 Playwright, backend 1269 + 29 + 526 passing, lint clean.

## State at handoff
- **Done (mock mode):**
  - Screens: Overview, Traffic + trace sidebar, Session view, Incidents, Approvals, Users & groups (People/Groups),
    Grants, Policies (Rules/YAML/History), Models & connectors, Tools & MCP, Known threats, Budgets & spend,
    Automation Insights.
  - Each screen lives in `panel/src/features/<screen>/` with its mock db/handlers in `panel/src/mocks/{db,handlers}/<domain>.ts`
    and one spec in `panel/e2e/<screen>.spec.ts`.
- **Never run against the real gateway / Keycloak** (cloud had no docker stack).
- **No contract changes were made.** The panel works around the gaps with tolerant readers over free-form fields and with
  demo-only data. Actions without endpoints are disabled with the title "Not available in the admin API yet".

## Tasks

### 1. Real-stack verification (do first, fix what breaks)
- `make up` (or `uv run python scripts/dev.py up`), then the panel against the gateway: `pnpm -C panel dev` with `.env` values
  `AUTH_SECRET`, `AUTH_KEYCLOAK_ID/SECRET/ISSUER`, `ROGATKA_GATEWAY_URL`. Then also `docker compose --profile panel up`
  (`deploy/compose.panel.yml`, `panel/Dockerfile`).
- Keycloak login with client `panel` (redirect URI on port 3000); roles `acl-admin` / `acl-analyst` / `acl-viewer` gate the UI; sign-out.
- SSE through the panel proxy `/admin/v1/events/stream`: new rows on Traffic, Incidents/Approvals badges update.
- Group save and Policies publish → new policy version → gateway hot reload; rollback; YAML save with a stale version → 409;
  an invalid file edited on disk → banner and the last good version kept.
- Walk every screen with real data and fix anything that assumes demo-only fields. Known spots where real data will be thinner:
  - approvals: details parsed from `arguments_preview` / `reason`;
  - incidents: evidence in `detail`;
  - budgets: extra `usage` keys;
  - models: `tags`;
  - feed: the signatures list is fixed demo data;
  - traffic: the `command` preview.
- Run the demo flows F1–F8, F10, F11 (`docs/ux/02-flows.md`) through the real clients (LibreChat / OpenCode) and watch them in the panel.

### 2. Close the API gaps (contract owner = this session)
The table in `CP3-panel.md` lists each gap with a suggested change. Recommended order:
1. Approval typed fields: `approver_label`, `data_class`, `client`, `flags[]`, `preview{type,body}`, `reasons[]`.
2. Typed incident `detail` per category.
3. `GET /feed/signatures` + `POST /feed/rules` (proxy to the demo feed server), so Known threats "+ Add rule" works (F11).
4. List totals (`total` or `X-Total-Count`) and `GET /metrics/counts` for the badges.
5. A `{reason}` body on policy rollback.
6. Then, as time allows: `EventSummary.tool_preview`, trace by trace id, grant extend/edit, replay / add-to-incident,
   budget forecast / by-model / limit source, insights dismiss + skills list, group members + Keycloak URL, `client_ref`
   in SSE summaries, schema generation in serialization mode.

For each change:
- change the Pydantic models and routes;
- run `uv run python scripts/dev.py contracts`, then `pnpm -C panel gen:api`;
- replace the panel's workaround reader with the typed field and update the mock fixtures and tests;
- re-enable the disabled button.

Rule: new fields only, no breaking changes; sessions B, C and D build on the contract.

### 3. Smaller panel items
- Optional: wire `monaco-yaml`. It needs a webpack alias in `panel/next.config.ts` for
  `monaco-editor/esm/vs/editor/editor.worker.js` (see `CP3-panel.md`). Then drop or keep the hand-written schema check in
  `features/policies/`.
- Make org-locked YAML lines read-only in the editor.
- Promote local helpers the screen agents duplicated:
  - URL-memory test helper (`features/traffic/test-url.tsx`, `features/overview/test-url.tsx`) → `renderApp` option;
  - `DiffBox`, `useNow`, `EffectChip`, the tool status chip → `components/rogatka`;
  - a `disabled` prop on `Segmented`; a Select primitive.
- Not built: two-person approval and GitOps mode (CONCEPT §11.1, `docs/ux/03c` §10). Decide whether they are in scope.

### 4. Open decisions (ask the user, do not change silently)
1. Developers reach Gemini via `auto` (`auto` grants its routing targets). Keep it, or add a local-only router alias for developers?
2. Session D (`docs/prompts/cloud-d-semantic.md` item 9) must build on `acl/routing/complexity.py`, not redo it.
3. The Keycloak realm has Jan in credit-analysts and Anna in developers, the reverse of the HANDOFF §6 personas
   (the panel mocks follow HANDOFF). Fix the realm or the docs?
4. HANDOFF §10 open questions (Qwen tag, OPA, reporting lines for the dropped Assure screens, roles).

## Done when
- Panel checks and backend checks green.
- Every screen verified against the real stack, in dark and light.
- The contract gaps above closed or explicitly deferred.
- `docs/checkpoints/CP3-panel.md` updated with the integration results.
- Merged to `main` and pushed, so cloud sessions B, C and D can rebase.

## Rules
- Commit messages are plain, with no AI attribution or co-author trailers.
- Never commit secrets; `.env` stays local.
- No raw sensitive values in fixtures, logs or tests: masked values and placeholders only.
- pnpm only for the panel; uv only for Python; LiteLLM is banned.
- Policy changes go through the policy service (draft → validate → impact → publish).
