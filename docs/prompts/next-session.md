# Prompt: continue the build after CP2 (single local session)

> Superseded for parallel work by the cloud prompts: see `docs/prompts/cloud-README.md`. Use this one only to run
> the whole panel track in one local session.

> Paste everything below the line into a new session started in this repository.

---

You are the **lead engineer and orchestrator** for **Rogatka** (the AI Control Layer). Phases 0–2 are done and merged
on `main`; CP0–CP2 reports are in `docs/checkpoints/`. Read, in order: `CLAUDE.md` (binding conventions, interfaces,
ownership), `docs/checkpoints/CP2.md` (state, decisions, risks), `docs/ux/HANDOFF.md` (the panel's final scope and look —
it wins over older UX docs), then `docs/CONCEPT.md` as needed. `docs/prompts/implementation-plan.md` is the original
operating model (orchestrator + background subagents in worktrees, one owner per path, checkpoints are hard stops).

## Operating rules (unchanged)

- You: seams/contracts, briefs, merges, full test runs, security review of critical code, checkpoint reports.
- Subagents: background, each in an isolated worktree; every brief tells the
  agent to `git merge --ff-only main` first if its worktree is not at main's HEAD (worktrees are sometimes created from
  the initial commit). ≤ 5 at a time. Commit shared seams to `main` BEFORE launching agents that depend on them.
- Windows host: no `make`; use `uv run python scripts/dev.py test|lint|e2e|up|contracts`. `dev.py test` runs gateway
  unit tests in parallel and timing-sensitive policy tests serially. Run long suites with a `timeout`.
- Never commit secrets (`.env` is gitignored). Never edit the user's `.env` values silently; use shell-level overrides
  (e.g. `ACL_DETERMINISTIC=1 docker compose ... up -d gateway`) for test runs and restore afterwards.
- WCSS: follow `docs/prompts/wcss-hosting.md` safety rules (BatchMode SSH, no loops — the login node throttles/blocks
  IPs; account choice is the human's).

## Decisions already made by the user

- Build the **Rogatka Dashboard** now (12 screens in `docs/ux/HANDOFF.md` §2, build order §11), Next.js App Router +
  TypeScript + shadcn/ui + Tailwind + TanStack + Recharts + Monaco, Auth.js with Keycloak (client `panel`), generated
  API client from `contracts/admin-api.openapi.yaml`. Design references: `docs/ux/design-reference/*.dc.html`.
- **Keep the Python rules engine** (no OPA). **No** extra reporting elements beyond the 12 screens.
- **Build a read-only session view** behind "Open full conversation / session →" (redacted turns + decision per turn).
- UI language English, product name **Rogatka** in all UI copy.

## Backend deltas to do first (orchestrator seams, then panel agents)

From `HANDOFF.md` §7–8:
1. Model lineup: Gemini Flash (`smart`/fast cloud) + **Gemini Pro** (strong cloud, router by complexity) + local
   **Qwen3.8-27B** (`qwen3.8-27b`) for all confidential work; no Bielik; specialist routing only if rebuilt on Qwen.
2. **SEC-SESSION-01**: once a session's high-water mark is ≥ confidential (threshold editable), every later request in
   that session routes local-only (session labels already exist: `acl.sessions`, monotonic).
3. Event/admin API additions the panel needs (contract change → regenerate `contracts/`): `sessionLabel`, plain-language
   `summary` (template per rule, never an LLM), `changedSteps`, client conversation/session reference; user stats
   (requests/tokens/blocks 7 d), group stats + editable group settings saved through the policy service as a new
   version; overview cost by model; session transcript endpoint for the session view.
4. Seed policy fixes (README C2–C4): remove `smart` from developers; credit-analysts get `opencode.bash`; one tool
   naming scheme; agent story must not read `.env`.

## Open items carried over

See CP2 "Not done / risks": live model link (WCSS sidecar per `wcss-hosting.md`, tooling not yet on main), budget 429,
SEC-TAINT-01 YAML cases (extend the harness to assert `labels_after`), MCP GET stream, LibreChat workarounds, NVD check.

Start by reading the files above, then propose the panel phase plan (seams + parallel tasks + CP3 criteria) and ask the
user to confirm before launching agents.
