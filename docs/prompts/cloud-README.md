# Parallel cloud sessions — how they fit together

Three sessions run in parallel in the cloud, each on its own branch, each opening a pull request to `main`. A local
session (the "integrator") keeps WCSS, secrets, the full docker stack, final e2e and merges.

| Session | Prompt | Branch | Owns | Must merge first? |
|---|---|---|---|---|
| **A — Backend deltas + Rogatka Dashboard** | `cloud-a-panel.md` | `feat/panel` (+ `feat/panel-backend` for step 1) | `contracts/` (admin API), panel-facing backend changes, `panel/` | **Step 1 (backend + contract) first**, as its own PR |
| **B — Automation Insights** | `cloud-b-insights.md` | `feat/insights` | `gateway/src/acl/insights/`, insights admin routes, seed data | after A step 1 (rebase on it) |
| **C — Model-file scanner + evidence suite** | `cloud-c-scanner-evidence.md` | `feat/scanner-evidence` | `gateway/src/acl/artifacts/`, artifacts admin routes, `tests/{mutation,perf,redteam}/` | independent |
| **D — Semantic layer** | `cloud-d-semantic.md` | `feat/semantic` | `gateway/src/acl/semantic/`, semantic controls, risk scoring in `engine/decide.py`, complexity routing | **start after A step 1 is merged**; live calibration later, locally, over the WCSS model link |

## Rules for every cloud session

- Start from `main` at or after `f0d5445`. Read `CLAUDE.md` (repo conventions — binding), `docs/checkpoints/CP2.md`
  (current state, decisions, risks) and your prompt.
- **No secrets exist in the cloud**: `.env` is not in the repo. Run everything in deterministic mode
  (`ACL_DETERMINISTIC=1`, mock connectors). Never try to reach WCSS or any model server; never ask for keys.
- The 17-container docker stack is not expected to run in the cloud. Use the in-process test fixtures
  (`create_app(Settings(..., deterministic=True, database_url="sqlite+aiosqlite:///<tmp>"), allow_anonymous_dev=True)`
  with dev headers `X-ACL-Dev-User/-Groups/-Roles`; see `gateway/tests/test_2b_decide_api.py`). Write e2e tests for the
  stack under `tests/e2e/` with the `e2e` marker — the integrator runs them locally.
- Gate before every push: `uv run python scripts/dev.py test` and `uv run python scripts/dev.py lint` (no `make`
  needed; contract drift is part of lint). Python 3.12 via `uv`; Node/pnpm for the panel.
- **Contracts** (`contracts/`, `gateway/src/acl/contracts/`, `acl/policy/models.py`) are owned by session A. B and C may
  add ONLY new models/fields/routes in their own sections (insights / artifacts / metrics) and must regenerate with
  `uv run python scripts/dev.py contracts`; never change existing fields. Mention every contract change in the PR.
- Shared files touched by everyone (`gateway/src/acl/main.py` INSTALLERS, `policy/controls.yaml`, `pyproject.toml` /
  `uv.lock`): one-line, additive edits only; the integrator resolves conflicts.
- Commit messages: plain, descriptive; **no AI/assistant attribution or co-author trailers**.
- Stop at your checkpoint, open the PR, and summarise: what was built, test counts, contract changes, follow-ups that
  need the local stack or WCSS.
