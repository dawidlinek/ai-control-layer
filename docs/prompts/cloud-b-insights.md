# Cloud session B — Automation Insights (the product's unique twist)

> Paste everything below the line into a new cloud session on `github.com/dawidlinek/ai-control-layer`.

---

You build **Automation Insights** for **Rogatka** (repo ai-control-layer), a company-wide AI gateway. Read, in order:
`docs/prompts/cloud-README.md` (rules for parallel cloud sessions — binding), `CLAUDE.md` (repo conventions —
binding), `docs/CONCEPT.md` §14 (the feature), §7.3 (`auto` and skills), §11 (policy), `docs/ux/HANDOFF.md` §5.12
(the screen and its data), `docs/checkpoints/CP2.md`. Branch `feat/insights`; rebase on session A's
`feat/panel-backend` once it is merged to `main` (until then build on `main`).

## The idea

Employees repeat the same AI-assisted tasks (a credit analyst summarising a loan application every morning). Detect
these patterns from **already-redacted** prompts, and turn them into **governed skills**: a fixed prompt template, an
input schema, the cheapest model that is good enough, a stricter preset and a narrow toolset — published as
`skill/<name>`, so it appears in every client through the personalised `/v1/models`. Pitch: *turn shadow AI usage into
approved, cheaper, safer workflows.*

## Build (owned paths: `gateway/src/acl/insights/`, `gateway/src/acl/api/admin/insights.py` (split it out of
`api/admin/platform.py`), insights section of `gateway/src/acl/contracts/admin.py`, `tests/cases/insights.yaml`,
`gateway/tests/test_insights_*.py`, seed data under `deploy/seed/insights/`, one INSTALLERS line)

1. **Input**: redacted prompts + metadata (user, groups, time, model, tokens in/out, latency, retries) from the audit
   index (`acl.audit`, `redacted_payload` + summary columns). Never raw text; never the vault.
2. **Embed** with the policy's `routing.targets.embeddings` model through the gateway's own connectors (deterministic
   mock embeddings in tests; real model later via the local WCSS link — do not try to reach it).
3. **Cluster per group** over a time window (HDBSCAN; add the dependency hash-locked with `uv add` — check its licence;
   a deterministic fallback such as agglomerative clustering on cosine is fine if HDBSCAN is unsuitable).
4. **Recurrence**: periodicity (daily/weekly), structural similarity, repeat count, distinct users.
5. **Cost estimate**: tokens, USD (model pricing), GPU-seconds, wall-clock time, retries; counterfactual saving if the
   task ran as a skill on the cheapest adequate model.
6. **Task card + draft skill**: a local LLM writes the plain description, template with `{placeholders}`, input schema
   (JSON Schema), suggested model, preset, tools — through the gateway connectors (mock in tests). The draft is
   **validated deterministically** (schema, placeholders ↔ inputs, model exists and is allowed for the group's data
   classes, tools ⊆ group tools) — the LLM proposes, code decides.
7. **Publish**: admin action writes the skill into `policy/models.yaml` `skills:` + the group's `skills:` through the
   **policy service writer** (new policy version, hot reload; same path as panel edits). After publish, the skill shows
   in that group's `/v1/models` and is routable; requests to `skill/<name>` render the template server-side and run under
   the skill's preset/model/tools.
8. **Privacy by design**: only redacted text; local models only; management sees only clusters with ≥ k distinct users
   (k configurable, default 5); individuals see only their own suggestions; per-group opt-in setting.
9. Worker: a background task (startup hook + interval) plus an admin "recompute" action; idempotent; bounded memory.
10. **Seed data** for the demo: realistic redacted history for `credit-analysts` (loan-application summaries daily,
    ~40 min/day) and `developers` (e.g. writing release notes), so the screen and scenario 14 work out of the box.
11. API per the insights contract (`InsightCluster`, `PublishSkillRequest`, list/publish/dismiss/recompute, skills list
    with runs and cost per run before → now) — extend the contract only in the insights section; regenerate contracts.

## Tests (definition of done)

Unit tests per pipeline stage (deterministic embeddings → known clusters), privacy threshold (k), publish → new policy
version → skill visible in `/v1/models` for the group only → a request to the skill renders the template and is
governed by the skill preset; draft validation rejects bad LLM drafts; paired YAML cases where meaningful; a scripted
e2e for scenario 14 under `tests/e2e/` (marker `e2e`). `dev.py test` + `lint` green.

## Checkpoint — stop and report

PR `feat/insights` with: what was built, test counts, contract changes, the demo story script for scenario 14, and what
the integrator must verify locally (real embeddings/LLM via WCSS, panel screen against the real API).
