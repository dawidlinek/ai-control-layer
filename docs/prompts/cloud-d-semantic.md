# Cloud session D — semantic layer (classifier, NER, similarity, judges, risk score, routing)

> Start **after session A's step 1 (`feat/panel-backend`) is merged to `main`** — both touch `engine/decide.py` and
> `engine/pipeline.py`. Sessions B and C do not overlap with this one. Paste everything below the line into a new cloud
> session on `github.com/dawidlinek/ai-control-layer`.

---

You build the **semantic layer** of **Rogatka** (repo ai-control-layer), a company-wide AI gateway: the probabilistic
detectors that sit on top of the deterministic gates. Read, in order: `docs/prompts/cloud-README.md` (rules for
parallel cloud sessions — binding), `CLAUDE.md` (repo conventions — binding), `docs/CONCEPT.md` §3 (principles — esp.
"deterministic gates decide; AI escalates"), §6 (pipeline, stages 1b/2/3, actions, presets, graded risk §6.5, shadow
judge and calibration §6.6), §7 (routing), §9 (task-scoped policy), §16 (strictness matrix, live mode), §20 (honest
limits), `docs/ux/HANDOFF.md` §7.1 (model lineup) and §7.8 (where decision models are used), `docs/checkpoints/CP2.md`.
Branch `feat/semantic`.

## Non-negotiable invariants (tests must prove them)

- An AI-tier verdict (`similarity`, `l1`, `l2`) can **only make a decision stricter**: allow → warn/sanitize/approval/
  block. It never relaxes a deterministic verdict and never grants access (`engine/decide.py` invariants stay true).
- Every semantic control has `fail_mode` (default `open_with_alert` from `global.fail_mode.semantic`), a `timeout_ms`,
  and never blocks the request path for longer than its budget (`global.latency_budget_ms.semantic`).
- Judges see **isolated, spotlighted inputs**: untrusted text is wrapped and stripped of instructions; the judge prompt
  never contains tool output as instructions; judge output is **structured JSON, validated** — anything else is a
  judge failure (fail mode applies), never "allow".
- No raw sensitive values in logs/audit; model inputs to cloud are impossible here (all detectors run on local models).
- Deterministic mode stays the default for tests: every model call has a deterministic mock so the strictness matrix
  passes with no model server. Live mode (real models) is run later by the integrator.

## Build (controls are already declared, disabled, in `policy/controls.yaml`)

1. **Model access layer** (`gateway/src/acl/semantic/`): thin clients for (a) embeddings through the gateway's own
   connectors (`routing.targets.embeddings`), (b) the judge LLM through the connectors (`routing.targets.judge`, local
   Qwen3.8-27B in production — thinking off, JSON mode/grammar if the server supports it), (c) an ONNX runtime for the
   small classifier, (d) the NER model. Content-hash caching where the verdict depends only on text (`cacheable`);
   guard tokens/GPU-seconds charged to the budget ledger (`budgets` service `charge_guard`).
2. **SEC-PI-01 `injection_classifier`** (L1, ingress + tool_result): an Apache-2.0 DeBERTa prompt-injection model
   exported to ONNX (verify the checkpoint licence; record it in `docs/licences.md`), `onnxruntime` + `tokenizers`
   (add hash-locked with `uv add`, optional dependency group `semantic` so the base image stays slim). Score vs preset
   `injection_threshold`; score inside `judge_band` → escalate to L2; on tool_result a hit raises integrity untrusted.
3. **SEC-NER-01 `pii_ner`** (PII tier T1): Presidio + a multilingual GLiNER PII model (verify licence; spaCy Polish
   models are reportedly GPL — do not use them). Same finding/placeholder machinery as SEC-PII-01 (pseudonymise via the
   vault; offsets on the normalised payload). Names, addresses and other quasi-identifiers the regex tier cannot see.
4. **SEC-SIM-01 `attack_similarity`** (stage 1b): kNN over embeddings of a known-attack corpus built from the signature
   feed (`regex`/`arg_pattern` examples), public injection/jailbreak datasets you can redistribute (check licences) and
   blocked incidents; mean + n-gram pooling so short injections in long text are not diluted; per-preset thresholds;
   corpus versioned and hot-swapped like the feed.
5. **L2 judges** (escalation only — when an L1 score is in the band, or the preset's `judge_on` says so):
   `judge_alignment` (does this tool call serve the trusted `user_request`? isolated context), `judge_contextual_integrity`
   (before send-type actions: is this flow of this data to this recipient appropriate?), `judge_sanitize` (find injected
   spans in a tool result → `Action.sanitize` with span replacements, PromptArmor-style, keeps the rest), PII tier T2
   (quasi-identifiers when T0/T1 are uncertain or the preset is strict). Content safety may be covered by the judge.
6. **Graded risk score** (§6.5): factors intent deviation, tool sensitivity, data sensitivity, chain anomaly, parameter
   risk → `Decision.risk_score` + `risk_factors` (each factor's contribution visible in the trace) → graded action via
   the preset's `risk_cutoffs` (sanitize / approval / block). This extends `engine/decide.py`; keep all existing
   invariants and tests; document the composition at the top of the file.
7. **Shadow judge**: under `balanced`, a sample (`preset.shadow_sample_rate`, default 5 %) of *allowed* traffic is judged
   asynchronously (never on the request path); disagreements are audited; an estimated miss rate feeds the metrics.
8. **Judge calibration**: `scripts/calibrate_judges.py` over a small hand-labelled set you write (benign + attack, EN +
   PL), reporting Cohen's κ, FPR, FNR per judge into `reports/` (run live by the integrator; deterministic dry run in CI).
9. **Routing by complexity and task** (§7, HANDOFF §7.1 as amended 2026-10-04: **Bielik 11B v3 is back** as the local
   Polish-legal specialist next to Qwen3.8-27B): a complexity score (classifier head, or a documented heuristic over the
   prompt) → bands `complexity_bands` → local / Gemini Flash / Gemini Pro; the Polish-legal task signal (a deterministic
   detector exists or is built by the integrator — add embedding-based task matching on top, never replacing it) →
   `local/bielik`; budget-aware escalation; sensitivity and SEC-SESSION-01 still force local; the trace explains "why
   this model". Router stays deterministic given the scores.
10. **Task-scoped policy** SEC-PLAN-01 (strict/paranoid; stretch if time is short): a planner call that sees only the
    trusted user request proposes a narrow tool policy (tools, argument ranges, sinks); the gateway intersects it with
    the static policy (can only narrow) and enforces it deterministically; calls outside the plan → block/approval.
11. **Model artifacts**: the ONNX classifier (and any other weights) must pass session C's artifact scanner and be pinned
    by sha256 in policy (`artifact:`); weights are fetched by `scripts/fetch_models.py` into a cache directory (never
    committed). If the cloud sandbox cannot download them, ship the fetch script + mocks and say so.

## Tests (definition of done)

- Unit tests per control with mocked model outputs (scores, judge JSON, NER spans), including timeouts and malformed
  judge output (→ fail mode, never allow) and the "AI can only escalate" invariant with real deterministic verdicts.
- Paired YAML cases ≥5 positive / ≥5 negative per semantic control, with `matrix` cells for all four presets; cases
  that need a real model are marked `modes: [live]` (run later with `dev.py test-live`, 3 runs, 2-of-3).
- **Strictness matrix green in deterministic mode**; per-layer attribution visible in `decided_phase` and the trace.
- Mutation coverage (session C's runner): disabling any semantic control fails at least one test.
- `dev.py test` + `lint` green.

## Checkpoint (CP-semantic) — stop and report

PR `feat/semantic` with: what was built, test counts, contract changes, licences of every model, and the **integrator
checklist for the live run** (requires the WCSS model link): fetch models, `dev.py test-live`, calibration report (κ,
FPR/FNR), judge latency p50/p95 (escalation-only budget), shadow-judge miss-rate sample, any threshold tuning needed.
