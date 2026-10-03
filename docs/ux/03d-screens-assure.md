# 3d. Screen specs — Assure & optimise

*Views 14, 15, 16, 17. Shared entities and states: [03-screen-specs.md](03-screen-specs.md).*

---

## 14. Guard quality — `/quality`

**Purpose.** Prove how well the guards work **and what they cost in utility**, with the metrics the literature uses and honest uncertainty. This is where "no vanity metrics" is enforced.
**Primary users.** Policy admin, analyst, judge; management viewer (headline only).
**Entry points.** Sidebar, `g q`, Overview "honest numbers", rule popover suite metrics, policy impact panel.

**Header.** Run selector: run ID, mode (`deterministic` / `live Ollama 3× 2-of-3`), commit, policy version, started, duration, cases. `Compare with…` another run *(S)*. A permanent framing line under the title: *"Attack success rate is shown next to false positives and utility. Results on our own suite; adaptive attacks are reported separately and are not 100%."*

**Layout (top to bottom).**

```
┌ PER PRESET (the strictness trade-off) ───────────────────────────────────────────────────────────────────────┐
│            ASR             FPR / call       FPR / task       benign utility   utility under attack   p95 ms  │
│ monitor    61% [55–67]     0.0%             0.0%             97%              38%                    41      │
│ balanced   2.1% [0.9–4.8]  3.1% [1.8–5.2]   6.0% [3.7–9.6]   94%              91%                    118     │
│ strict     0.7% [0.2–2.6]  7.4% [5.2–10.4]  15% [11–20]      86%              85%                    260     │
│ paranoid   0.0% [0.0–1.3]  12% [9.4–15.6]   27% [22–33]      71%              71%                    690     │
├ PER CONTROL ──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ control      cases  ASR (CI)   FPR (CI)   defence success  wrongly withheld  caught-by-layer  mutation ✓      │
├ STRICTNESS MATRIX (cases × presets, expected vs actual) ─────┬ LEAK RATE PER CHANNEL ─────────────────────────┤
├ PER-LAYER ATTRIBUTION (which layer caught what) ─────────────┼ JUDGE CALIBRATION (κ, FPR/FNR) + SHADOW JUDGE ─┤
├ ADAPTIVE TIER (paraphrased / encoded / translated) ──────────┼ FINE-TUNED PL CLASSIFIER before / after ───────┤
└──────────────────────────────────────────────────────────────┴────────────────────────────────────────────────┘
```

| Element | Content | Pri |
|---|---|---|
| Per-preset table | ASR with Wilson CI, FPR per call and per task, benign utility, utility under attack, NRP = utility under attack × (1 − ASR), p95 latency. Never sorted by ASR alone; the best-ASR row is not highlighted | M |
| Per-control table | Cases (attack / benign pairs), ASR + CI, FPR + CI, defence success rate, wrongly-withheld (over-redaction) rate, recovery-after-block rate, which layer caught it, **mutation test**: "switching this control off made N tests fail" ✓ / ✗ | M |
| Strictness matrix | Grid of case families (18 control rows from §16) × 4 presets; each cell = expected decision vs actual (✓ match / ✕ mismatch with both decisions shown as badges). Click cell → case list → case detail with trace | M |
| Leak rate per channel | Output text, tool arguments, inter-agent / memory (stretch), embeddings; with CIs; oracle = canary values + attacker sink log (independent of the gateway) | S |
| Per-layer attribution | Stacked bar per attack family: deterministic / similarity / L1 / L2 / taint rule / none (missed) — LlamaFirewall-style ablation | S |
| Judge calibration | Per local judge: Cohen's κ vs hand labels, FPR / FNR, n | S |
| Shadow judge | Sample size, disagreement count, **estimated miss rate with CI** (live, from §6.6 sampling) | M |
| Adaptive tier | Paraphrase / encoding / translation variants: ASR per variant family, explicitly labelled as harder and non-zero | S |
| Fine-tuned PL classifier | Before / after (off-the-shelf vs ours): ASR, FPR, latency on Polish and English sets | C |
| Specialist evaluations | Link to Insights › Specialists (quality vs cost) | C |
| Run history | Trend of headline metrics per run with policy version markers | S |

**Copy rules.** Every metric shows `n`; CIs always shown when n < 1000; "0%" is never shown without its CI upper bound (`0.0% [0.0–1.3]`).

**States.** No run yet: "Run `make test` (deterministic, ~40 s) — results appear here automatically." Run in progress: progress bar by control. Live-mode run missing: the live columns show "not run" rather than deterministic numbers.

**Permissions.** Policy admin, analyst, judge R · viewer Σ (per-preset headline + shadow miss rate) · others none.

**Data.** `GET /quality/runs` → `{ runId, mode, commit, policyVersion, startedAt, headline }[]` · `GET /quality/runs/:id` → `TestRun` with `perPreset: { preset, asr: Metric, fprCall: Metric, fprTask: Metric, utility: Metric, utilityUnderAttack: Metric, nrp, p95Ms }[]`, `perControl: { ruleId, cases, asr, fpr, defenceSuccess, wronglyWithheld, recoveryAfterBlock, layer, mutation: { killed: boolean, failingTests: n } }[]`, `strictnessMatrix: { family, preset, expected: Action, actual: Action, caseIds }[]`, `leakByChannel`, `layerAttribution`, `judgeCalibration: { judge, kappa, fpr, fnr, n }[]`, `shadow: { sampleN, disagreements, estMissRate: Metric }`, `adaptive`. SSE `quality`.

---

## 15. Performance — `/performance`

**Purpose.** Show that security is cheap where it should be: overhead per stage and control, cache effect, how often the expensive judge runs, and when anything failed open.
**Primary users.** Policy admin, analyst, judge.
**Entry points.** Sidebar, status-bar gateway health, trace latency bars.

| Element | Content | Pri |
|---|---|---|
| Overhead headline | Gateway overhead vs direct call to Ollama at p50 / p95 / p99 (from the latency report and live histograms) | M |
| Stage waterfall | p50 / p95 / p99 per stage (normalise → … → egress) as horizontal bars on one scale; share of requests that reached each stage (early exit visible) | M |
| Per-control table | Control, invocations, p50 / p95 / p99, timeouts, cache hit rate, fail mode | M |
| Cache | Verdict cache hit rate (content hash), response cache hit rate (scoped per user and data class) | S |
| Judge escalation rate | % of requests reaching L2, by reason (uncertainty band / high-risk action / preset / shadow sample), trend; judge queue depth | M |
| Fail-open count | Count with list of events (each a trace link) and the control that failed open; alerting style when > 0 | M |
| Throughput | Requests/s, streaming hold-back delay | C |
| Policy reload times | Last N reloads (ms) with versions | S |

**States.** Prometheus unreachable: "Metrics unavailable — traces still carry per-control latency" with link to traffic.

**Permissions.** Policy admin, analyst, judge R.

**Data.** `GET /metrics/performance?range` → `{ overhead: { p50, p95, p99, directBaseline }, stages: { stage, p50, p95, p99, reachedPct }[], controls: { ruleId, n, p50, p95, p99, timeouts, cacheHitRate, failMode }[], cache: { verdict, response }, judge: { escalationRate, byReason, queueDepth }, failOpen: { count, events: DecisionEvent[] }, reloads: { version, ms }[] }` (backed by Prometheus histograms + Postgres for event lists).

---

## 16. Automation Insights — `/insights`

**Purpose.** Turn repetitive AI usage into governed, cheaper skills (and optionally local specialist models), with privacy built in.
**Primary users.** Policy admin (publish), group admin (own group), management viewer (aggregated patterns), employee (personal suggestions), judge.
**Entry points.** Sidebar, Overview savings, `/me` insights.

**Privacy framing (always visible in the header).** "Mined from redacted prompts on local models. Patterns with fewer than **k = 5** distinct users are hidden (4 hidden). Individuals see only their own suggestions." The k value links to its policy line.

**Tabs:** `Patterns` · `Skills` · `Specialists`.

### Patterns (list + detail)

| Element | Content | Pri |
|---|---|---|
| Cluster list | Title (from task card), group, distinct users (≥ k), runs, frequency (daily ~08:30 / ~14×/day), estimated effort (min/day), tokens / GPU-s / USD per month, retries %, status (new / drafting / published / dismissed) | M |
| Task card | What the task is, typical inputs and outputs, recurrence chart, cost now (model, tokens, GPU-s, cloud share), retry rate | M |
| Redacted examples | 3 sample prompts (redacted, placeholders only) — policy admin only; hidden for viewers | S |
| Draft skill editor | Name `skill/<name>`, prompt template (Monaco, `{{variables}}` highlighted), input schema (form builder: field, type, required, enum), suggested model (default `auto`), preset (default stricter than the group's), tools (default none), controls (pre-filled: PII pseudonymise, route local, output format check) | M |
| Test the skill | Run the draft with a sample input through the gateway (trace link) | S |
| Publish | Choose groups → creates a policy draft (skill definition + group grant) → impact preview → publish; then "appears in clients on next model refresh" | M |
| Dismiss with reason | Removes from list, keeps in history | S |

### Skills

Published skills: ID, version, groups, model, preset, runs 30 d, avg cost vs pre-skill baseline, failure / block rate, last edited. Edit → new draft. Pri S.

### Specialists (train → register → route)

A stepper per specialist (flow F10 step 4): dataset (approved, redacted examples or synthetic; count; consent setting respected) → export for training (offline WCSS — the panel tracks status, it does not run training) → artifact upload → **artifact scan** (same scanner as Feed › Artifacts) → registration (ID, tags `task`, `lang`, `min_confidence`) → grant to groups → **evaluation** (specialist vs general local vs Gemini on held-out set: quality score by local judge, format pass %, p95 latency, GPU-s / USD per task, n) → **enable in auto**. After enabling: routed share and savings trend. Pri C for the train path, S for evaluation display.

### Management lens

Aggregated patterns only (no examples, no individuals, k enforced server-side): pattern, group, users band ("5–10"), estimated hours/month, potential savings, adoption of published skills.

### Employee view (in `/me`)

Personal suggestions if opted in: "You often summarise loan applications — `skill/loan-memo-summary` does this with a fixed form." Opt-in / out toggle with explanation.

**States.** Not enough data: "Insights need ≥ 7 days of traffic and ≥ k users per pattern." Miner not running: "Last mining run 3 days ago — worker offline." Insights disabled for a group by policy: shown as such.

**Permissions.** Policy admin, judge W · group admin R (own group, ≥ k) · analyst R · viewer Σ · employee own.

**Data.** `GET /insights/clusters?group&status` → `InsightCluster[]` (server applies k) · `GET /insights/clusters/:id` (+ `examples` for policy admin) · `POST /insights/clusters/:id/skill` (create / update draft skill) · `POST /skills/:id/test {input}` → `{ traceId }` · `POST /skills/:id/publish {groups}` → `{ draftId }` (policy flow) · `GET /skills` · `GET /specialists` · `GET /specialists/:id` → `{ steps: { step, status, at, detail }[], evaluation: { model, quality, formatPass, p95Ms, gpuSPerTask, usdPerTask, n }[], routedShare, savings }` · `PATCH /specialists/:id {enabledInAuto}`.

---

## 17. Audit & exports — `/audit`

**Purpose.** Prove integrity (hash chain), find any record, export evidence for SIEMs and auditors, and produce the management report.
**Primary users.** Analyst, policy admin, judge; management viewer (reports, break-glass log).
**Entry points.** Sidebar, status-bar chain badge, incident export, Overview break-glass count.

**Tabs:** `Search` · `Chain` · `Exports` · `Reports` · `Break-glass log`.

| Element | Content | Pri |
|---|---|---|
| Search | Query by trace ID, principal, rule, event type (decision, policy change, grant change, approval, break-glass, export), time range; results with record hash; open → trace or object | M |
| Chain verification | Status (✓ verified / ✗ broken), last verified, range (first … last record), records count, `Verify now` (range); on failure: first broken record, expected vs actual prev-hash, and an incident | M |
| Exports | Format JSONL / OCSF (Detection Finding, API Activity) / CSV; filters; time range; includes a manifest (filters, record count, first / last hash, verification result, policy versions in range); export history (who exported what — itself audited) | M |
| Reports | Monthly management report (flow F12): sections, preview, PDF / CSV / JSONL; schedule (monthly, recipients); history of generated reports | S |
| Break-glass log | Who looked at whose data: actor, subject, records, reason, incident, time, duration; filter by actor / subject; management sees this too | M |
| SIEM CEF line preview | Example CEF output for an event | C |

**States.** Chain broken: status bar ✗ and red banner on Audit with "Verification failed at record #48 211 — export includes the break point". Large export: async job with progress and download link (expires in 24 h).

**Permissions.** Analyst, policy admin, judge: R + export. Viewer: Reports + Break-glass log (Σ). Others none.

**Data.** `GET /audit?q&type&principal&rule&from&to&cursor` → `AuditRecord[]` · `GET /audit/chain` → `{ status, lastVerifiedAt, firstSeq, lastSeq, brokenAt? }` · `POST /audit/verify {from, to}` · `POST /exports {format, filters, from, to}` → `{ jobId }` · `GET /exports` · `GET /reports` · `POST /reports {period, sections, format}` · `POST /reports/schedules` · `GET /break-glass?actor&subject&range` → `BreakGlassEvent[]`. SSE `audit`.
