# 3c. Screen specs — Govern

*Views 10, 8, 9, 13, 12. Shared entities and states: [03-screen-specs.md](03-screen-specs.md).*

All configuration in these views is either **policy (YAML, versioned)** or **assignment (DB grant)** — §11.0. Every write control says which one it produces, so nobody is surprised that "kill switch" or "raise limit" creates a new policy version.

| Control in the UI | Writes | Goes through |
|---|---|---|
| Policies forms / YAML | `policy/*.yaml` new version | Draft → validate → impact → (approve) → publish |
| Connector kill switch | `models.yaml › connectors.<id>.enabled` | Fast path: confirm + reason → publish (impact shown, not blocking) |
| Model registry edit | `models.yaml` | Draft flow |
| Budget limit change | `budgets.yaml` | Draft flow (short form) |
| Per-user budget share, group-admin split | DB `budget_share` grant | Grant flow |
| Tool quarantine / re-approve hash | MCP pin store (DB state, audited) + incident | Dedicated dialog |
| Feed rule (demo) | Demo feed server bundle | Feed form → gateway sync |
| Publish skill | `groups.yaml` grant + skill definition (policy) | Draft flow (pre-filled) |

---

## 10. Policies — `/policies`

**Purpose.** The single place to read, change, verify and roll back the rules — safely, with the security cost of every change visible before it goes live — while hand edits to the files stay first-class.
**Primary users.** Policy admin, judge; analyst (read).
**Entry points.** Sidebar, `g p`, every rule chip ("Open policy line"), version badges, external-edit notifications, Overview posture deductions.

**Layout.**

```
┌ Policies   live v8 · loaded 14:02:11 · source panel (m.zielinska) · reload 0.8 s   [GitOps: off]  [History] [Org locks] ┐
│ ⚠ banner area (disk invalid / conflict / GitOps PR open)                                                                │
├ FILES ────────────┬ EDITOR  controls.yaml   [ Form | YAML ]   draft from v8 · 2 changes ───────┬ CHECKS ────────────────┤
│ controls.yaml  •2 │                                                                            │ ✓ Schema valid         │
│ models.yaml       │  Form: sections → fields (each shows its YAML path + line)                  │ ✓ No org-lock conflict │
│ groups.yaml       │  YAML: Monaco, schema-aware, locked ranges, rule anchors                    │ Impact (dry-run)       │
│ budgets.yaml      │                                                                            │  3 / 500 change ▸      │
│ routing.yaml      │                                                                            │ Suite 142 / 144 ▸      │
│ ── drafts (1)     │                                                                            │ ( Review & publish )   │
└───────────────────┴────────────────────────────────────────────────────────────────────────────┴────────────────────────┘
```

### Form mode (must for common edits)

| Form | Fields | Pri |
|---|---|---|
| Presets | Per preset: `injection_threshold`, `judge_band`, `pii_action`, `secret_action`; per group: preset selector. Sliders show the current live value as a tick and the suite FPR/ASR at that value if measured | M |
| Controls | Table: rule ID, type, stages, action, mode (`enforce` / `monitor`), enabled toggle; org-locked rows (e.g. `SEC-SECRET-01` per LOCK-02) show a lock and are disabled with the reason | M |
| Models & connectors | Registry rows (see view 8) | S |
| Group grants | Group → models / skills / tools / MCP checklist, `max_external_data_class` | M |
| Budgets | Org / group / agent limits, soft %, breaker cooldown | M |
| Routing | Sensitivity → action table, complexity bands, budget-scaled escalation, on-exhausted behaviour | S |

Forms produce minimal YAML patches applied by the gateway's single writer (round-trip, comments preserved). Every field has a `↗ YAML` link that switches to YAML mode with the line selected; YAML edits update the form live when they parse.

### YAML mode (must)

- Monaco + `monaco-yaml` with the same JSON Schema the gateway uses: autocomplete for keys and enums (`balanced`, `route_local`, data classes), hover docs from schema descriptions, inline errors.
- **Rule anchors:** `?rule=SEC-PII-01` scrolls to and highlights the entry; `?line=` selects a line; gutter shows hit counts (24 h) next to each control entry *(S)*.
- **Org-locked ranges:** decorated (lock glyph, tinted background), read-only in the panel; tooltip "Org lock LOCK-02 — change via file review / GitOps only".
- **Version context:** when opened from an old trace, read-only on that version with "Open in live vN" bar.

### Version history (must)

List: version, time, author (user or `filesystem` or `gitops`), **source** badge (`panel` / `file` = external edit / `rollback` / `gitops`), files, diff stat, note. Select two versions → Monaco diff (side-by-side or inline). Actions: `Rollback to this version` (creates a new version whose content equals the selected one; never rewrites history; runs the same impact preview). Each version links to "first decision with this version" in Live traffic.

### Publish flow

1. **Review & publish** → validate (server) → **impact preview** (dry-run replay of the last N stored decisions, default 500 / 6 h, adjustable) + **deterministic test suite** against the draft *(S)*.
2. Impact panel (flow F2 step 5): transitions table (from → to, count, by group, by rule), sample traces with before/after badges, **approximate** marker for controls whose replay needs raw content ([README C6](README.md#conflicts-with-conceptmd)), suite deltas (ASR, FPR with CI; newly failing / passing cases), a plain-language headline ("would have blocked 14 of the last 500, mostly credit-analysts").
3. Note (required when the change loosens a control — any `block → allow` transition or ASR increase).
4. **Second approver** *(S3, setting)*: draft → `awaiting approval`; other policy admins see it in Drafts and in the bell; approver sees the same impact panel; author cannot approve.
5. **GitOps mode** (indicator in header; when on, the publish button reads `Open pull request`): creates a PR with the diff and the impact report in the description; the draft shows the PR link and status; the version goes live only after merge (the panel then receives `policy.version_loaded` with source `gitops`).
6. Success: toast "v9 live · reloaded in 0.8 s" + link "watch next decisions on v9".

### Invalid YAML

| Case | Behaviour |
|---|---|
| Invalid in the panel editor | Inline Monaco markers + error list in CHECKS (file, line, col, YAML path, message); Publish disabled; form fields for the broken section show "fix in YAML" |
| Server rejects on publish (schema passed, semantic check failed, e.g. unknown model in a group) | Dialog lists errors with jump links; draft kept |
| File on disk invalid (judge edit) | Sticky banner on Policies + Overview + status bar `⚠ disk invalid · last good v8`; "Show disk file with error" opens the disk content read-only with markers; "Load disk version into a draft" lets the admin fix it in the panel and publish a valid version (flow F3 step 5) |

### Conflict (optimistic lock)

Triggered live (SSE `policy.version_loaded` while a draft based on an older version is open) or on publish (HTTP 409).

```
┌ ⚠ controls.yaml changed while you were editing ───────────────────────────────────────────────────────┐
│ Your draft is based on v8. Live is now v9 (external edit · filesystem · 14:05:12).                     │
│ Their change: −1 control (SEC-EXFIL-01).   Your change: presets.balanced.injection_threshold 0.88.    │
│ The changes do not overlap.                                                                             │
│ [ View 3-way diff ]   ( Rebase my draft onto v9 )   [ Discard my draft ]                               │
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```
Overlapping changes: rebase is replaced by a 3-way merge editor (base v8 / theirs v9 / mine) with per-hunk choice; publishing is blocked until resolved. The panel never overwrites a newer version.

### Org locks — `/policies/locks`

Read-only list of `org_locks` (ID, rule text, file + line, what it overrides), "where it applied in the last 24 h" counts, and the controls it protects from panel edits. Pri M (judges ask "can I turn off secrets?" — the answer is visible here).

**Elements summary.** File list M · Form mode M · YAML mode M · validation M · version history + diff M · dry-run impact M · conflict handling M · invalid-file banner M · org locks M · rollback M · GitOps indicator + PR state S · second approver S · test suite against draft S · hit-count gutter C.

**States.** No drafts; draft autosaved (server-side) every 5 s with "saved" indicator; gateway unreachable → read-only ("publishing needs the gateway's policy service"); GitOps PR pending → banner with PR link and status.

**Permissions.** Policy admin, judge: W. Analyst: R (history, diff, locks). Group admin: R of their group's block.

**Data.** `GET /policy/status` → `PolicyStatus` · `GET /policy/schema` (JSON Schema) · `GET /policy/files/:file?version=` → `{ content, version, lockedRanges: { startLine, endLine, lockId }[], ruleAnchors: { ruleId, line }[] }` · `GET /policy/versions` → `PolicyVersion[]` · `GET /policy/versions/:v/diff?against=` · drafts: `POST /policy/drafts {baseVersion, file}`, `PUT /policy/drafts/:id` (If-Match), `POST …/validate` → `ValidationError[]`, `POST …/impact {window, n, runSuite}` → `ImpactReport`, `POST …/publish` → `{ version } | 409 { liveVersion, theirDiff }`, `POST …/approve`, `POST /policy/rollback`. SSE `policy`.

---

## 8. Models & connectors — `/models`

**Purpose.** See and control where AI traffic can go: upstream connectors, the model registry, and who can use what.
**Primary users.** Policy admin; analyst (kill switch); viewer (spend/health summary).
**Entry points.** Sidebar, model IDs anywhere, Overview cost column, routing lines in traces.

**Tabs:** `Connectors` · `Registry` · `Access matrix`.

### Connectors

Rows (or compact cards, max 1 row each): name, type (`ollama` / `gemini` / `openai_compatible`), tier (local / cloud), host, health (icon + label), p50 / p95 latency (sparkline 1 h), error rate, requests and spend today, credential `present / missing` (never the value), **kill switch**.

Kill switch dialog: "Disable *gemini*? Cloud aliases (`smart`) fall back to local models and responses are marked **degraded**. This writes policy v9 (`connectors.gemini.enabled: false`)." Reason required; shows the number of users whose `/v1/models` changes. Re-enable is the same flow. Pri M.

### Registry

Table: model ID, aliases, connector, tier, prices (in / out per 1k, USD per GPU-second), allowed data classes (chips), capability tags (`task: loan_memo`, `lang: pl`), specialist flag + `min_confidence`, artifact scan status (passed / blocked / pending, with sha256 prefix → Feed › Artifacts), routed share of `auto` 24 h, requests 24 h, available to (groups / users count). Row detail: routing reasons distribution ("selected by auto because…" top 5), latency and cost per request, recent traces. Edit → Policies form (models.yaml).

### Access matrix

Rows: groups (expandable to users with overrides), columns: models / aliases / connectors. Cell: `✓` with source icon (group / user grant / elevation), `✕` with reason (lock / not granted), `⏱` temporary. Click a cell → resolution chain popover with links. Answers "who can use Gemini?" in one glance. Pri M.

**Elements.** Connectors with health + kill switch M · registry M · access matrix M · routing-share column S · per-model reasons distribution S · cost comparison chart (local GPU-s vs cloud USD) C.

**States.** Connector down: row in alerting style + "requests falling back to local (degraded): 12 in 5 min"; no Gemini key: credential `missing`, connector shown disabled with "offline mode — cloud aliases fall back to local" (§7.2). Artifact scan pending: model cannot be routed to (shown with the reason).

**Permissions.** Policy admin, judge W · analyst R + kill switch · group admin R (models available to their group) · viewer Σ (spend and health only).

**Data.** `GET /connectors` → `Connector[]` (+ 1 h series) · `POST /connectors/:id/enabled {enabled, reason}` → `{ version }` · `GET /models` → `Model[]` · `GET /models/:id/routing-reasons` · `GET /access-matrix` → `{ rows: { principalId, kind, cells: Record<objectId, EffectiveItem> }[] }`. SSE `inventory`, `policy`.

---

## 9. Tools & MCP inventory — `/tools`

**Purpose.** Know every tool an agent can reach, its tier and labels, whether its definition is still the one that was approved, and who can use it.
**Primary users.** Policy admin, analyst, judge.
**Entry points.** Sidebar, tool names in traffic / approvals / incidents, drift notifications.

**Layout.** Header counters: servers approved · quarantined · unlisted (shadow) · drift alerts open. Tabs: `Servers` · `Tools` · `OpenCode built-ins`.

| Element | Content | Pri |
|---|---|---|
| Servers | Name, transport + origin (bound at `initialize`), status (approved / quarantined / pending / **unlisted** = seen but not on allowlist), manifest hash (pinned), pinned at / by, tools count, sandbox egress allowlist, last drift, `sampling/createMessage` (denied by default) | M |
| Tools | Tool, server, tier (`deny` / `must` / `allow` / `confirm`), labels (`reads_untrusted`, `touches_sensitive`, `external_egress`, `irreversible`), capabilities (`network`, `filesystem`, `env`, `exec`), description hash (pinned), schema pinned (unknown fields rejected ✓), status, granted to (groups / users), calls / blocks 24 h | M |
| OpenCode built-ins | `read`, `write`, `edit`, `bash`, `webfetch` as a pseudo-server "local tools via `/v1/decide`", with per-group grants, managed-config state (`webfetch: deny`) and path / command rules | M |
| Drift alerts | Banner + filter: tools whose description / schema hash changed; link to incident (rug pull) | M |
| Name-collision / shadowing alerts | Same tool name on two servers, look-alike names | S |
| Tool detail | Current description and schema, **hash history** (each pin with approver and incident), diff between any two pins, grants, recent calls | M |
| Scan report | Description scanner findings for pending servers (before approval) | S |

**Actions.** Quarantine tool / server (analyst +) — immediate removal from every personalised `tools/list`; re-approve and pin new hash (policy admin, dialog of flow F7); approve pending server (policy admin; shows scan findings and requires reason); remove server; open grants.

**States.** Server unreachable (health) vs quarantined (policy) shown distinctly. Unlisted server seen in traffic → appears in an "Unlisted" section with "Approve…" / "Block" actions and an incident.

**Permissions.** Policy admin, judge W · analyst R + quarantine · group admin R scoped.

**Data.** `GET /mcp/servers` → `McpServer[]` · `GET /tools?server&tier&label&status` → `Tool[]` · `GET /tools/:id` (with `descriptionCurrent`, `schemaCurrent`, `hashHistory`, `diff?from&to`) · `POST /tools/:id/quarantine {reason}` · `POST /tools/:id/approve-hash {hash, reason}` · `POST /mcp/servers/:id/approve {manifestHash, reason}`. SSE `inventory`.

---

## 13. Signature feed & artifacts — `/feed`

**Purpose.** Show that historical attacks are covered by an external, signed, hot-swapped feed, let a judge add a rule live, and show model-artifact scan results.
**Primary users.** Policy admin, judge; analyst (read).
**Entry points.** Sidebar, status-bar feed badge, `FEED-…` rule chips, registry scan status.

**Tabs:** `Feed` · `Rules` · `Artifacts`.

### Feed

Header: bundle version, source URL, signature / checksum verification (✓ / ✗), last sync (age), poll interval, last failure (if any: "rejected f-…6: checksum mismatch — kept last good f-…5"), `Sync now` *(S)*. Rules by type (bar: `regex`, `yara`, `package_version`, `url_path`, `tool_desc_hash`, `manifest_hash`, `opcode`, `arg_pattern`, `ioc_domain`). Bundle history (version, time, +/− rules). Pri M.

### Rules

Table: ID, type, pattern preview (truncated; secrets-like patterns masked), severity, action, ATLAS technique, OWASP tag, CVE, source, expires, **hits 24 h** (live counter), last hit (→ trace). Search by CVE / ATLAS / package. `+ Add rule (demo feed server)` → form of flow F11, explicitly labelled as writing to the external-feed stand-in. Pri M.

### Artifacts

Table: artifact, format (safetensors / GGUF / pickle / keras / 7z…), sha256, origin (HF repo @ revision SHA, upload), verdict (allowed / blocked, icon + label), findings (e.g. `GLOBAL os.system via REDUCE`, `archive format mismatch: 7z where ZIP expected → treated as malicious`, `broken pickle stream → malicious`, `Keras Lambda layer`, `GGUF header OK`), scanned at, registered model. Row detail: opcode listing excerpt / header dump. `Scan file…` upload *(S)* to demo scenario 8. Pri M.

**States.** Feed never synced: "Waiting for first bundle from http://feed:8080 …"; verification failed: alerting banner + incident; no artifacts scanned: "Upload a model file or register a model to see scan results."

**Permissions.** Policy admin, judge W · analyst R.

**Data.** `GET /feed` → `FeedBundle` + `history` · `GET /feed/rules?type&q` → `FeedRule[]` · `POST /feed/sync` · demo feed server `POST /rules` (`FeedRule` without stats) · `GET /artifacts/scans` → `ArtifactScan[]` · `POST /scan/model` (multipart). SSE `feed` (`feed.rule_hit` increments counters).

---

## 12. Budgets & spend — `/budgets`

**Purpose.** Live view of consumption against limits across the hierarchy, why spend moved, breaker control, and the savings story.
**Primary users.** Policy admin, analyst, management viewer, group admin (own group), judge.
**Entry points.** Sidebar, Overview cost column, breaker notifications, incidents (budget breach), User 360 budgets row.

**Layout.**

```
┌ Budgets & spend   period: today ▾ (today · month)   meter: USD ▾ (tokens · USD · GPU-s)   [Savings] ┐
├ HIERARCHY TREE (left 60%) ───────────────────────────────┬ SELECTED NODE (right 40%) ───────────────┤
│ scope · used / limit bar · forecast · breaker · guard    │ series chart with spike annotations       │
│ org → groups → users / agents → sessions                 │ cause panel (rule, top traces)            │
│                                                          │ breaker state machine + actions           │
├ TOP CONSUMERS (users, agents, models, skills) ───────────┴ SAVINGS & GUARD SPEND ────────────────────┤
└──────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Element | Content | Pri |
|---|---|---|
| Hierarchy tree | org → group → user → agent → session; per node: used / limit meter (bar + numbers + %), soft-alert marker at 80%, forecast end of period, breaker state (closed / open / half-open with cooldown countdown; icon + label), source of the limit (YAML line or grant) | M |
| Meter switch | Tokens (in / out separate), USD, GPU-seconds; requests and tool calls in node detail | M |
| Node series | Spend over time with spike detection; annotations for policy versions and breaker transitions | M |
| Cause panel | For spikes / breaches: triggering rule (`repeat_call`, tokens-per-step growth, rate limit, confounder-gadget escalation anomaly), top traces | M |
| Breaker actions | Reset (reason) · raise limit (→ budgets.yaml draft) · keep open; history of transitions | M |
| Top consumers | Users, agents, models, skills — sortable, with share of total | S |
| Savings | vs always-cloud baseline (same tokens priced at the reference cloud model) and GPU-s saved by specialists vs the general model; "how computed" explainer; trend | S |
| Guard spend | Judge + classifier tokens / GPU-s / USD as a separate line, % of total, per-request `guard_budget` hits | S |
| Burn forecast | Linear + recent-rate forecast to end of month with the date the org limit would be hit | S |

**States.** No limits configured for a node: meter shows usage only, "no limit (inherits org)". Breaker open: node pinned to top. Management lens: no session level (aggregated to user / agent), no traces.

**Permissions.** Policy admin, judge W (limits) · analyst R + reset breaker · group admin W within group (split) · viewer R · employee own (in `/me`).

**Data.** `GET /budgets/tree?period&meter&depth` → `BudgetNode[]` (tree) · `GET /budgets/:scope/:id/series?range&meter` → `{ ts, value }[]` + `annotations: { ts, kind, ref }[]` · `GET /budgets/:scope/:id/cause` → `{ ruleId, detail, traceIds }` · `POST /budgets/:scope/:id/breaker/reset {reason}` · `GET /savings?period` → `{ vsAlwaysCloud: { usd, pct, method }, specialistGpuSSaved, series }` · `GET /budgets/top?by=principal|model|skill`. SSE `budgets` (5 s ticks, breaker transitions).
