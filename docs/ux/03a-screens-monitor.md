# 3a. Screen specs — Monitor

*Views 1–5. Shared entities, endpoints and standard states: [03-screen-specs.md](03-screen-specs.md).*

---

## 1. Overview / posture — `/`

**Purpose.** Answer in 5 seconds: *Are we safe? What is happening right now? What is it costing?* Then send the user one click away to the evidence.
**Primary users.** Security analyst, policy admin, management viewer (management lens), judge.
**Entry points.** Default landing; logo click; `g o`.

**Layout (1440 px).**

```
┌ status strip: Gateway ● OK · policy v8 ⟳ 14:02 (panel) · feed f-…4 · chain ✓ 14:00 · break-glass today 0 · fail-open 0 ┐
├ ARE WE SAFE? ──────────────────┬ WHAT IS HAPPENING? ──────────────────────┬ WHAT IS IT COSTING? ──────────────────────┤
│ Posture 82/100 ▼2 (v8)         │ Last 15 min · 1 284 decisions            │ Today 3.12 / 5.00 USD (org daily share)   │
│  ▸ what lowers it (3)          │ ▆▆▇█▇▆ stacked by decision (icon legend) │ forecast 4.40 by 24:00 ▏ ok               │
│ Incidents  ● 1 high  ● 2 med   │ allow 1 102 · pseudonymise 71 · route_   │ GPU-s 1 912 / 3 600 · breakers ◉ 1 open   │
│  oldest open 0:38 · mine 1     │ local 64 · approval 3 · block 44         │ savings vs always-cloud 61%               │
│ Top risks (OWASP, 24 h)        │ Notable now ───────────────────────────  │ guard spend 0.21 USD · 7% of total        │
│  LLM01 prompt injection   41   │ 14:03 Anna · PESEL → pseudonymise+local  │ external routing rate 18%                 │
│  LLM02 sensitive info     128  │ 14:02 Jan  · git push → approval         │                                           │
│  ASI02 tool misuse        9    │ 14:01 research-bot · loop → breaker      │                                           │
│  MCP — tool poisoning     1    │ [Open live traffic →]                    │ [Open budgets →]                          │
├ NEEDS A HUMAN ─────────────────┴──────────────────────────────────────────┴───────────────────────────────────────────┤
│ Approvals 1 pending (oldest 0:20, auto-deny 9:40) · Policy: external edit v8 14:02 [diff] · Grants expiring 24 h: 1  │
├ HONEST NUMBERS ───────────────────────────────────────────────────────────────────────────────────────────────────────┤
│ Block rate 3.4%  next to  FPR/call 3.1% [1.8–5.2] · FPR/task 6.0% · est. miss rate (shadow judge) 1.2% [0.4–3.1]    │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Elements.**

| Element | Content | Pri |
|---|---|---|
| Status strip | Gateway health, live policy version + source + reload time, feed version + sync age, chain verification, break-glass count today (→ list), fail-open count (→ filtered traffic) | M |
| Posture score | 0–100, delta vs 24 h ago, policy version it was computed on; **"what lowers it"** expander lists controls in `monitor` mode, disabled or removed, each with its point cost and link to the policy line. Never shown without the expander | M |
| Incidents tile | Open counts by severity (icon + label + count), oldest open age, assigned to me | M |
| Top risks | Top 5 categories across OWASP LLM / ASI / MCP Top 10 (24 h), count + sparkline; click → Live traffic filtered by tag | M |
| Decisions strip | Last 15 min stacked bar by decision (live, 10 s buckets); totals per decision; click a segment → filtered traffic | M |
| Notable now | Last 5 non-`allow` events in one plain-language line each (same template as the trace summary); click → trace drawer | M |
| Spend vs budget | Today USD vs limit, forecast to end of period, GPU-s vs limit, breakers open (icon + label) | M |
| Savings | % and USD vs always-cloud baseline, with "how computed" tooltip; GPU-s saved by specialists | S |
| Guard spend line | Judge + classifier cost as its own number and % of total (§8) | S |
| External routing rate | % of requests sent to cloud connectors, trend | S |
| Needs a human | Pending approvals, policy alerts (external edit / disk invalid / GitOps PR waiting), grants expiring in 24 h | M |
| Honest numbers | Block rate shown **beside** FPR per call/task and the shadow judge's estimated miss rate, with CIs, from the last suite run + live shadow sample | M |
| Demo checklist *(S1)* | Judge persona only: 10 scenario cards ("Paste a PESEL in LibreChat", "Delete a control in `controls.yaml`") that tick automatically when a matching event is observed, each linking to the resulting trace | C |
| Spend by team/model | Small table (management lens) | S |

**Actions.** All tiles navigate; no editing on Overview. Range selector (15 m / 1 h / 24 h / 7 d) applies to the "happening" and "risks" columns; posture and spend show their own period labels.

**States.** Empty (fresh install): "No traffic yet — send a prompt through LibreChat or OpenCode; it will appear here within seconds." Gateway unreachable: tiles show last stored values greyed with "as of hh:mm". Policy disk invalid: amber banner pinned above the columns (see F3).
**Management lens.** Hides "Notable now" (individual events) and the break-glass details (shows only the count and a link to the aggregated log); adds spend by team/model and adoption (active users, skill runs).
**Mobile (< 768 px).** One column: status strip → needs a human (approvals first) → safe → happening (strip only) → cost.

**Permissions.** R: policy admin, analyst, viewer (lens), judge; group admin gets the same layout scoped to the group ("Team overview"); employee redirected to `/me`.

**Data.** `GET /overview?range=` → `{ posture: { score, delta, version, deductions: { ruleId, points, reason, location }[] }, incidents: { bySeverity, oldestOpenAt, mine }, topRisks: { tag, framework, count, series }[], decisions: { bucketTs, counts: Record<Action, n> }[], notable: DecisionEvent[5], spend: { usd, usdLimit, forecast, gpuS, gpuSLimit, breakersOpen }, savings: { pct, usd, gpuSSavedBySpecialists }, guardSpend, externalRoutingRate, approvals: { pending, oldestAt }, policyAlerts, grantsExpiring24h, honest: { blockRate, fprCall: Metric, fprTask: Metric, estMissRate: Metric } }`. SSE: `decisions`, `incidents`, `approvals`, `policy`, `budgets`, `audit`.

---

## 2. Live traffic — `/traffic`

**Purpose.** Watch every inspected hop as it happens; filter to the interesting ones in two clicks; open any trace.
**Primary users.** Security analyst, judge.
**Entry points.** Sidebar, `g t`, any Overview number, rule popover "Hits in traffic", User 360 "see in traffic".

**Layout.** Filter bar (sticky) → stream table (virtualised) → trace drawer on the right (pushes the table, does not overlay it, at ≥ 1440 px).

```
┌ Live traffic  ● LIVE [❚❚ Pause]  range 15m ▾   Saved views: [Blocks] [PII] [Agents] [Approvals] [+ Save]  ┐
│ decision ▾  point ▾  group ▾  user/agent ▾  client ▾  model ▾  rule ▾  tag ▾  class ▾  taint ▾  {search} │
│ chips: decision=block,require_approval ✕   group=developers ✕          [Hide allow ☐]   1 284 matching │
│ TIME     WHO               CLIENT   POINT      MODEL / TOOL          DECISION            RULES        CLASS  TAINT  RISK  ms   TAGS │
│ 14:03:12 Anna Nowak  c-a   LibreCh. ingress    auto → bielik-11b     ⇄ pseudonymise ⌂ …  SEC-PII-01 +1 conf.  S      0.31  212  LLM02 │
│ 14:02:41 Jan Kowalski dev  OpenCode tool call  bash: git push        ? require_approval  SEC-FLOW-01  conf.  U S    0.78  9    ASI02 │
└──────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Elements.**

| Element | Content | Pri |
|---|---|---|
| Stream table | Columns: time, principal (name + group abbreviation; agent icon for agents; delegation indicator `↳` if on behalf of a user), client, inspection point, model requested → routed (or tool + server), decision badges (primary + secondary), rule chips (max 2 + "+n"), data class, taint after (`U` untrusted / `S` sensitive, icon + letter), risk score, overhead ms, tags. Degraded responses carry the `◐ degraded` marker | M |
| New-events pill | "↑ N new events" when scrolled, hovered or paused; click scrolls to top and merges. Counter caps at "999+" | M |
| Pause / resume | Button + `Space`; paused state shows "Paused at 14:03:12 · 37 new" | M |
| Filters | All in URL; multi-select chips; typing a rule ID / trace ID in search jumps straight to it | M |
| Hide allow | Quick toggle (most useful default for judges); remembered per user | M |
| Saved views | Named URLs; four seeded views (Blocks, PII, Agents, Approvals); personal + shared | S |
| Row expand (narrow screens) | Below 1280 px, low-priority columns (tags, taint, risk, ms) move into an expandable row detail | M |
| Group by session | Toggle that nests hops under their session (useful for agents and Rule-of-Two) | S |
| Export view | CSV / JSONL of the current filter (redacted) | C |

**Actions.** Click row → trace drawer (`?trace=`); `[` `]` step through traces in the filtered list; right-click / `⋯` → copy trace ID, open user, add to incident, create incident.

**States.** Empty for filter: "No events match. Remove `group=developers` or widen the range." Paused for > 5 min: gentle reminder "Still paused — 1 204 new events". Stream down: amber bar "Reconnecting…", table keeps rows. Gateway unreachable: table becomes historical (range picker only).
**Performance.** Virtualised rows, max 2 000 in memory; older rows fetched by cursor on scroll. Row insert animation ≤ 150 ms, disabled with reduced motion.

**Permissions.** Analyst, policy admin, judge: all. Group admin: own group only (server-scoped). Viewer and employee: no access.

**Data.** `GET /events?decision&point&group&principal&client&model&rule&tag&class&taint&range&q&cursor` → `{ items: DecisionEvent[], nextCursor, total }`. SSE `decisions` (server applies the same filter when the client passes it in the stream URL to save bandwidth). Saved views: `GET/POST /me/saved-views`.

---

## 3. Decision trace (hero) — drawer `?trace=:id` and page `/traces/:traceId`

**Purpose.** Explain one decision completely: readable by a non-expert in < 30 s, deep enough for an analyst, every element linked to its evidence.
**Primary users.** Analyst, judge; policy admin when tuning.
**Entry points.** Any row in Live traffic, User 360 activity, incident, approval, notable-now line, command palette (`tr_…`), trace ID in a client message.

**Layout — three layers of depth (progressive disclosure, one component):**

```
┌ LAYER 1 — the answer (always visible, ~5 lines) ──────────────────────────────────────────────────────────┐
│ Plain-language summary (deterministic template from fields; no LLM)                                       │
│ Outcome row: decision badges · data class · taint before → after · risk score + band · overhead · client │
│ Version row: policy v8 · grants g231 · feed f-…4 · chain ✓     (each a link; "new" tag if newer than     │
│              the previous trace the user looked at)                                                       │
├ LAYER 2 — the why (sections open by default for non-allow decisions) ─────────────────────────────────────┤
│ ▾ What changed in the content     redacted view with typed placeholders + legend                          │
│ ▾ Why this model                  ordered routing steps with rule chips                                    │
│ ▾ Risk factors                    5 bars, contributions summing to the score, cut-offs for the preset     │
│ ▾ Session                         hop rail: ingress → tool call → tool result → … with taint carried       │
├ LAYER 3 — the evidence (collapsed by default) ────────────────────────────────────────────────────────────┤
│ ▸ Pipeline                        stage rows → control rows (verdict, score vs threshold, ms, cached)      │
│ ▸ Versions & integrity            all versions incl. classifier/judge models, record hash, prev hash      │
│ ▸ Raw event (JSON)                the audit record as stored (redacted)                                    │
└───────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Stage rows (Pipeline).** Fixed order, always all rows, so the shape is learnable:

| # | Stage | Shows |
|---|---|---|
| 0 | Identity | principal, groups, auth method (Keycloak JWT / API key `acl_7f3a…`), delegation chain |
| 1 | Normalise | transformations applied (NFKC, zero-width stripped ×3, Base64 decoded and rescanned), malformed-call fail-closed |
| 2 | Deterministic | authz (model / tool grant check with source), budgets, rate/loop, PII T0 validators, secrets, signatures, egress rules, tool tier + arg schema, MCP pin, taint rule |
| 3 | Similarity | top kNN match from attack corpus, distance, threshold |
| 4 | Semantic L1 | NER (T1), injection classifier, Bielik Guard, sensitivity/complexity/task scores |
| 5 | Semantic L2 | which judge ran and **why** (uncertainty band 0.3–0.8 / high-risk action / strict preset / shadow sample), verdict, ms; or "skipped: score outside band" |
| 6 | Decide | risk score composition, preset cut-offs, fail mode applied, deterministic denial = final |
| 7 | Route | requested → resolved model (mirrors "Why this model") |
| 8 | Approval | only when held: approver, decision, elevation |
| 9 | Egress | response hygiene: logprobs/reasoning stripped, canary check, placeholder restore (which types, for whom), streaming hold-back |

Each stage row: status icon + label (`pass`, `hit`, `skipped`, `timeout`, `early exit`), latency bar on a shared scale, count of controls. Early exit greys subsequent stages with "not reached — deterministic block at stage 2". Each control row: rule chip, verdict badge, score vs threshold mini-bar with the threshold's YAML source, latency, `cached` tag, `fail-open` tag (alerting style) when applied.

**Elements.**

| Element | Pri |
|---|---|
| Plain-language summary (template per decision type; i18n-ready) | M |
| Outcome row with decision badges, data class, taint before → after, risk, overhead | M |
| Version row + chain status | M |
| Redacted content view with typed placeholders, entity legend, detector tier (T0/T1/T2) per entity, "restored on egress" marker | M |
| "Why this model" ordered steps (specialist check → sensitivity → grant ceiling / org lock → complexity band → budget state → result), each with rule chip | M |
| Pipeline stage rows + control rows | M |
| Risk-factor bars with contributions and preset cut-offs | M |
| Rule chip popover → `Open policy line` (exact file + line in the version that decided) | M |
| Session hop rail with taint propagation (which hop set which flag) | S |
| "Not evaluated" list (controls removed / disabled / not in this stage, with version) | S |
| Replay with live policy / with a draft (single-request dry-run; result shown as a diff of decisions) | S |
| Prev / next in list (`[` `]`) | S |
| Raw event JSON (redacted) with copy | S |
| Break-glass "Reveal raw" (if retained) | S |
| Side-by-side compare two traces (e.g. before/after a policy change) | C |

**Actions.** Copy trace ID · open principal · open rule line · replay (live / draft) · add to incident / create incident (pre-filled) · export evidence (JSON with record hash and chain proof) · reveal raw (break-glass).

**Policy-line navigation.** The rule popover's link opens `/policies/edit/:file?version=<deciding version>&line=<n>&rule=<id>`. If the deciding version is older than live, the editor opens read-only on that version with a bar: "This decision used v8. Live is v9. [Open the same rule in v9]". Locks open the read-only Org locks page; feed rules open the feed entry; `AUTHZ-*` open the grant; `BUDGET-*` open the budget node.

**States.** Trace not found (expired retention or wrong ID) with search box; trace still in flight (streaming response) → egress stage shows "in progress" and updates live; chain `pending` (not yet verified) vs `broken` (red, links to Audit › chain); scoped user (group admin / employee) sees the same layout with payload sections showing placeholders only and no raw/break-glass.

**Permissions.** Analyst, policy admin, judge: full. Group admin: own group, no break-glass. Employee: own traces in a simplified view (layers 1–2, no risk internals) from `/me`.

**Data.** `GET /traces/:id` → `Trace`. `GET /rules/:ruleId?version=` → `RuleRef`. `POST /traces/:id/replay` → `{ before: Action[], after: Action[], changedStages: StageResult[], version }`. `GET /sessions/:id` for the hop rail. SSE `decisions` for in-flight updates of this trace.

---

## 4. Incidents — `/incidents`, `/incidents/:id`

**Purpose.** Group events into things a human must handle; record the handling; export evidence.
**Primary users.** Analyst (owner), policy admin, judge. Viewer sees aggregates.
**Entry points.** Sidebar, bell, Overview tile, trace "create incident", approvals "create incident", budget breaker.

**List layout.** Table: severity (icon + label), ID, type, title, principal(s), status, assignee, first / last seen, linked traces count, age. Filters: status (default `open,triaged`), severity, type, assignee (`me`), principal. Bulk: assign, change status.

**Detail layout.**

```
┌ inc-0057 · <type label> · <severity> · <status ▾> · assignee <▾>                 [Export evidence ▾] ┐
├ SUMMARY (plain language, 1–2 lines) ────────────────────────────────────────────────────────────────────┤
├ TYPE-SPECIFIC EVIDENCE PANEL (see below) ───────────────────────────────────────────────────────────────┤
├ LINKED TRACES (mini stream table)                  ├ TIMELINE (system events + human actions + notes)  ┤
├ ACTIONS (type-specific + generic)                  ├ + Add note                                          ┤
└─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Type-specific evidence panels.**

| Type | Evidence panel | Type actions | Pri |
|---|---|---|---|
| MCP rug pull | Server, tool, pinned hash → new hash, **description diff** (inline, insertions highlighted), input-schema diff, scanner findings (imperative text, secret paths, hidden Unicode shown as visible tokens `⟨U+200B⟩`, Base64 blobs, cross-tool references), L2 judge verdict, exposure (sessions that listed the tool; calls since drift) | Keep quarantined & close · Re-approve & pin new hash (policy admin; reason + type hash prefix) · Remove server | M |
| Budget breach | Budget node path, meter, limit, breaker state machine (closed → open → half-open) with cooldown countdown, spike chart, cause rule (`repeat_call`, tokens-per-step growth, rate), top contributing traces | Reset breaker (reason) · Raise limit (→ budgets form, policy flow) · Keep open | M |
| Forbidden-model attempt | Principal, model requested, effective model list at that time, grant history (e.g. expired g-0412), client + device, HTTP 403 trace | Grant access (→ grant drawer) · Mark as expected · Revoke API key (if key-based) | M |
| Plugin bypass detected *(S5)* | Device ID, OpenCode session, evidence: tool results in the conversation with **no matching `/v1/decide` record**, or LLM requests missing plugin headers; first/last seen | Revoke device token / API key · Notify owner (copy template) | S |
| Break-glass access | Actor, subject, records, reason, linked incident, duration; posture link | Acknowledge (viewer/admin) · Flag as inappropriate (opens a new high-severity incident) | M |
| Rule of Two / exfiltration | The three taint sources (as in Approvals), sink, decision | Revoke tool for user · Tighten preset (→ policy) | S |
| Policy file invalid | File, errors with line/col, last good version, time invalid | Open disk file · Open last good | S |
| Artifact blocked | Artifact, format, findings (opcode list, archive mismatch, Keras Lambda) | Keep blocked · Request exception (policy admin) | S |

**Elements.**

| Element | Pri |
|---|---|
| List with severity/status/assignee filters in URL | M |
| Detail header with status & assignee controls | M |
| Type-specific evidence panel (above) | M |
| Timeline (system + human, chronological, immutable; notes are append-only) | M |
| Linked traces mini-table (opens trace drawer) | M |
| Export evidence: JSONL bundle (incident + traces + audit records + chain proof: first/last hash and verification result), also OCSF | M |
| Merge incidents / link related | C |
| SLA / age indicators | C |

**States.** Empty list: "No open incidents. Incidents are raised by: MCP drift, breaker trips, forbidden models, break-glass access, … (each links to how to trigger it in the demo)". Closed incident: read-only, reopen action.

**Permissions.** Analyst + judge: W. Policy admin: R + notes + type actions that require admin (re-approve hash, raise limit). Group admin: R for incidents involving members. Viewer: Σ only (counts by type/severity, MTTR) on Overview and Reports.

**Data.** `GET /incidents?status&severity&type&assignee&principal&cursor` → `{ items: Incident[] }` (list projection without evidence). `GET /incidents/:id` → `Incident` with `evidence` per type, e.g. `mcp_rug_pull: { serverId, toolId, pinnedHash, newHash, descriptionBefore, descriptionAfter, schemaBefore, schemaAfter, findings: { code, span, detail }[], judge?: { verdict, score }, exposure: { sessions, callsSinceDrift } }`, `budget_breach: { node: BudgetNode, series, causeRuleId, topTraceIds }`. `PATCH /incidents/:id {status, assignee, resolution}`, `POST /incidents/:id/notes`, `POST /incidents/:id/export {format}`. SSE `incidents`.

---

## 5. Approvals — `/approvals`, `/approvals/:id` (+ employee side in `/me`)

**Purpose.** Let a human decide held actions quickly and safely, with everything needed on one screen.
**Primary users.** Analyst (security approvals), group admin (team approvals), policy admin, judge; employees see their own requests.
**Entry points.** Sidebar counter, bell, Overview "needs a human", mobile Overview card, link from the client's pending message (`apr-…`).

**Layout.** Split pane: queue (left, 360 px) + detail (right). Queue sorted by time-to-auto-deny ascending. Tabs: Pending (mine) · Pending (all I can see) · Decided (24 h).

**Detail sections (top to bottom, in reading order of the decision):**
1. **Who** — principal, group, client, device, delegation chain (`Jan → OpenCode agent`, or `research-bot (agent) on behalf of Anna`).
2. **What** — tool + arguments (redacted), **preview** by kind: command (with syntax highlight and target resolution, e.g. remote URL resolved and flagged `not *.corp`), diff (Monaco diff, secrets masked), email (recipients vs allowlist, body redacted), HTTP (method, host, path, query entropy flag).
3. **Why held** — the rule chip and its plain reason; for Rule of Two, the three numbered sources with timestamps and trace links; for tier `confirm`, the tool tier and label (`irreversible`); for risk score, the factor bars and the preset cut-off it crossed.
4. **Session** — hop rail of the session up to now.
5. **Decision bar** — `( Deny )` primary and default-focused · `[ Approve once ]` · `[ Approve with elevation ▾ ]` (5 / 15 / 60 min; scope: *this exact target* (default) / this tool); reason field (required for approve, optional for deny); auto-deny countdown.

**Elements.**

| Element | Pri |
|---|---|
| Queue with countdowns and approver role | M |
| Who / What / Why held / Decision bar | M |
| Command and diff previews | M |
| Approve with time-boxed elevation + scope | M |
| Session hop rail | S |
| Keyboard `a` / `d` / `e` with confirm dialog | S |
| Mobile layout: queue → full-screen detail with sticky decision bar | M |
| Bulk deny (e.g. runaway agent spamming requests) | C |

**Elevation visibility.** An approved elevation appears in the principal's User 360 › Effective access as `⏱ elevated` with countdown, scope and approval link; it reverts automatically and writes `grant_changes: expire`.

**Employee side — `/me` › Requests.** List of my pending / decided requests: what, why held (plain language), approver role ("security team" / "your team lead"), status, countdown; actions: cancel, open trace (simplified). Copy for outcomes matches the client messages ([3.2](03-screen-specs.md#approval-pending-and-outcome)).

**States.** Empty: "Nothing waiting. Approvals appear when a tool needs confirmation or a session would complete the Rule of Two." Approval expired while open: decision bar replaced by "Expired — auto-denied at 14:22". Already decided by someone else: live update "Denied by k.wojcik 5 s ago", bar disabled. Gateway unreachable: decisions disabled ("approvals are delivered by the gateway").

**Permissions.** Analyst, policy admin, judge: approvals with `approverRole=security` and any; group admin: `approverRole=group_admin` for their group; employee: own requests only (and user-level approvals are handled in the client).

**Data.** `GET /approvals?status&approverRole&cursor` → `Approval[]`; `GET /approvals/:id`; `POST /approvals/:id/decision { decision: 'approve'|'deny', reason, elevation?: { minutes, scope: 'target'|'tool' } }` → 409 if already decided. SSE `approvals`.
