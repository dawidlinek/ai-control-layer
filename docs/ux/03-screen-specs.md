# 3. Screen specs

*Deliverable 3. One spec per view in the brief §4, plus the shared data contract and the copy for surfaces outside the panel (brief §8).*

| Part | Views |
|---|---|
| [3a — Monitor](03a-screens-monitor.md) | 1 Overview · 2 Live traffic · 3 Decision trace · 4 Incidents · 5 Approvals |
| [3b — Access](03b-screens-access.md) | 6 Users & groups + User 360 · 7 Agents · 11 Grants · 18 Employee home (+ group admin "My team") |
| [3c — Govern](03c-screens-govern.md) | 10 Policies · 8 Models & connectors · 9 Tools & MCP · 13 Signature feed & artifacts · 12 Budgets & spend |
| [3d — Assure & optimise](03d-screens-assure.md) | 14 Guard quality · 15 Performance · 16 Automation Insights · 17 Audit & exports |

Every spec uses the same headings: **Purpose · Primary users · Entry points · Layout · Elements (M/S/C) · Actions · States · Permissions · Data**.
Priorities: **M** must (demo-critical), **S** should, **C** could. Items marked *(Sx)* are suggestions beyond `CONCEPT.md`, listed in the [README](README.md#suggestions-beyond-conceptmd).

---

## 3.0 Shared conventions

### 3.0.1 Standard states (every view)

| State | Behaviour |
|---|---|
| Loading | Skeleton in the final layout (no spinners over empty pages); live widgets show "connecting…" in the status bar |
| Empty | Says what will appear and **how to make it appear** (e.g. "No blocks in the last 15 min. Try pasting a PESEL in LibreChat."); judges learn the product from empty states |
| Error | Plain message + request ID (copyable) + Retry; partial failures degrade per widget, never the whole page |
| No permission | "This view needs the *Security analyst* role. Ask a policy admin, or open Keycloak group `/panel/analysts`." No data is fetched |
| Gateway unreachable | Red banner (see [IA §1.5](01-information-architecture.md#15-global-ui-rules-apply-to-every-view)); history still readable from Postgres; all writes disabled with an explanation; status bar `● Gateway unreachable since hh:mm` |
| Stale stream | If SSE drops > 10 s: amber "Live stream reconnecting… data as of hh:mm:ss"; on resume, the missed events arrive through the "N new events" pill (resume with `Last-Event-ID`) |

### 3.0.2 Scoping is server-side

The panel never filters sensitive data client-side. The API and the SSE stream scope every response by role (group admins see their group, employees see themselves, viewers get aggregates with k-anonymity applied). The UI only hides navigation.

### 3.0.3 Redaction display rule

| Data | Default display |
|---|---|
| Payload text | Stored redacted / pseudonymised version with typed placeholders `<PERSON_1>`, `<PESEL_1>`, `<IBAN_1>`, `‹SECRET:api_key›` |
| PESEL | `***-**-**123` (last 3 digits) |
| IBAN | `PL** **** … 2874` (country + last 4) |
| NIP / REGON / ID card | type + last 3 (`NIP ***-***-**-45`) |
| Card number | `•••• 4242` |
| Person name in payloads | placeholder; on hover, initial + mask (`Jan W•••••••`) only for roles with payload access |
| Tool arguments | redacted + hashed (`args#e41c`) with a structured summary (`path=/data/**`, `url host=evil.tld`) |

---

## 3.1 Shared data contract

Admin API prefix `/admin/v1` (served by the gateway; the panel is a pure client). Live updates via **SSE** `GET /admin/v1/stream?topics=…` with `Last-Event-ID` resume. Field names below are the agreement between backend and frontend; per-view specs reference these entities and list only additions.

### 3.1.1 Core entities

```ts
// Identity
Principal        { id, kind: 'user'|'agent', displayName, email?, groups: string[], preset, keycloakId, ownerUserId? }

// One row in Live traffic = one inspection of one hop
DecisionEvent    { traceId, ts, sessionId, hopIndex, principal: Principal, delegationChain: Principal[],
                   client: 'opencode'|'librechat'|'agent'|'api', deviceId?,
                   point: 'ingress'|'egress'|'tool_call'|'tool_result'|'embeddings'|'a2a_memory'|'artifact_load',
                   modelRequested?, modelRouted?, connector?, tool?: { name, serverId|'builtin', tier },
                   decisions: Action[],            // primary first, e.g. ['pseudonymise','route_local']
                   ruleIds: string[], riskScore, dataClass, taintBefore: Taint[], taintAfter: Taint[],
                   overheadMs, totalMs?, tokens?: { in, out }, cost?: { usd, gpuS }, degraded: boolean,
                   tags: { owaspLlm: string[], owaspAsi: string[], owaspMcp: string[], atlas: string[] },
                   versions: { policy, grants, feed }, incidentId?, approvalId?, argsSummary? }
Action           = 'allow'|'monitor'|'redact'|'pseudonymise'|'sanitize'|'downgrade'|'route_local'|'require_approval'|'block'
Taint            = 'untrusted'|'sensitive'
DataClass        = 'public'|'internal'|'confidential'|'restricted'

// Decision trace = DecisionEvent + evidence
Trace            = DecisionEvent & {
  summary: string,                                  // deterministic template, not LLM-generated
  stages: StageResult[],
  risk: { score, preset, cutoffs: { sanitize, approval, block }, factors: RiskFactor[] },
  redactions: { placeholder, entityType, maskedPreview, detectorTier: 'T0'|'T1'|'T2', ruleId, restoredOnEgress: boolean }[],
  routing: { requested, resolved, task?: { category, confidence }, sensitivity, complexity, budgetState,
             steps: { order, check, outcome, ruleId?, detail }[] },
  versions: { policy, grants, feed, classifierModel, judgeModels: string[], gatewayBuild },
  integrity: { recordHash, prevHash, chainPosition, lastVerifiedAt, status: 'verified'|'pending'|'broken' },
  payload: { requestRedacted, responseRedacted }, rawAvailable: boolean,
  notEvaluated: { ruleId, reason }[],               // e.g. removed in this version, disabled, out of stage
  sessionHops: { hopIndex, traceId, point, decisions, taintAfter, ts }[]
}
StageResult      { stage: 'identity'|'normalise'|'deterministic'|'similarity'|'l1'|'l2'|'decide'|'route'|'approval'|'egress',
                   status: 'pass'|'hit'|'skipped'|'timeout'|'error'|'early_exit', latencyMs, controls: ControlVerdict[] }
ControlVerdict   { ruleId, controlType, verdict: Action|'pass', score?, threshold?,
                   thresholdSource?: { file, yamlPath, line, version }, latencyMs, cached: boolean,
                   failModeApplied?: 'closed'|'open_with_alert', detail }
RiskFactor       { factor: 'intent_deviation'|'tool_sensitivity'|'data_sensitivity'|'chain_anomaly'|'parameter_risk',
                   value, weight, contribution, sourceRuleId? }

// Rule resolution (powers every rule chip)
RuleRef          { ruleId, kind: 'control'|'org_lock'|'feed'|'builtin',
                   location: { file, yamlPath, line, version } | { feedBundle, entryId } | { grantId } | { budgetScope, budgetId },
                   summary, stages?, action?, hits24h, suiteMetrics?: { asr: Metric, fprCall: Metric },
                   lastChange?: { version, author, source, at } }
Metric           { value, ciLow?, ciHigh?, n?, method?: 'wilson' }
```

```ts
// Policy
PolicyStatus     { liveVersion, loadedAt, source: 'panel'|'file'|'rollback'|'gitops', reloadMs,
                   disk: { status: 'in_sync'|'invalid'|'pending', errors?: ValidationError[], firstSeenAt? },
                   gitopsMode: boolean, secondApproverRequired: boolean }
PolicyVersion    { version, parent, createdAt, author: { kind: 'user'|'filesystem'|'gitops', id? }, source,
                   files: string[], summary, diffStat: { added, removed }, note?, prUrl? }
PolicyDraft      { draftId, baseVersion, author, files: Record<path, string>, validation: ValidationError[],
                   impact?: ImpactReport, status: 'editing'|'awaiting_approval'|'published'|'conflict'|'discarded',
                   approvals: { by, at, decision }[] }
ValidationError  { file, line, column, yamlPath, message, schemaRef }
ImpactReport     { replayed: number, window, transitions: { from: Action, to: Action, count, byGroup, byRule }[],
                   sampleTraceIds: string[], approximate: { ruleId, reason }[],
                   suite?: { total, pass, newlyFailing: CaseRef[], newlyPassing: CaseRef[], before: SuiteHeadline, after: SuiteHeadline } }

// Access
Grant            { grantId, principalId, effect: 'allow'|'deny',
                   objectKind: 'connector'|'model'|'alias'|'skill'|'mcp_server'|'tool'|'budget_share'|'preset'|'elevation',
                   objectId, constraints: { dataClasses?, budgetShare?, preset?, scope? },
                   expiresAt?, reason, createdBy, createdAt, status: 'active'|'expiring'|'expired'|'revoked',
                   sourceApprovalId? }
GrantChange      { changeId, grantId, op: 'create'|'update'|'revoke'|'expire', actor, at, before?, after?, reason }
EffectiveItem    { objectKind, objectId, state: 'allowed'|'denied'|'elevated'|'expired'|'not_granted',
                   resolution: { layer: 'org_lock'|'group'|'user_grant'|'elevation'|'managed_config',
                                 ref: string /* yaml path+line | grantId | lockId */, effect }[],
                   constraints, expiresAt? }
ApiKey           { keyId, ownerId, prefix /* 'acl_7f3a' */, createdAt, lastUsedAt, expiresAt?, label }

// Response
Incident         { id, type: IncidentType, severity: 'critical'|'high'|'medium'|'low', status: 'open'|'triaged'|'resolved'|'closed',
                   resolution?, assignee?, principals: Principal[], firstSeen, lastSeen, traceIds: string[],
                   timeline: { at, kind, actor?, text }[], notes: { at, author, text }[], evidence: object /* per type */, tags }
IncidentType     = 'mcp_rug_pull'|'budget_breach'|'plugin_bypass'|'forbidden_model'|'break_glass'|'rule_of_two'
                 | 'injection'|'exfiltration'|'artifact_blocked'|'policy_invalid'|'feed_verification_failed'|'anomaly'
Approval         { id, status: 'pending'|'approved'|'denied'|'expired'|'cancelled', createdAt, expiresAt,
                   approverRole: 'user'|'group_admin'|'security', principal, delegationChain, client,
                   tool, argsRedacted, preview: { kind: 'command'|'diff'|'email'|'http', contentRedacted },
                   heldByRule, taintSources: { flag: Taint|'external', source, at, traceId, ruleId }[],
                   risk: Trace['risk'], sessionHops, decision?: { by, at, reason, elevation?: { minutes, scope } } }

// Spend
BudgetNode       { scope: 'org'|'group'|'user'|'agent'|'session', id, parentId?, period,
                   meters: { tokensIn, tokensOut, usd, gpuS, requests, toolCalls }, limits: Partial<meters>,
                   pct, forecastEndOfPeriod, softAlert: boolean,
                   breaker: { state: 'closed'|'open'|'half_open', openedAt?, cooldownEndsAt?, causeRuleId?, causeTraceIds? },
                   guardSpend: { tokens, gpuS, usd }, source: { file: 'budgets.yaml', yamlPath, line } | { grantId } }

// Inventory
Connector        { id, type: 'ollama'|'gemini'|'openai_compatible', tier: 'local'|'cloud', host, enabled,
                   health: 'ok'|'degraded'|'down', latencyP50, latencyP95, errorRate, spendToday, requestsToday,
                   credential: 'present'|'missing' /* never the value */ }
Model            { id, connector, aliases, tier, prices: { inPer1k?, outPer1k?, usdPerGpuSecond? }, dataClasses, tags,
                   specialist?: { minConfidence }, artifact?: { sha256, scanStatus: 'passed'|'blocked'|'pending', scannedAt, findings },
                   routedShare24h, requests24h, availableTo: { groups, users } }
McpServer        { id, transport, origin, status: 'approved'|'quarantined'|'pending'|'unlisted', manifestHash,
                   pinnedAt, approvedBy, sandboxEgress: string[], toolsCount, lastDriftAt? }
Tool             { id, serverId|'builtin', tier: 'deny'|'must'|'allow'|'confirm', labels, capabilities,
                   descriptionHash, schemaHash, quarantined: boolean, grantedTo, calls24h, blocks24h,
                   hashHistory: { hash, pinnedAt, by, incidentId? }[] }
FeedBundle       { version, sourceUrl, signature: 'verified'|'failed', syncedAt, pollS, rulesByType, lastFailure? }
FeedRule         { id, type, patternPreview, severity, action, atlas?, owasp?, cve?, source, expires?, hits24h, lastHitAt? }
ArtifactScan     { id, artifact, format, sha256, origin, verdict: 'allowed'|'blocked', findings: { code, detail }[], scannedAt, modelId? }

// Assurance & insights
TestRun          { runId, mode: 'deterministic'|'live', commit, startedAt, durationS, cases, perControl, perPreset,
                   strictnessMatrix, leakByChannel, layerAttribution, judgeCalibration, shadow, mutation }
InsightCluster   { id, group, distinctUsers, kThreshold, runs, window, frequency, effort: { minutesPerDay, tokens, gpuS, usd },
                   retriesPct, taskCard, draftSkill?, status: 'new'|'drafting'|'published'|'dismissed' }
Skill            { id, template, inputSchema, model, preset, tools, controls, groups, version, runs30d }
AuditRecord      { seq, ts, eventType, traceId?, actor, subject?, summary, recordHash, prevHash }
BreakGlassEvent  { id, actor, subjectPrincipalId, recordRefs, reason, incidentId?, at, durationS }
```

### 3.1.2 Endpoints (summary; per-view specs list which ones they use)

| Area | Endpoints |
|---|---|
| Session | `GET /me/session` (roles, scopes, feature flags such as `gitopsMode`, `breakGlassEnabled`) |
| Overview | `GET /overview?range=` (aggregates) |
| Events & traces | `GET /events?filters&cursor` · `GET /traces/:id` · `POST /traces/:id/replay {policy: 'live' or draftId}` · `GET /sessions/:id` · `GET /rules/:ruleId` |
| Incidents | `GET /incidents` · `GET/PATCH /incidents/:id` · `POST /incidents/:id/notes` · `POST /incidents/:id/export` |
| Approvals | `GET /approvals?status=` · `POST /approvals/:id/decision {decision, reason, elevation?}` |
| Users & agents | `GET /users` · `GET /users/:id` · `GET /users/:id/effective-access` · `GET /users/:id/models-preview` · `GET /users/:id/activity` · `GET /users/:id/risk` · `GET /groups` · `GET /groups/:id` · `GET /agents` · `GET /agents/:id` |
| Grants | `GET/POST /grants` · `PATCH/DELETE /grants/:id` · `GET /grants/:id/changes` · `POST /grants/check` (ceiling check for a candidate grant) |
| API keys | `GET/POST /users/:id/api-keys` · `DELETE /api-keys/:id` |
| Policy | `GET /policy/status` · `GET /policy/schema` · `GET /policy/files/:file?version=` · `GET /policy/versions` · `GET /policy/versions/:v/diff?against=` · `POST /policy/drafts` · `PUT /policy/drafts/:id` (If-Match base version) · `POST /policy/drafts/:id/validate` · `POST /policy/drafts/:id/impact` · `POST /policy/drafts/:id/publish` (409 on stale base) · `POST /policy/drafts/:id/approve` · `POST /policy/rollback {toVersion}` |
| Models | `GET /connectors` · `POST /connectors/:id/enabled {enabled, reason}` (writes a policy version) · `GET /models` · `GET /access-matrix` |
| Tools & MCP | `GET /mcp/servers` · `GET /tools` · `POST /tools/:id/quarantine` · `POST /tools/:id/approve-hash {hash, reason}` |
| Budgets | `GET /budgets/tree?period&meter` · `GET /budgets/:scope/:id/series` · `POST /budgets/:scope/:id/breaker/reset {reason}` · `GET /savings` |
| Feed & artifacts | `GET /feed` · `GET /feed/rules` · `POST /feed/sync` · demo feed server `POST /rules` · `GET /artifacts/scans` |
| Quality & perf | `GET /quality/runs` · `GET /quality/runs/:id` · `GET /metrics/performance?range=` |
| Insights | `GET /insights/clusters` · `GET /insights/clusters/:id` · `POST /insights/clusters/:id/skill` · `POST /skills/:id/publish` · `GET /specialists` · `PATCH /specialists/:id` |
| Audit | `GET /audit?query` · `POST /audit/verify {from,to}` · `POST /exports {format, filters}` · `GET/POST /reports` · `GET /break-glass` · `POST /break-glass {recordRefs, reason, incidentId}` → short-lived raw-read token |
| Me | `GET /me/usage` · `GET /me/access` · `GET /me/requests` · `GET /me/insights` · `GET /me/blocks` |

### 3.1.3 SSE topics

| Topic | Events | Consumers |
|---|---|---|
| `decisions` | `decision.created` (DecisionEvent; server-side scoped and sampled for viewers) | Live traffic, Overview strip, User 360 activity |
| `incidents` | `incident.created / updated` | Overview, Incidents, bell |
| `approvals` | `approval.created / decided / expired` | Approvals, bell, `/me` |
| `policy` | `policy.version_loaded`, `policy.disk_invalid`, `policy.disk_valid`, `draft.updated`, `draft.conflict` | Status bar, Policies, bell, trace badges |
| `grants` | `grant.changed`, `grant.expiring`, `grant.expired` | User 360, Grants |
| `budgets` | `budget.tick` (5 s rollups), `breaker.transition` | Overview, Budgets |
| `inventory` | `connector.health`, `tool.drift`, `tool.quarantined` | Models, Tools & MCP |
| `feed` | `feed.synced`, `feed.verification_failed`, `feed.rule_hit` | Feed, status bar |
| `audit` | `chain.verified`, `chain.broken`, `break_glass.performed` | Status bar, Overview, Audit |
| `quality` | `test_run.finished` | Guard quality |

---

## 3.2 Surfaces outside the panel

*Brief §8: copy and structure only. Gateway messages are plain text with optional markdown (LibreChat renders markdown; OpenCode shows tool errors as plain text). Every message has the same skeleton: **icon + what happened · why (plain language) · rule ID · trace ID · what you can do**. Max 4 lines. i18n keys shown for the first message; all copy is ICU-ready.*

### Block message

```
⛔ Blocked by company AI policy (SEC-FLOW-01)
This action would send data from a sensitive file to an external destination after the session read untrusted content.
Trace tr_9b21e4 · If you need this, request an exception: https://ai.corp/me/requests/new?trace=tr_9b21e4
```
- Keys: `gw.block.title {ruleId}`, `gw.block.reason.{ruleId}` (one plain-language sentence per rule, maintained next to the rule), `gw.block.footer {traceId, url}`.
- OpenCode (thrown from `tool.execute.before`): same three lines, no emoji fallback `[BLOCKED]` if the terminal lacks emoji.
- The URL contains only the trace ID, never payload data. The "request an exception" target is an access request in `/me` *(S8)*; for actions the policy already allows with approval, the gateway returns `require_approval` instead and this line is omitted.

### Approval pending and outcome

```
⏳ Waiting for approval (SEC-FLOW-01) — git push to github.com/jk-priv/loan-calc needs a security reviewer.
Request apr-0193 · decided automatically as "denied" in 10 min if nobody responds.
```
Outcomes (replace the pending line in place where the client allows; otherwise a new message):
```
✓ Approved by k.wojcik — git push allowed to this remote for 15 min (until 14:27). Request apr-0193.
✕ Denied by k.wojcik — "pushes to a private remote". Request apr-0193 · trace tr_9b21e4.
✕ Approval expired — nobody responded in 10 min, so the action was not run. Request apr-0193.
```

### Redaction / pseudonymisation notice

```
🛡 2 identifiers pseudonymised (PESEL, IBAN) and 1 name. The model saw placeholders; your answer shows the original values.
```
`redact` variant: `🛡 1 secret removed (API key). It was not sent to the model and is masked in this answer.`

### Routed-to-local notice

```
⌂ Answered by a local model (Bielik 11B) — this conversation contains confidential data, which stays on company servers. Trace tr_8f3a2c
```
Specialist variant: `⌂ Answered by the company loan-memo model (local) — picked automatically for this task.`

### Degraded-response marker

```
◐ Degraded response — your team's cloud budget for today is used up, so a local model (Qwen3 8B) answered. Quality may be lower. Resets 00:00.
```
Also: `◐ Degraded response — the Gemini connector is switched off by an administrator, so a local model answered.` The marker is always the **first** line, never appended after the answer.

### OpenCode device login (plugin `auth` hook)

```
Company AI Gateway — sign in
  1. Open  https://sso.corp.example/realms/corp/device
  2. Enter code  WDJB-MJHT
  3. Sign in with your company account (MFA may be required)
Waiting for confirmation…  code expires in 10:00   ·   Esc to cancel
✓ Signed in as Jan Kowalski (developers). Models available: auto, local-coder.
```
Errors: `Code expired — run "opencode auth login" again.` · `Your account has no AI access yet. Ask your team lead or open https://ai.corp/me.`

### Keycloak login theme (branding note)

Product name "Company AI Gateway", company logo, no extra fields. One line under the form: *"Sign in to use company AI tools. Requests are inspected for security and personal data — see the AI usage policy."* (link). Device-flow confirmation page states the client name ("OpenCode on dev-jk-01") so users can spot a phishing device code.
