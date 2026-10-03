# 3b. Screen specs — Access

*Views 6, 7, 11, 18 (+ group admin "My team"). Shared entities and states: [03-screen-specs.md](03-screen-specs.md).*

Access rules shown in these views follow §7.1 / §11.0 exactly: **resolution order org locks → group grants (YAML) → user grants (DB)**; a user grant can extend access but never past an org lock. The UI always shows the whole resolution chain, not just the result.

---

## 6a. Users & groups — `/users`, `/groups`, `/groups/:id`

**Purpose.** Find any person or group fast; see who has unusual access, activity or risk.
**Primary users.** Policy admin, analyst; group admin (own group).
**Entry points.** Sidebar, `g u`, `@name` in the palette, any principal link.

**Users table.** Columns: name (diacritics-safe sort), email, Keycloak groups (read-only chips), effective preset, user grants count (with "temporary" icon if any expire), API keys count, last active, requests 7 d, spend 7 d, blocks 7 d, risk vs group baseline (normal / elevated / high, icon + label). Filters: group, has user grants, has temporary grants, risk, inactive > 30 d. Row → User 360.

**Groups list.** Group, members, preset, models / skills / tools allowed (counts with hover list), budget (used / limit today), source `groups.yaml L…`. Row → group page.

**Group page `/groups/:id`.** Header (preset, budget meter, members). Tabs: Members (users table scoped) · Permissions (read-only render of the group's YAML block, each line clickable → Policies editor) · Budget split · Activity (scoped traffic) · Approvals (team). For group admins this page is their home ("My team"):
- **Budget split** *(group admin W)*: per-member share of the group budget (sliders + numbers, sum ≤ group limit, written as DB `budget_share` grants);
- **Member access**: toggle allowed models / skills for members **within the group ceiling** (writes DB user grants; items outside the ceiling are shown disabled with the reason).

**Elements.** Users table M · Groups list M · Group permissions read-only view M · Group admin budget split S · Member access toggles S · "Open in Keycloak" link (user creation lives there, §5.2) M.

**Actions.** Open User 360 · open in Keycloak · (policy admin) issue API key for a user · (group admin) adjust budget split, toggle member access.

**States.** Empty users: "Users appear on first sign-in (just-in-time from Keycloak). Demo users: Jan Kowalski, Anna Nowak…". Keycloak unreachable: groups shown from last token claims with "as of" stamp.

**Permissions.** Policy admin, judge: W. Analyst: R. Group admin: own group, W on budget split and member access within ceiling. Others: none.

**Data.** `GET /users?group&risk&hasGrants&q&cursor` → `{ id, displayName, email, groups, preset, userGrants, temporaryGrants, apiKeys, lastActiveAt, requests7d, spend7d, blocks7d, riskLevel }[]`. `GET /groups` → `{ id, members, preset, allowed: { models, skills, tools, mcp }, budget, source: { file, line } }[]`. `GET /groups/:id`. Writes via `/grants`.

---

## 6b. User 360 — `/users/:userId` (agents reuse it as Agent 360)

**Purpose.** Everything about one person in one place: what they can do and why, what they did, and how risky it looks — with inline grant editing.
**Primary users.** Policy admin (grants), analyst (investigation), group admin (own members), judge.
**Entry points.** Any principal link, palette `@`, Users table, incident, approval.

**Header.** Name, email, Keycloak groups (chips; "Open in Keycloak"), effective preset (with source), risk level vs group baseline, last active, quick actions: `+ Grant`, `Revoke API keys`, `Open in traffic`, `⋯` (copy ID, break-glass history for this user).

**Tabs:** `Access` · `Activity` · `Risk` · `API keys` · `Changes`.

### Access tab

```
┌ Effective access — as of grants g231 · policy v8 ──────────────────── [Show resolution chain ☑] [+ Grant] ┐
│ KIND / ITEM          STATE          SOURCE (resolution chain)                        CONSTRAINTS   EXPIRES  │
│ Models & aliases                                                                                            │
│  auto                ✓ allowed      group developers (groups.yaml L22)                 —             —      │
│  smart → gemini/…    ✓ allowed      user grant g-0412 · by you · "Gemini pilot"        ≤ internal    6 d 23 h│
│                                      ↳ capped by ‹LOCK-01› for restricted; model data classes ≤ internal   │
│ Connectors           ollama ✓ group · gemini ✓ via smart (g-0412)                                          │
│ Skills               skill/… ✓ group credit-analysts                                                      │
│ MCP servers          jira ✓ user grant g-0398 · docs-search ⛔ quarantined (inc-0057)                       │
│ Tools                read ✓ · edit ✓ · bash ✕ user deny g-0415 (overrides group) · webfetch ✕ managed cfg│
│                      git push → jk-priv/loan-calc ⏱ elevated 14:57 left (apr-0193)                         │
│ Budgets              user share 1.00 USD/day (g-0420) of developers 5.00 · today 0.42                       │
│ Preset               balanced ← group developers                                                           │
│ Data-class ceiling   cloud ≤ internal ← ‹LOCK-01› + group max_external_data_class                           │
│ ┌ What this user's clients see ──────────────────────────────────────────────────────────────────────────┐ │
│ │ /v1/models: auto · local-coder · smart        tools/list (MCP): jira.search, jira.create_issue          │ │
│ └────────────────────────────────────────────────────────────────────────────────────────────────────────┘ │
└────────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

| Element | Pri |
|---|---|
| Effective access grouped by kind: models & aliases, connectors, skills, MCP servers, tools (OpenCode built-ins + MCP tools), budgets, preset, data-class ceiling | M |
| State badge per item: allowed / denied / elevated / expiring / expired / not granted (icon + label) | M |
| Source chip per item: `group <name> (file Lnn)` / `user grant g-… · author · reason` / `org lock LOCK-…` / `managed config` / `elevation apr-…`; click → the policy line, grant, lock or approval | M |
| Resolution chain toggle: expands each row into its layers (lock → group → user grant) with the effect of each | M |
| Expiry with countdown; "expiring" style under 24 h | M |
| Inline actions per row: grant / revoke / extend / edit constraints | M |
| "What this user's clients see" — personalised `/v1/models` and MCP `tools/list` preview | M |
| Recently changed marker (changed in last 10 min) | S |

**Grant drawer** (shared with Grants view; see flow F4): object picker (kind → item), effect allow / deny, constraints (data classes — impossible values disabled with the lock that forbids them; budget share; preset), expiry presets (1 d / 7 d / 30 d / custom; custom supports minutes for demos), reason (required), **live ceiling check** (`POST /grants/check`) and **after-save preview** of `/v1/models`. Revoking a group-sourced item creates a user-level deny and says so (flow F5).

### Activity tab

Timeline, newest first, grouped by session (collapsible): session start (client, device), each request (decision badges, model chosen and short "why"), tool / MCP calls with redacted arguments and outcome, approvals, incidents, grant changes affecting the user. Filters: kind, decision, client, range. Spend-over-time chart (tokens / USD / GPU-s) above the timeline. Every item opens its trace. **Redacted by default**; `Reveal raw…` on an item starts break-glass (flow F9).
Priority: timeline M · spend chart S · session grouping S.

### Risk tab

- Taint events: when the user's sessions became `untrusted` / `sensitive`, from which source (M);
- Blocked attempts by rule (M);
- Anomalies vs group baseline: requests/day, tool mix, external routing share, spend rate, off-hours activity — each as the user's value vs the group's median and band, with the date it deviated (S);
- Incidents involving the user (M);
- Break-glass accesses **to this user's data** (who, when, why) (S).

### API keys tab

Prefix, label, created, last used, expires; issue (shows the key once, with copy and a warning), revoke (immediate; next request with it → 401 and, for a revoked key, a low incident). Policy admin for any user; employees issue their own in `/me`.

### Changes tab

Append-only list from `grant_changes` + policy changes that affected this user's effective access (e.g. "v9: group developers lost `smart`"), with actor, time, reason.

**States.** User never signed in (exists only in Keycloak): "Not provisioned yet — appears after first sign-in." Disabled in Keycloak: banner "Account disabled in Keycloak; tokens rejected." Scoped viewer (group admin): Activity shows redacted payloads only, no break-glass, no API keys tab.

**Permissions.** Policy admin, judge: W. Analyst: R + break-glass + revoke API keys. Group admin: own members — Access W within ceiling, Activity R, Risk R. Employee: their own data via `/me`.

**Data.** `GET /users/:id` (header) · `GET /users/:id/effective-access` → `EffectiveItem[]` + `{ grantsVersion, policyVersion }` · `GET /users/:id/models-preview` → `{ models: string[], tools: string[] }` · `GET /users/:id/activity?kind&decision&range&cursor` → sessions with `DecisionEvent[]`, approvals, incidents, grant changes · `GET /users/:id/risk` → `{ taintEvents, blocksByRule, anomalies: { metric, value, baselineMedian, band, since }[], incidents, breakGlassOnSubject }` · `GET /users/:id/api-keys` · `GET /grants?principal=:id` + `/grants/:id/changes`. SSE: `grants`, `decisions` (filtered to this principal).

---

## 7. Agents — `/agents`, `/agents/:agentId`

**Purpose.** Govern non-human identities: what each agent may do, on whose behalf, within which limits, and what it actually did.
**Primary users.** Policy admin, analyst, judge.
**Entry points.** Sidebar, palette `@research-bot`, traffic rows with the agent icon, budget nodes.

**List.** Agent ID, Keycloak client, owner (user / group), preset, tools count, limits (max steps / depth / repeat), status (active / breaker open / disabled), last run, runs 24 h, blocks 24 h, spend today.

**Agent 360** (User 360 layout with agent-specific sections):

| Section | Content | Pri |
|---|---|---|
| Identity & scopes | Keycloak client ID, scopes, credential type (client credentials), owner | M |
| Delegation chains | Recent chains as horizontal diagrams: `Anna Nowak → research-bot → mcp core-banking`, each hop showing scopes **narrowing** (struck-through scopes removed at that hop) and token lifetime (RFC 8693) | S |
| Effective access | Same component as User 360, including tool labels (`reads_untrusted`, `external_egress`, `irreversible`), path allow/deny, recipient allowlist, approval-required tools | M |
| Limits | `max_steps`, `max_tool_depth`, `repeat_call {count, window}` with current usage in the active run; budget per session (tokens, GPU-s) with breaker | M |
| Task-scoped policy (strict/paranoid) | For the current/last run: the proposed narrow policy, the intersection with the static policy, and calls rejected for being outside the plan | S |
| Recent runs | Run (session) list: start, trigger, steps, tool calls, approvals, blocks, spend, outcome (completed / blocked / breaker / approval denied); open → session view (hop rail + traces) | M |

**Actions.** Disable agent (= deny all via policy admin user-level deny / Keycloak disable link), reset breaker, open the agent's YAML block (`groups.yaml › agents/research-bot`), edit limits (policy flow).

**States.** Agent defined in policy but never ran: "No runs yet." Agent running now: live run strip at the top (step n / max, current tool, spend).

**Permissions.** Policy admin, judge W; analyst R + reset breaker; group admin R for agents owned by their group.

**Data.** `GET /agents` · `GET /agents/:id` → `{ principal, keycloakClientId, scopes, owner, preset, limits, effectiveAccess: EffectiveItem[], delegationChains: { hops: { principal, scopesGranted, scopesRemoved, tokenTtlS }[], lastSeenAt }[], taskPolicy?: { proposed, effective, rejectedCalls }, runs: { sessionId, startedAt, steps, toolCalls, approvals, blocks, spend, outcome }[] }`. SSE: `decisions` (this principal), `budgets`.

---

## 11. Grants (DB) — `/grants`

**Purpose.** All per-user and temporary assignments across the organisation: create, expire, audit; answer "who has Gemini?".
**Primary users.** Policy admin; group admin (own members); analyst (read).
**Entry points.** Sidebar, User 360 grant links, `g-…` in the palette, bell "grant expiring".

**Layout.** Summary chips (active · temporary · expiring in 24 h · created today · denies) → table → grant drawer.

| Element | Content | Pri |
|---|---|---|
| Table | Grant ID, principal, effect (allow / deny), object (kind + id), constraints, expires (countdown, "expiring" style < 24 h), reason, created by / at, status, source approval (for elevations) | M |
| Quick questions | Preset filters: "Who has cloud access?", "Temporary grants", "Expiring this week", "Denies overriding a group", "Created from approvals (elevations)" | M |
| Object pivot | Group by object → list of principals (e.g. `smart`: 3 users via grants + group developers via policy) | S |
| Grant drawer | Same component as User 360 (ceiling check, preview, reason required) | M |
| History | Per grant: `grant_changes` timeline (create / update / revoke / expire) with actor and reason | M |
| Bulk revoke / extend | With a single reason | C |
| Export CSV | Current filter | C |

**Rules the UI enforces (and explains).** Reason is required; data classes beyond a lock are not selectable; group admins can only pick their members and only objects inside the group ceiling; an expiry is required for `connector`/`model` grants to cloud tiers *(assumption A6, configurable)*.

**States.** Empty: "No per-user grants. Group-level access lives in the policy files (`groups.yaml`); use grants for exceptions and pilots." DB unreachable: read-only error with request ID (grants cannot be edited).

**Permissions.** Policy admin, judge W · group admin W scoped · analyst R · employee R (own, in `/me`).

**Data.** `GET /grants?principal&objectKind&objectId&status&expiresBefore&createdBy&cursor` → `Grant[]`; `POST /grants` (body = `Grant` minus server fields) → 201 / 422 with `{ violatedLock?, reason }`; `PATCH /grants/:id`; `DELETE /grants/:id {reason}` (soft revoke); `GET /grants/:id/changes` → `GrantChange[]`; `POST /grants/check` → `{ ok, effective: EffectiveItem, modelsPreview }`. SSE `grants`.

---

## 18. Employee self-service home — `/me` (and group admin "My team" → see 6a)

**Purpose.** Let any employee understand their own AI access and usage without asking IT: what they can use, what it costs, why something was blocked, what is pending.
**Primary users.** Every employee; also every other role (their own data).
**Entry points.** Landing for employees; links in client messages (`/me/requests`, trace links); user menu "My home".

**Layout.** Simple, non-SOC tone; one column with cards on desktop, stacked on mobile.

| Card / tab | Content | Pri |
|---|---|---|
| My usage | Requests and spend this month vs my budget share (tokens / USD; GPU-s hidden behind "details"), models used, skills used | M |
| My access | My models (exactly my `/v1/models`), skills, tools, MCP servers, each with a plain source ("from your team *developers*", "temporary access until 10 Oct — Gemini pilot") | M |
| My requests | Pending and decided approvals, cancel pending, see outcome; access requests *(S8)* | M |
| Recent blocks | My last blocked / held requests with the plain-language reason and rule ID, linking to my simplified trace | S |
| My API keys | Issue (shown once), label, last used, revoke | M |
| My insights | Personal Automation Insights suggestions (opt-in toggle): "You summarise loan applications ~daily — try `skill/loan-memo-summary`" | S |
| Privacy | What is inspected and stored (redacted only), raw retention setting, break-glass accesses to my data *(S7)* | C |

**States.** No AI access yet: "Your account has no AI models assigned. Your team lead or the AI governance team can grant access." with the group admin's name if one exists. Insights opted out: card shows the opt-in explanation.

**Permissions.** Everyone, own data only (server-scoped).

**Data.** `GET /me/usage` → `{ period, requests, tokens, usd, budgetShare, models: { id, requests }[], skills }` · `GET /me/access` → `EffectiveItem[]` (plain-language sources) · `GET /me/requests` → `Approval[]` (own) · `GET /me/blocks` → `DecisionEvent[]` (own, non-allow) · `GET/POST /users/me/api-keys`, `DELETE /api-keys/:id` · `GET /me/insights` + `PATCH /me/insights {optIn}`. SSE `approvals`, `grants` (own).
