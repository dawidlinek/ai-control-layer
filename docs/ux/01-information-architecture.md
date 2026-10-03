# 1. Information architecture

*Deliverable 1 of the admin-panel UX. Source of truth: [`CONCEPT.md`](../CONCEPT.md). Conflicts and assumptions: [README](README.md#conflicts-with-conceptmd).*
*Visual version: [navigation-map.md](navigation-map.md) / [navigation-map.html](navigation-map.html).*

---

## 1.1 Organising idea

The panel is organised around the **evidence chain**, not around database tables:

```
  signal  ──►  event  ──►  trace  ──►  rule / grant / budget  ──►  policy line + version  ──►  change (dry-run → publish)
 (Overview)  (Live traffic) (Decision trace)   (rule chip popover)         (Policies)                (Policies)
```

Every screen is a place on this chain. Every number links one step to the right (towards evidence), and every
configuration links one step to the left (towards the traffic it affects). A judge who clicks anything ends up,
within 2–3 clicks, at either a concrete request or a concrete line of YAML.

Three questions drive the top of the hierarchy (§12 Posture):

| Question | Answered on | Proof one click away |
|---|---|---|
| Are we safe? | Overview › posture, incidents, top OWASP risks | Incidents, Guard quality (FPR next to ASR) |
| What is happening right now? | Overview › live decision strip | Live traffic → Decision trace |
| What is it costing? | Overview › spend vs budget, breakers, savings | Budgets & spend |

---

## 1.2 Sitemap

Seven navigation groups, 18 views (numbers match the brief §4 and [screen specs](03-screen-specs.md)).
`[M]` = must for the hackathon build, `[S]` = should, `[C]` = could.

```
AI Control Layer — Admin panel
│
├── Overview  /                                            [M]  (1)
│
├── MONITOR
│   ├── Live traffic          /traffic                       [M]  (2)
│   │     └── Decision trace  /traffic?trace=:id  (drawer)   [M]  (3)
│   │                         /traces/:traceId    (page)     [M]
│   │                           └── Session rail  /sessions/:sessionId  [S]
│   ├── Incidents             /incidents                     [M]  (4)
│   │     └── Incident detail /incidents/:id                 [M]
│   └── Approvals             /approvals                     [M]  (5)
│         └── Approval detail /approvals/:id   (split pane)  [M]
│
├── ACCESS
│   ├── Users & groups        /users · /groups               [M]  (6)
│   │     ├── User 360        /users/:userId                 [M]
│   │     │     tabs: access · activity · risk · keys · changes
│   │     └── Group page      /groups/:groupId  ("My team" for group admins)  [S]
│   ├── Agents                /agents                        [S]  (7)
│   │     └── Agent 360       /agents/:agentId               [S]
│   └── Grants                /grants                        [M]  (11)
│
├── GOVERN
│   ├── Policies              /policies                      [M]  (10)
│   │     ├── Editor          /policies/edit/:file?line=&rule=   (Form | YAML)
│   │     ├── Dry-run         /policies/drafts/:draftId/impact
│   │     ├── History         /policies/versions  ·  /policies/versions/:v  (diff)
│   │     └── Org locks       /policies/locks    (read-only)
│   ├── Models & connectors   /models                        [M]  (8)
│   │     tabs: connectors · registry · access matrix
│   ├── Tools & MCP           /tools                         [M]  (9)
│   │     └── Server / tool   /tools/servers/:id · /tools/:toolId
│   ├── Signature feed & artifacts  /feed                    [M]  (13)
│   │     tabs: feed · rules · artifacts
│   └── Budgets & spend       /budgets                       [M]  (12)
│         └── Node            /budgets/:scope/:id   (org | group | user | agent | session)
│
├── ASSURE
│   ├── Guard quality         /quality                       [M]  (14)
│   ├── Performance           /performance                   [S]  (15)
│   └── Audit & exports       /audit                         [M]  (17)
│         tabs: search · chain · exports · reports · break-glass log
│
├── OPTIMISE
│   └── Automation Insights   /insights                      [S]  (16)
│         ├── Cluster         /insights/:clusterId  (task card → draft skill → publish)
│         ├── Skills          /insights/skills
│         └── Specialists     /insights/specialists/:modelId  (train → scan → register → eval)
│
└── ME
    └── My home               /me                            [M]  (18)
          tabs: usage · access · requests · api keys · insights · blocks
```

**Not in the sidebar** (reached by links, the command palette or notifications):
rule chip popover (any `SEC-*`, `LOCK-*`, `FEED-*`, `AUTHZ-*`, `BUDGET-*` ID), version diff, break-glass modal,
grant drawer, notifications centre, keyboard help (`?`).

---

## 1.3 Navigation model

### 1.3.1 Shell

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│ ◆ AI Control Layer   ● Gateway OK │ policy v8 ⟳ 14:02 │ feed f-2026.10.03.4 │ chain ✓ │ ● LIVE  ⌘K 🔔3 JK▾│ ← status bar
├───────────────┬──────────────────────────────────────────────────────────────────────────────────┤
│ ◉ Overview    │  Breadcrumb › Page title                         [view actions]   as of 14:03:12 │
│               │ ──────────────────────────────────────────────────────────────────────────────── │
│ MONITOR       │                                                                                  │
│   Live traffic│                                                                                  │
│   Incidents 2 │                         page content                                │ drawer     │
│   Approvals 1 │                                                                     │ (trace,    │
│ ACCESS        │                                                                     │  grant,    │
│   Users       │                                                                     │  rule)     │
│   Agents      │                                                                     │            │
│   Grants      │                                                                     │            │
│ GOVERN        │                                                                     │            │
│   Policies  ⚠ │                                                                     │            │
│   Models      │                                                                     │            │
│   Tools & MCP │                                                                     │            │
│   Feed        │                                                                     │            │
│   Budgets     │                                                                     │            │
│ ASSURE        │                                                                     │            │
│   Guard qual. │                                                                     │            │
│   Performance │                                                                     │            │
│   Audit       │                                                                     │            │
│ OPTIMISE      │                                                                     │            │
│   Insights    │                                                                     │            │
│ ───────────── │                                                                     │            │
│   My home     │                                                                     │            │
└───────────────┴──────────────────────────────────────────────────────────────────────────────────┘
```

- **Status bar (always visible, every role except employee).** Five live facts, each a link:
  - `● Gateway OK | Degraded | Unreachable` → Performance (or the unreachable state page);
  - `policy v8 ⟳ 14:02` — the version badge. It pulses once on hot reload; shows `external edit` when the
    source was `file`, and `⚠ disk invalid · last good v8` when the file on disk fails validation → Policies › History;
  - `feed f-…` with last sync age → Feed;
  - `chain ✓ / ✗` (last hash-chain verification) → Audit › chain;
  - `● LIVE / ❚❚ PAUSED` — global stream state; pausing here pauses every live widget.
- **Sidebar** grouped by job (Monitor → Access → Govern → Assure → Optimise → Me). Counters only where action is
  expected (open incidents assigned to me, pending approvals I can decide, policy alerts). Collapses to icons
  at < 1280 px; hidden behind a menu button at < 768 px.
- **Right drawer** for "peek" objects (trace, grant, rule, user card). The drawer is URL-addressed
  (`?trace=tr_…`), so it can be shared and survives reload; `Open full page` promotes it to `/traces/:id`.
  Only one drawer at a time; `Esc` closes it and returns focus to the row that opened it.
- **Breadcrumbs** on detail pages only. Detail pages keep the filter state of the list they came from (`← Back to
  Live traffic (decision=block, 15 min)`).

### 1.3.2 Landing page per role

| Role | Lands on | Why |
|---|---|---|
| Policy admin | Overview | Posture and the policy-version state first |
| Security analyst | Overview (can pin Live traffic as home) | The 5-second check, then work |
| Group admin | Group page (`/groups/:id`, "My team") | Their scope only |
| Management viewer | Overview (management lens: no payload-level widgets) | Posture, spend, trends |
| Employee | My home (`/me`) | Self-service only |
| Judge | Overview with the **Demo checklist** card *(suggestion S1)* | Rewards curiosity, zero preparation |

### 1.3.3 Cross-linking rules (the explainability contract)

| From (anywhere it appears) | Click → | Hover / focus → |
|---|---|---|
| Decision badge | Live traffic filtered by that decision | Definition of the action (§6.3) |
| Rule chip `SEC-PII-01` | Rule popover → `Open policy line` (`/policies/edit/controls.yaml?rule=SEC-PII-01`) | Type, stages, hits 24 h, FPR from last suite run |
| Rule chip `LOCK-01` | Org locks (read-only), line highlighted | "Org lock — cannot be overridden by any grant" |
| Rule chip `FEED-…` | Feed › rules › that entry | Source, CVE, ATLAS technique |
| Rule chip `AUTHZ-…` *(S4)* | The grant row (User 360 › access) that caused it | Grant source, author, expiry |
| Rule chip `BUDGET-…` *(S4)* | Budget node with its breaker | Limit, usage, breaker state |
| Version badge `policy v8` | Policies › History › v8 (with diff to previous) | Author, source (`panel` / `file`), time |
| User / agent name | User 360 / Agent 360 | Groups, preset, risk vs baseline |
| Model ID | Models › registry row | Tier, data classes, connector health |
| Tool / MCP server | Tools & MCP row | Tier, labels, pinned hash |
| Any metric number | The filtered list that produced it | Definition, window, CI where applicable |
| Trace ID / incident ID / any ID | Copy on click of the copy icon; navigate on text click | — |

### 1.3.4 Command palette (`Ctrl/⌘ K`)

One input, typed prefixes, recent items first:

| Prefix | Finds | Example |
|---|---|---|
| *(none)* | Everything, fuzzy | `kowal` → Jan Kowalski |
| `@` | Users, agents, groups | `@research-bot` |
| `#` | Rule IDs (controls, locks, feed, built-in) | `#SEC-FLOW` |
| `tr_` / `inc-` / `apr-` / `g-` | Trace, incident, approval, grant by ID | `tr_8f3a…` |
| `v` | Policy version | `v9` |
| `>` | Actions | `> pause live`, `> grant model`, `> verify chain`, `> kill switch gemini` |

Actions in the palette respect permissions: unavailable actions are listed greyed out with the role they need, so a
judge learns what exists.

### 1.3.5 Keyboard

| Keys | Action |
|---|---|
| `g` then `o / t / i / a / u / p / m / b / q` | Go to Overview / Traffic / Incidents / Approvals / Users / Policies / Models / Budgets / Quality |
| `/` | Focus the page filter |
| `j` / `k`, `Enter`, `Esc` | Move in tables, open, close drawer |
| `Space` | Pause / resume the live stream (when the table has focus) |
| `[` / `]` | Previous / next trace in the current filtered list (inside the trace drawer) |
| `a` / `d` / `e` | Approve / deny / approve with elevation (Approvals detail, with confirm) |
| `c` | Copy the ID of the focused row |
| `?` | Shortcut help |

All shortcuts are single-key only when focus is not in an input; every shortcut has a visible button equivalent.

### 1.3.6 URL state

Filters, sort, time range, open drawer, active tab and pause state live in the query string (`nuqs`), e.g.
`/traffic?decision=block,require_approval&group=developers&point=tool_call&range=15m&trace=tr_8f3a`.
Saved views are named query strings, stored per user (server-side), shareable as links.

### 1.3.7 Notifications

The bell collects events that need a human; each links to its object:
- new incident ≥ medium severity (analyst, policy admin);
- approval assigned to my approver role;
- policy: external edit applied, disk file invalid (kept last good), GitOps PR opened / merged;
- circuit breaker opened; connector unhealthy; feed sync / signature verification failed;
- grant expiring within 24 h (policy admin, group admin of that group);
- break-glass access performed (policy admin, management viewer — the "who looked at whose data" signal).

Toasts appear only for things that happened **because of the current user's action** (published, granted) or for
critical incidents; everything else goes to the bell to keep the screen calm.

---

## 1.4 Roles

### 1.4.1 Keycloak group claims → panel roles

`CONCEPT.md` §12 defines three panel roles (admin / analyst / viewer). The brief adds three; see [README — conflicts](README.md#conflicts-with-conceptmd) C1.

| Panel role | Keycloak group (claim `groups`) | Concept role |
|---|---|---|
| Policy admin | `/panel/policy-admins` | admin |
| Security analyst | `/panel/analysts` | analyst |
| Group admin | `/panel/group-admins/<group>` (scope = that business group, e.g. `credit-analysts`) | *addition* |
| Management viewer | `/panel/viewers` | viewer |
| Employee | any authenticated user (no panel group) | *addition (self-service)* |
| Judge | `/panel/judges` = Policy admin ∪ Security analyst ∪ Management viewer, demo realm only; every action tagged `persona=judge` in the audit log | *demo persona* |

A user can hold several roles; permissions are the union. Every user also has **Employee** access to their own `/me`.

### 1.4.2 Role × view matrix

Legend: **W** read + write · **R** read · **A** act (triage / decide / reset) without editing configuration ·
**S** scoped (own group for group admins, own data for employees) · **Σ** aggregated only (no payloads, no
individual events) · **—** hidden (not in navigation; direct URL shows the no-permission state).

| # | View | Policy admin | Security analyst | Group admin | Mgmt viewer | Employee | Judge |
|---|---|---|---|---|---|---|---|
| 1 | Overview | R | R | S (team overview) | R (management lens) | — (→ `/me`) | R |
| 2 | Live traffic | R | R | S R (redacted) | — | — (own requests in `/me`) | R |
| 3 | Decision trace | R | R | S R | — | S R (own, simplified) | R |
| 4 | Incidents | R + comment | W (triage, assign, close, export) | S R (incidents of members) | Σ | — | W |
| 5 | Approvals | A | A | S A (approver = group admin) | — | S (my requests, cancel) | A |
| 6 | Users & groups | W | R | S R (members) | — | — | W |
| 6 | User 360 | W (grants inline) | R (+ break-glass) | S W (grants within group ceiling) | — | S R (= `/me`) | W |
| 7 | Agents | W | R | S R (group-owned agents) | — | — | W |
| 8 | Models & connectors | W (incl. kill switch) | R + A (kill switch only) | R (models available to group) | Σ (spend, health) | — | W |
| 9 | Tools & MCP | W (re-approve, pin) | R + A (quarantine only) | S R | — | — | W |
| 10 | Policies | W (publish; second approver if enabled) | R | S R (own group section) | — | — | W |
| 11 | Grants | W | R | S W (members, within ceilings) | — | S R (own) | W |
| 12 | Budgets & spend | W (limits) | R + A (reset breaker) | S W (split group budget across members) | R | S R (own) | W |
| 13 | Feed & artifacts | W | R | — | — | — | W |
| 14 | Guard quality | R | R | — | Σ (headline only) | — | R |
| 15 | Performance | R | R | — | — | — | R |
| 16 | Automation Insights | W (publish skill, train) | R | S R (group clusters ≥ k) | Σ (≥ k users only) | S (own suggestions, opt-in) | W |
| 17 | Audit & exports | R + export | R + export | — | Σ (reports, break-glass log) | — | R + export |
| 18 | My home | S | S | S | S | S | S |

**Sensitive actions** (each needs the role *and* a reason; each writes its own audit event):

| Action | Policy admin | Analyst | Group admin | Viewer | Employee | Judge |
|---|---|---|---|---|---|---|
| Break-glass "reveal raw" | ✓ | ✓ | — | — (sees that it happened) | — | ✓ |
| Connector kill switch | ✓ | ✓ | — | — | — | ✓ |
| Publish policy | ✓ | — | — | — | — | ✓ |
| Approve someone else's policy draft (second approver, *S3*) | ✓ (not the author) | — | — | — | — | ✓ |
| Re-approve MCP tool / pin new hash | ✓ | — | — | — | — | ✓ |
| Quarantine MCP tool | ✓ | ✓ | — | — | — | ✓ |
| Reset circuit breaker | ✓ | ✓ | ✓ (own group) | — | — | ✓ |
| Create / revoke grant | ✓ | — | ✓ (members, within ceilings) | — | — | ✓ |
| Issue / revoke API key | ✓ (any user) | revoke only | — | — | ✓ (own) | ✓ |
| Publish skill | ✓ | — | — | — | — | ✓ |
| Add feed rule (demo feed server) | ✓ | — | — | — | — | ✓ |
| Export audit / evidence | ✓ | ✓ | — | reports only | — | ✓ |

Design notes:
- Analysts can take **safe-direction** actions (quarantine, kill switch, revoke key, reset breaker) but not
  widening ones (re-approve a tool, publish policy, grant). This mirrors §9 monotonic confinement: narrowing is
  cheap, widening needs a privileged human.
- Hidden ≠ secret: the command palette lists actions a role cannot perform (greyed, with the role needed).

---

## 1.5 Global UI rules (apply to every view)

| Rule | Detail |
|---|---|
| Version stamps | Every data panel shows `as of hh:mm:ss`; every configuration panel shows the policy / grants version it reflects |
| Private by default | Payloads are always the stored redacted / pseudonymised version; identifiers masked (`PESEL ***-**-**123`, `PL** **** … 2874`); raw only via break-glass |
| Live by default | New rows enter through an "N new events" pill when the user has scrolled or is hovering; no table jumps under the cursor. `prefers-reduced-motion` disables pulses and row highlights (replaced by a static "new" marker) |
| States | Each view defines: loading (skeleton matching layout), empty (what will appear here + how to produce it), error (message + request ID + retry), no permission (which role is needed, who grants it), **gateway unreachable** (see below) |
| Gateway unreachable | Panel reads history from Postgres, so lists still work. A red banner: "Gateway unreachable since 14:02. Showing stored data; the live stream, policy publish, grants and approvals are unavailable — they are written by the gateway." Writes are disabled with that tooltip, never silently queued |
| Copy | English, ICU message format (`next-intl`) so Polish plural forms work later; no text baked into images; dates in ISO-like `2026-10-03 14:03` with the user's timezone shown in the footer |
| Polish data | Fonts and sort order support diacritics (`ą ć ę ł ń ó ś ź ż`); search is accent-insensitive (`Wisniewski` finds `Wiśniewski`) |

---

## 1.6 Proposed stack (brief §9)

| Need | Choice | Licence | Why |
|---|---|---|---|
| Framework | Next.js (App Router) + TypeScript | MIT | Required by `CONCEPT.md` §4 |
| Components | shadcn/ui on Radix UI primitives + Tailwind CSS | MIT / MIT / MIT | Code we own (copied in, not a dependency to fight); Radix gives accessible focus management, dialogs, menus |
| Tables | TanStack Table + TanStack Virtual | MIT | Headless, virtualised rows for the live stream; column pinning and priority columns for narrow screens |
| Data fetching | TanStack Query | MIT | Cache + invalidation when SSE says something changed |
| Live stream | Native `EventSource` (SSE) | — | One-way server → panel, auto-reconnect with `Last-Event-ID`, proxy-friendly; no WebSocket needed |
| Charts | Recharts (via shadcn chart wrappers) | MIT | Enough for time series, bars, sparklines; consistent theming with the component tokens |
| Policy editor | Monaco (`@monaco-editor/react`) + `monaco-yaml` (JSON-Schema validation, autocomplete, hover docs) + Monaco diff editor | MIT | Same schema the gateway validates against (§11.1) |
| URL state | `nuqs` | MIT | Type-safe query-string state for filters |
| Command palette | `cmdk` (shadcn Command) | MIT | Accessible, fast |
| Forms | react-hook-form + zod | MIT | zod schemas generated from the same JSON Schema |
| Auth | Auth.js (Keycloak provider) | ISC | OIDC code flow + PKCE; group claims → roles |
| i18n | next-intl | MIT | ICU messages, Polish plurals later |
| Icons | Lucide | ISC | Decision icons (never colour alone) |
| Dates | date-fns | MIT | — |

Avoided: anything AGPL/GPL/BSL; chart libraries with non-OSI licences (e.g. Highcharts).
