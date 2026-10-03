# Prompt: Admin panel UX design

> Paste everything below the line into a new session started in this repository.

---

You are a senior product designer specialising in security and observability tools (SOC consoles, IAM consoles, policy management). Design the UX for the **admin panel of our AI Control Layer**. It is the only first-party UI in the product, and it is where hackathon judges will form most of their opinion.

## 1. Read first

Read `docs/CONCEPT.md` in full before designing anything. It is the source of truth for architecture, terminology and features. The sections that matter most for the panel:
- §1 summary;
- §5 clients and identity;
- §6 decision pipeline, actions, presets, risk scoring;
- §7 routing, connectors, per-user model access;
- §8 budgets;
- §9 tools/MCP and historical attacks;
- §10 lockdown;
- §11 policy storage and editing;
- §12 admin panel views;
- §13 audit;
- §14 Automation Insights;
- §15 fine-tuned models;
- §16 tests and metrics;
- §17 demo scenarios.

If anything below conflicts with `CONCEPT.md`, the concept wins. Tell me about the conflict.

## 2. Product context (short version)

- **What it is:** a company-wide AI gateway. All AI traffic goes through it in both directions: prompts, responses, tool calls, tool results, MCP traffic, embeddings.
- **What it does with that traffic:**
  - classifies it for PII, secrets, injection and data sensitivity;
  - enforces permissions;
  - routes it to a model (local Ollama models, a Gemini cloud connector, fine-tuned local specialists picked by `auto`);
  - enforces budgets;
  - writes a hash-chained audit log.
- **Clients** are off-the-shelf and **not designed by us**: OpenCode for developers (with our plugin) and LibreChat for staff. Keycloak does SSO.
- **Scenario:** a Polish bank. Credit analysts, developers, autonomous agents. Data includes PESEL, IBAN, client records.
- **Hackathon judging:**
  - Security Reporting is 20% of the score and Robustness 30%.
  - Judges will use the panel live with **zero preparation**: type ad-hoc prompts in the clients, edit policy files by hand, delete controls, and watch how the panel reflects it in real time.
  - The panel must make the system's behaviour **visible and explainable within seconds**.

## 3. Users and roles

Design one product with role-based views. Roles come from Keycloak groups:

| Role | Who | Primary jobs |
|---|---|---|
| **Policy admin** | Security engineer | Edit policy (forms + YAML), manage models/connectors/tools, grant access, manage the feed, publish skills |
| **Security analyst** | SOC | Watch live traffic, investigate decision traces, triage incidents, handle approvals, export evidence |
| **Group admin** | Team lead (delegated) | Within their group and org limits: budget split, which allowed models/skills their people get, approvals for their team |
| **Management viewer** | CISO / CFO / board | Posture, risk trends, spend vs budget, savings, adoption, reports |
| **Employee** (self-service) | Any user | Their own usage and spend, their access, their pending approval requests, personal API keys, their personal Automation Insights suggestions |
| **Judge** (demo persona) | Hackathon evaluator | Treat as a power user who explores everything quickly; the panel must reward curiosity |

Deliver a role × view permission matrix.

## 4. Views to design

Start from §12 of `CONCEPT.md`. At minimum:

1. **Overview / posture.**
   - The first screen must answer within 5 seconds: *Are we safe? What is happening right now? What is it costing?*
   - Content: posture score, live decision counts, top risks by OWASP category, spend vs budget, the current policy version with a hot-reload indicator, active incidents and pending approvals.
2. **Live traffic.** A streaming event table: user/agent, inspection point, model, decision, rule IDs, latency, data class, OWASP/ATLAS tags. Fast filters (kept in URL state), pause/resume, saved views.
3. **Decision trace (the hero component).** For one request, show:
   - every stage (normalise → deterministic → similarity → L1 → L2 → risk score → decide → egress) with each control's verdict, score, latency and rule ID;
   - the risk-factor contributions (§6.5);
   - the taint state before and after;
   - redactions shown as typed placeholders;
   - the routing decision with "why this model" (e.g. `auto → corp/loan-memo-pl: task=loan_memo 0.91, data=confidential → local`);
   - policy, grants, feed and model versions;
   - hash-chain integrity.

   It must be readable by a non-expert judge in under 30 s **and** deep enough for an analyst. Design one-click navigation from any rule ID to the exact policy line.
4. **Incidents.** List and detail: severity, status, assignee, linked traces, timeline, notes, evidence export. Include specific incident types: MCP rug pull (show the tool-description diff), budget breach (breaker state), plugin bypass detected, forbidden-model attempt, break-glass access.
5. **Approvals queue.** Pending human approvals with full context: who, what, why held (taint reason / tier / risk score), diff or command preview. Actions: approve, deny, **approve with time-boxed elevation**. Also design the employee's side: "my pending requests".
6. **Users & groups, and User 360.** The User 360 page has three parts:
   - **Effective access:** models, connectors, skills, MCP servers, tools, budgets, preset. Each item shows its **source** (group / user grant / org lock) and expiry. Grants can be edited inline.
   - **Activity history:** sessions, requests with traces, tool/MCP calls, approvals, incidents, spend over time. Shown **redacted by default**, with a **break-glass "reveal raw"** flow that requires a reason and is itself audited.
   - **Risk:** taint events, blocks, anomalies against the group baseline.
7. **Agents.** Identities, scopes, delegation chains, limits, recent runs.
8. **Models & connectors.**
   - Connectors (Ollama, Gemini, OpenAI-compatible) with health, latency, spend and a kill switch.
   - Model registry: tier, prices, allowed data classes, capability tags, artifact-scan status, specialist flag.
   - An access view: who can use what.
9. **Tools & MCP inventory.** Servers and tools, tiers, labels, pinned hashes, drift alerts, quarantine/re-approve, who has access.
10. **Policies.** The most important editing surface:
    - **Forms** for common edits (presets, thresholds, models, group grants, budgets, enabling/disabling controls);
    - a **YAML editor** with schema validation and autocomplete;
    - version history with author and source (`panel` / `file`, so judges' hand edits are visible as "external edit");
    - diff;
    - a **dry-run impact preview** ("would have blocked 14 of the last 500, mostly credit-analysts");
    - an optional second-approver step;
    - rollback;
    - org-locked rules shown as locked;
    - an indicator when GitOps mode is on (the edit becomes a PR).

    Design what happens when someone saves invalid YAML, and when the file changed underneath you (optimistic-lock conflict).
11. **Grants (DB).** Per-user and temporary grants: create, expiry, reason, history of changes.
12. **Budgets & spend.** Hierarchy (org → group → user → agent → session) with live counters; tokens, USD and GPU-seconds; burn forecast; circuit-breaker states with reset; top consumers; savings vs an always-cloud baseline; guard spend as its own line.
13. **Signature feed & artifacts.** Feed version, source, last sync, rules by type, hit counts, add-rule flow (for the live demo). Model artifact scan results (blocked pickle, archive mismatch, etc.).
14. **Guard quality.** Test-suite results per control and per preset:
    - ASR with confidence intervals;
    - FPR per call and per task;
    - defence success rate; wrongly-withheld rate;
    - leak rate per channel; per-layer attribution;
    - judge κ; the shadow judge's estimated miss rate;
    - the strictness matrix.

    The honest framing must be visible: security next to its utility cost.
15. **Performance.** p50/p95/p99 overhead per stage and control, cache hit rate, judge escalation rate, fail-open count.
16. **Automation Insights.** Clusters of recurring tasks (k-anonymity threshold respected; management sees only aggregated patterns), each showing a task card, estimated time/cost and a draft skill (template, input schema, suggested model and controls) → review → **publish as skill**. Also the optional "train specialist model" path and its evaluation (specialist vs general vs Gemini). Plus the employee's personal suggestions.
17. **Audit & exports.** Search, hash-chain verification status, exports (JSONL / OCSF / CSV), and a scheduled management report.
18. **Employee self-service home.** My usage, my access, my requests, my API keys, my insights.

## 5. End-to-end flows to design (wireframe each step)

1. A judge types a prompt containing a PESEL in LibreChat. The analyst sees the event appear live, opens the trace and sees: pseudonymised, routed local, why.
2. Investigate a block: event → trace → rule ID → the policy line → loosen the threshold → dry-run → publish → re-run → the decision changes, and the new policy version shows in the trace.
3. A judge hand-edits the YAML file (or deletes a control). The panel shows an external-edit notification, a diff, and the new version live. Invalid YAML shows a "kept last good version" alert.
4. Grant Jan temporary Gemini access for 7 days from User 360, then see `smart` appear for him; later the grant expires automatically.
5. Revoke `bash` from Anna. Her next OpenCode shell call is blocked; the block appears in her history.
6. An approval arrives: an agent wants `git push` after reading `.env`. Review the preview and the taint reason, then deny, or approve with a 15-minute elevation.
7. An MCP rug-pull incident: review the description diff, keep it quarantined or re-approve and pin the new hash.
8. A budget breach trips the circuit breaker: see the spike and the cause, raise the limit or reset, add a note.
9. Break-glass: an analyst needs raw content. Reason prompt → reveal → the access itself appears in posture and audit.
10. Automation Insight → publish skill → it appears in clients; optionally train a specialist → it gets registered → `auto` starts routing to it → savings appear.
11. A judge adds a signature-feed rule → the next matching request is blocked → the feed hit counter increments.
12. Management exports a monthly report (posture, incidents, spend, savings, adoption).

## 6. Vocabulary (use consistently, with one visual treatment each)

- **Decisions:** `allow`, `monitor`, `redact`, `pseudonymise`, `sanitize`, `downgrade`, `route_local`, `require_approval`, `block`.
- **Presets:** `monitor`, `balanced`, `strict`, `paranoid`.
- **Data classes:** `public`, `internal`, `confidential`, `restricted`.
- **Taint flags:** `untrusted`, `sensitive`.
- **Tool tiers:** `deny`, `must`, `allow`, `confirm`.
- **Inspection points:** ingress, egress, tool call, tool result, embeddings, A2A/memory, artifact load.
- **Tags:** OWASP LLM 2026, OWASP Agentic ASI, OWASP MCP Top 10, MITRE ATLAS.
- **Rule IDs:** e.g. `SEC-PII-01`, `SEC-FLOW-01`, `LOCK-01`.

Decisions must never be encoded by colour alone: always icon + label. Define a semantic colour scale for decisions and severities that works in light and dark mode.

## 7. Design principles

- **Explainability first:** every number and every decision links to its evidence (trace, rule, policy line, version).
- **Show the cost of security:** FPR and utility next to block counts; no vanity "100% blocked" metrics; confidence intervals where they apply.
- **Live by default:** streaming updates, a visible policy version, a hot-reload indicator, an "N new events" pattern instead of jumpy tables.
- **Private by default:** redacted payloads everywhere; raw content only via audited break-glass; Polish identifiers masked (`PESEL ***-**-**123`).
- **Dense but scannable:** a professional SOC/IAM tool, not a marketing dashboard. Avoid the generic "AI dashboard" look (gradient cards, oversized KPIs with no context).
- **Fast for experts:** keyboard navigation, command palette (jump to user, rule, trace ID), filters kept in URL state, copyable IDs.
- **Accessible:** WCAG 2.2 AA, focus states, reduced motion, sensible table behaviour on narrow screens. Desktop-first; mobile only needs to support approvals and the overview.
- **Every view has defined states:** empty, loading, error, no-permission, and "gateway unreachable".
- **Language:** English UI for the hackathon; keep copy i18n-ready (Polish later). Data will contain Polish names and diacritics.

## 8. Small surfaces outside the panel (copy and structure only)

We don't design the OpenCode or LibreChat UIs, but our gateway's messages appear inside them. Design the text and structure of:
- a **block message** (rule ID, plain-language reason, trace ID, "request approval" path);
- an **approval-pending message** and its outcome;
- the **redaction / pseudonymisation notice** and the **"routed to local model"** notice;
- the **degraded-response marker** (budget exhausted → local fallback);
- the **OpenCode device-login** instructions;
- optionally a Keycloak login theme note (branding only).

## 9. Technical constraints

- **Stack:** Next.js + TypeScript. Propose a permissively licensed component system (e.g. shadcn/ui + Tailwind), a chart library, and Monaco for the YAML editor with JSON-Schema validation. Licences must be OSI-permissive; say which you chose and why.
- **Data sources:** gateway REST API + a live event stream (SSE/WebSocket) + Postgres-backed queries. For each screen, list the data it needs (entities and fields) so backend and frontend can agree on an API contract.
- **Auth:** Keycloak OIDC; roles from group claims.

## 10. Deliverables (in this order; stop for my review after step 3)

1. **Information architecture:** sitemap, navigation model, role × view matrix.
2. **Flows:** the 12 flows in §5 as step-by-step wireframe sequences (low fidelity is fine).
3. **Screen specs** for every view in §4: purpose, primary user, data shown, components, actions, states, permissions.
4. **Design system:** tokens (colour incl. decision/severity semantics for light and dark, type, spacing), and a component inventory (decision badge, rule chip, trace stage row, risk-factor bar, taint indicator, version badge, diff viewer, grant row with source and expiry, budget meter with breaker state, metric with CI, live-stream table).
5. **High-fidelity designs** of the priority screens: Overview, Live traffic + Decision trace, Incident detail (rug pull), Approvals, User 360, Policies (form + YAML + dry-run + conflict state), Models & connectors, Budgets, Guard quality, Automation Insights.
6. **Mock data spec:** realistic seed data matching the demo scenarios (§17 of `CONCEPT.md`): users Jan Kowalski (developers) and Anna Nowak (credit-analysts), agent `research-bot`, models (Qwen3, Bielik, Qwen2.5-Coder, a Gemini model, `corp/loan-memo-pl`), rules, incidents, budgets, a week of traffic.
7. **Optional:** a clickable prototype. Before starting, ask me whether the high-fidelity output should be Figma frames or a coded Next.js prototype with mock data.

## 11. Working rules

- Ask clarifying questions only when the answer would change the design materially. Otherwise choose, state the assumption and continue.
- Don't invent features that contradict `CONCEPT.md`. Propose additions separately, marked as suggestions.
- Prioritise ruthlessly. Judges spend minutes, not hours, so mark each screen element as **must** / **should** / **could**.
- Write deliverables to `docs/ux/` (markdown + images or links).
