# Rogatka Dashboard — implementation handoff

*Written 2026-10-03 at the end of the design session. This file is the **source of truth for the admin panel's final scope and look**. Where it disagrees with `01-information-architecture.md`, `02-flows.md`, `03*-screens-*.md` or `navigation-map.*` (written earlier for an 18-view scope), **this file wins**. For architecture, `docs/CONCEPT.md` still rules, except for the decisions listed in §7.*

| What | Where |
|---|---|
| Interactive design canvas (Claude Design) | https://claude.ai/artifact/TKP38ufQ4YhkrZUHDamisL — page **"Rogatka Dashboard"** holds the final screens. Pages "Screens" and "Overview styles" are earlier explorations, superseded. Private: share it from the canvas Share menu if the implementing person needs access. |
| Design source of each final screen | `docs/ux/design-reference/*.dc.html` (+ `canvas.json`). Prototype format, **not production code**: HTML with inline styles, `{{hole}}` bindings, `<sc-for>` / `<sc-if>`, and a `class Component` whose `renderVals()` holds the exact demo data, colours and interactions. Read them for markup structure, copy, data and tokens. |
| Earlier deliverables | `01-information-architecture.md` (roles, keyboard, URL state, stack), `02-flows.md` (12 flows), `03-screen-specs.md` (data contract §3.1, client message copy §3.2), `03a–d` (old 18-view specs), `README.md` (conflicts C1–C9, suggestions S1–S8) |

---

## 1. Product and brand

- **Product name:** **Rogatka** (Polish for a toll-gate barrier at a town's entrance — every AI request passes the gate). **Admin panel:** **Rogatka Dashboard**. Replace "AI Control Layer" everywhere in UI copy. (`CONCEPT.md` and the earlier UX docs still use the old name.)
- **Logo in use:** option 1 "Szlaban" — a post with a raised, striped boom barrier, white on an accent-coloured rounded tile. SVG (24×24 viewBox, `stroke="currentColor"`, `fill="none"`, round caps):
  ```html
  <path d="M6.5 21V9.5 M3.5 21h6" stroke-width="2.2"/>
  <path d="M6.5 10L21 4" stroke-width="2.6" stroke-linecap="butt" stroke-dasharray="3.4 2.2"/>
  <circle cx="6.5" cy="10" r="2" fill="currentColor" stroke="none"/>
  ```
  Header lockup: 24 px tile (radius 6) + "**Rogatka** Dashboard" ("Dashboard" in muted weight 400). Two alternative marks (R-gate monogram, Checkpoint) are on the canvas board `Logo.dc.html`; the user has not picked a final one.
- **UI language:** English. Demo conversations are in English; data is still Polish (PESEL, IBAN, NIP), so the Polish validators stay.

## 2. Final scope — 12 screens

```
Overview                      /                     Dashboard.dc.html
MONITOR   Traffic             /traffic              LiveTraffic.dc.html      (trace opens in a right sidebar)
          Incidents           /incidents            Incidents.dc.html
          Approvals           /approvals            ApprovalsQueue.dc.html
ACCESS    Users & groups      /users  (tabs People | Groups)
                                                    UsersGroups.dc.html (People tab), UsersGroupsGroups.dc.html (Groups tab, managing a group)
          Grants              /grants               Grants.dc.html
GOVERN    Policies            /policies (tabs Rules | YAML | History)
                                                    PolicyEditor.dc.html
          Models & connectors /models               ModelsConnectors.dc.html
          Tools & MCP         /tools                ToolsMcp.dc.html
          Known threats       /threats (tabs Signatures | Model files)
                                                    FeedArtifacts.dc.html
          Budgets & spend     /budgets              Budgets.dc.html
OPTIMISE  Automation Insights /insights (tabs Repeated tasks | Skills | Specialist models)
                                                    Insights.dc.html
```

**Dropped during the session (do not build):**

| Dropped | Why / note |
|---|---|
| Agents screen | Scope cut. Agents still appear as principals in Traffic, Incidents, Approvals and Budgets (research-bot). Delegation-chain view and per-run limits have no home. |
| Guard quality, Performance, Audit & exports (whole "Assure" section) | Scope cut. **Consequence:** formal requirement 5 ("reporting and audit") and the scoring areas Security reporting (20%) and Self-testing suite (15%) have no dedicated UI. Recommended minimal compensation, **not yet agreed**: a "144 tests · attacks through 2.1% · false alarms 3.1%" line on Policies, and an "audit log ✓ verified · Export" control in the Incidents header. |
| My home (employee self-service) | Scope cut. Employees use only the clients. |
| False alarms, Unused access (Optimise) | Designed, then dropped. Idea worth keeping for later: "This was wrong" link in block messages → appeal signal. |
| Posture score | User found it unclear. Do not show a 0–100 score. |
| "Honest numbers" strip, "Needs a human" section, status strip (gateway / policy version / feed / chain / LIVE) in the header, search box, notification bell, LIVE badge + Pause on Traffic, event counters, separate full Trace page, "Why this model" and "Evidence" in the trace sidebar | Removed for simplicity at the user's request. |

## 3. Global UI patterns

**Shell.** Top bar: logo lockup (left), profile button (right) showing avatar initials, name and role ("Katarzyna Wójcik · Security analyst"). Clicking it opens a menu: name, e-mail, role chips (role + Keycloak group), **Notifications**, **Keyboard shortcuts**, a working **Dark / Light theme switch**, **Sign out**. No search, no bell.
Left sidebar (≥200 px; stacks above content on narrow screens): sections with uppercase 10.5 px headers — *(none)* Overview · MONITOR · ACCESS · GOVERN · OPTIMISE. Active item: accent-tinted background, weight 600. Count badges: Incidents 7, Approvals 3.

**List + sidebar (used on every screen except Overview).**
- Page title (20 px / 600), then a filter row: segmented tabs with counts, filter buttons with ▾, a search field, optional switch on the right.
- Table: header row 10.5 px uppercase muted; rows are links (whole row clickable), compact padding 8 px; mono font for IDs/times/numbers; ellipsis on overflow; horizontal scroll inside the table box on narrow screens. Selected row = accent-soft background + 3 px accent inset bar on the left.
- **Clicking a row opens a right sidebar** (≈ 420–480 px, `flex: 1 1 440px`) next to the list; close with × (list goes full width). Sidebar order: header (ID / name + close) → **one plain-language sentence** → 4–8 key facts in a 2-column grid → type-specific sections → actions.
- Pagination below lists: "Rows per page 25 ▾", ‹ 1 2 3 … N ›.

**The plain-language first line** in every sidebar ("Anna Nowak's prompt contained a PESEL, an IBAN and a name. They were replaced…") is **generated from a template per rule/decision type, filled from the decision record — never by an LLM**. Each rule carries its own reason sentence (the same sentence used in the block messages shown in OpenCode/LibreChat). Deterministic, always true, translatable.

**Vocabulary.**
- Decisions are always **icon + mono label** badges, never colour alone: `allow`, `monitor`, `redact`, `pseudonymise`, `sanitize`, `downgrade`, `route_local`, `require_approval`, `block`. Default style "tint": text colour = decision colour, background = colour at 14% (dark) / 10% (light), border at 32% / 30%. ("outline" and "solid" variants exist as canvas tweaks.)
- Severity chips: `high`, `medium`, `low` (+ `critical`), icon + label.
- Rule chips: mono 11–12 px, raised background, strong border, link to the rule in Policies.
- Masked identifiers: `PESEL ***-**-**123`, `PL** **** … 2874`, placeholders `<PERSON_1>`, `<PESEL_1>`, `<IBAN_1>`, `‹SECRET:api_key›` (placeholder chips use the `pseudonymise` tint).

**Interaction rules.** Every action that changes policy says so ("Saved as policy v9", "writes groups.yaml"). Publish/approve/grant flows show the result inline in the sidebar (green status box). Deny is the primary (solid red) button in approvals. Org-locked items are read-only with a lock icon.

## 4. Design tokens (from the prototypes)

**Fonts:** IBM Plex Sans (400/500/600) for UI, IBM Plex Mono (400/500) for IDs, numbers, code, decision labels. Base 13 px / line-height 1.45.

| Token | Dark (default) | Light |
|---|---|---|
| bg | `#0e1013` | `#f3f4f6` |
| surface (cards, sidebar, table) | `#15181c` | `#ffffff` |
| raised | `#1c2025` | `#f6f7f9` |
| inset (inputs, code) | `#101215` | `#eceef1` |
| border | `#272c33` | `#dce0e5` |
| strong border | `#3a414a` | `#c3c9d1` |
| text | `#e7e9ec` | `#14171b` |
| muted text | `#9ba4ae` | `#56606b` |
| accent | `#4C8DFF` | accent darkened 32% (`#3460ad`) |
| on-accent text | `#0e1013` | `#ffffff` |
| accent-soft (selection) | accent @ 16% | accent @ 12% |

Decision / severity colours (dark → light): allow `#4ade80 → #15803d` · monitor `#a3b1c2 → #475569` · redact `#d8a4fe → #7e22ce` · pseudonymise `#b4a0ff → #6d28d9` · sanitize `#2dd4bf → #0f766e` · downgrade / medium `#fbbf24 → #a16207` · route_local `#7cb4ff → #1d4ed8` · require_approval `#fb923c → #c2410c` · block / high `#f87171 → #b91c1c` · critical `#fb7185 → #be123c` · low = monitor.
Decision icons are 24×24 stroke paths — copy the `DEC` and `SEV` objects from any `design-reference/*.dc.html` script.

Radii 4 (chips) / 6 (buttons, inputs) / 8 (cards, sidebars). Buttons ≥ 32 px high (primary 34–36). Section labels 11 px / 600 / uppercase / letter-spacing .08em / muted.

## 5. Screens

Data shown below is the demo data in the prototypes (§6). Field lists name what the API must provide.

### 5.1 Overview (`Dashboard.dc.html`)
Two columns: **left "What is happening?"** (full height) · **right top "Are we safe?"**, **right bottom "What is it costing?"**. Range switch 15m / 1h / 24h / 7d.
- *What is happening?* — "1 284 decisions · last 15 min"; stacked bar chart per minute by decision (allow muted); legend chips with totals (allow 1 102 · pseudonymise 71 · route_local 64 · require_approval 3 · block 44); "Notable now": last 5 non-allow events, one plain sentence each + decision chips → Traffic.
- *Are we safe?* — "7 open incidents" + severity chips (1 high · 2 medium · 4 low) → Incidents; "Top risks · 24 h": 5 OWASP categories with count + bar (LLM02 128, LLM01 41, ASI02 9, ASI04 3, MCP 1) → Traffic filtered.
- *What is it costing?* — "3.12 / 5.00 USD today" with bar and forecast tick ("forecast 4.40 by 24:00"); GPU-seconds 1 912 / 3 600; table **Model · Tokens in / out · Usage** (usage = USD for cloud, GPU-s for local), thin share bar under each model; "Open budgets →".
- No posture score, no header status strip.

### 5.2 Traffic (`LiveTraffic.dc.html`)
A **paged list of past requests** (not a live stream). Filters: **Last 24 hours ▾** (time range, highlighted), Decision, Who, Point, More filters, search ("Rule, trace ID or text"), **Hide allowed** switch.
Columns: Time (+ "today") · Who (+ client · group) · Point (prompt / answer / tool call / tool result / tool list) · Model / tool · Decision chips · Rule · ›.
**Row click → trace sidebar:**
1. Trace ID + copy, close.
2. Decision chips, plain sentence.
3. Facts: Who, When, Point, Model / tool, Data class, Risk score.
4. **"Open full conversation →"** (LibreChat) or **"Open full session →"** (OpenCode / agent), with "c_51a8 · LibreChat · 6 messages · started 13:58". (The conversation view itself is not designed.)
5. **What the model saw** — only when content was changed (placeholders; removed key; removed injected sentence) + one note line.
6. **How the decision was made** — vertical timeline of the steps **Identity → Normalise → Rules → Similarity → Classifier → Judge → Decide → (Approval) → Route → Output**; each with a one-line result and ms; steps that changed something are bold with a filled accent dot; click a step to expand the controls that ran (rule chip, finding, score vs threshold, verdict chip).
7. Actions: Replay with live policy · Add to incident.
12 demo events, each with its own sentence and changed steps (see `EVENTS` in the prototype).

### 5.3 Incidents (`Incidents.dc.html`)
Tabs Open 7 · Resolved 2 · All 9; filters Severity, Type, Assignee; search; **Assigned to me** switch. Columns: Severity · Incident (title, then "ID · type · who") · Status (Open / Triaged / Resolved) · Assignee · Opened (age).
Sidebar: severity + ID + type → title + summary → status button, **Assign to me** (if unassigned), opened time → **type-specific evidence**:
- *MCP rug pull*: server › tool, approved hash vs new hash, description diff with injected lines highlighted, finding chips ("hidden instruction", "reads ~/.ssh", "“do not tell the user”", "new parameter: context"), "0 calls since the change".
- *Budget breach*: breaker states closed → **OPEN** → half-open (countdown), full GPU-s meter, cause with rule chip.
→ **Do something** (type-specific buttons, first one primary: Keep quarantined and close / Re-approve new version… / Remove server; Reset breaker / Raise limit… / Keep blocked; Open approval; Grant access…; Acknowledge / Flag as inappropriate) → **Linked traces** → **Notes and timeline** (add note, events with coloured dots: system-bad red, person accent, system muted) → Export evidence.

### 5.4 Approvals (`ApprovalsQueue.dc.html`)
Tabs Waiting 3 · Decided · 24 h 3 · All; filters Approver, Who, Tool; note "Requests nobody answers are denied after 10 minutes". Columns: Request (mono action + ID) · Who · Why it was held · Approver (Security team / Team lead) · Time left (urgent one highlighted).
Sidebar: `require_approval` chip, ID, held time, **auto-deny in 9:40** pill → plain sentence + facts (Session, Risk score, Data class, Trace) → **What it wants to do**: exact command, details with red-flag chips ("not a company remote", "secret found", "outside @corp.example"), preview (git diff with masked key / e-mail body with placeholders / terraform plan) → **Why it was held**: rule chip + numbered reasons with timestamps linking to Traffic (Rule of Two: ① untrusted ② sensitive ③ external) + "Open full session →" → **Decision**: reason input (required to approve), **Deny** (primary, solid red), **Approve once**, **Approve for 5m | 15m | 60m** ("allows only this exact action"). After deciding: status box explaining the consequence ("shows as an elevation on Jan Kowalski's access page"), the row flips to approved/denied.

### 5.5 Users & groups (`UsersGroups.dc.html`, `UsersGroupsGroups.dc.html`)
Tabs **People 41 | Groups 4**; "Open Keycloak ↗" (people and membership are created in Keycloak).
- **People** columns: Person (avatar, name, e-mail) · Group · Preset · Last active · Requests 7 d · **Tokens in / out 7 d** · Blocks · ›. Sidebar: avatar, name, "e-mail · group · preset", "7 days: N requests · X / Y tokens in / out" → **Access** list (kind · item with state icon · source line "group developers · groups.yaml L20" / "your grant g-0412 · “Gemini pilot” · ≤ internal" / "user deny g-0415 · overrides group" / "approved apr-0193 by k.wojcik" · expiry · inline Grant / Revoke / Restore) with **+ Grant** (inline form: data classes with LOCK-01 note, expiry 1 d / 7 d / 30 d, reason) → **Their clients see** (the person's model list; new grant shows "smart (new)") → **Recent activity** (4 rows with decision chips) → "All activity in Traffic →", "Grant history →".
- **Groups** columns: Group · Members · Preset · Models · **Tokens in / out today** · Spend today. **Sidebar = group management**: "Keycloak group · N members · tokens today"; note "Who is in the group comes from Keycloak. What the group may use is set here and saved to groups.yaml as a new policy version." Controls: **Strictness** segmented (monitor / balanced / strict / paranoid) · **Models** toggle chips (✓ allowed / + not) · **Tools** toggle chips · **Cloud models may get** (nothing / public / internal; "confidential and above: never (LOCK-01)") · **Daily budget** − / + · change summary bar ("3 changes: + smart (gemini), − bash, budget 5 → 6 USD · written to groups.yaml") with Discard / **Save as policy v9** → "v9 is live" status · **Members** list + "Manage in Keycloak ↗".

### 5.6 Grants (`Grants.dc.html`)
Subtitle "personal and temporary access on top of group rules"; **+ New grant**. Quick-filter pills: Active · Temporary · Expiring in 24 h · Denials · From approvals; search. Columns: Who · Grant (effect chip allow / deny / budget + what) · Limits · Expires (orange when < 24 h) · Reason. Sidebar: plain sentence, facts (Who, Grant, Limits, Expires, Reason, Created), org-lock ceiling note when relevant, **History** (created / expired / revoked), actions Extend… (primary) / Edit… / Revoke (red) or "Grant again…" when expired, "Open person →". **New grant** form in the sidebar: person or group, what, data classes, Allow / Deny, expiry 1 d / 7 d / 30 d / never, reason, ceiling check, Create grant.

### 5.7 Policies (`PolicyEditor.dc.html`)
Header "live v8 · loaded 14:02 from the file (edited on disk)". Tabs **Rules | YAML | History**.
- **Rules**: Rule (lock icon for org locks) · What it does (plain) · Action chip · Mode (enforce / monitor / always) · Hits 24 h. Sidebar: rule + type, plain explanation, facts, org-lock note if locked; for `SEC-PI-01` an editable **Setting** ("Block when the injection score is at least [− 0.80 +]") → "If you publish this" box: impact sentence ("Would have let through 3 of the last 500 requests that were blocked…"), attacks through 2.1% → x, false alarms 3.1% → y, tests, required note, Discard / **Publish as v9** → "v9 is live" and the header updates. **In the file**: the YAML line, "Open in YAML", "See its hits in Traffic".
- **YAML**: read view of `controls.yaml` with syntax colours, line numbers, org-lock lines tinted with lock icon, the selected rule's line highlighted. (Production: Monaco + JSON-Schema validation, see `01 §1.6`.)
- **History**: Version · When · who · Source (`file` accent / `panel` / `rollback`) · Change. Sidebar: change sentence, diff, "Roll back to this version…", "First requests on vN →".
- Not designed but required by `CONCEPT.md §11.1`: invalid-YAML-on-disk banner (keep last good version), optimistic-lock conflict, GitOps mode, second approver. Specs in `03c` §10 still apply.

### 5.8 Models & connectors (`ModelsConnectors.dc.html`)
Connector cards (name, kind, **on/off switch**, health, response time p95, today's usage) + "+ Add connector". Switching Gemini off shows: "Gemini is switched off. Requests for smart now go to local models and their answers are marked as degraded. Saved as policy v9." Model table: Model (+ role) · Runs on (local / cloud chip) · Data it may get · Requests · Usage today · File check. Sidebar: plain description, facts (connector, alias, price, data classes, tags, limits), **Who can use it** (groups / grants), **How auto picks it** (share of auto requests + reasons with counts), **Model file** scan line, Edit in Policies / Turn off model.
**⚠ Update the demo data to the new lineup (§7.1)** — the prototype still shows Bielik / Qwen2.5-Coder / Qwen3 8B / corp/loan-memo-pl. Consider adding a small "Guard models" section (classifier, NER, embeddings, judge).

### 5.9 Tools & MCP (`ToolsMcp.dc.html`)
Tabs All · Quarantined · Need approval; filters Server, Who can use it; "+ Add MCP server". Columns: Tool (+ server) · Status (approved / quarantined / built-in / denied) · Rule (allowed / needs approval / denied) · Who can use it · Calls 24 h. Includes OpenCode built-ins (`bash`, `webfetch`) checked via `/v1/decide`. Sidebar: plain description, facts, labels, **Changed since approval** diff for quarantined tools (→ incident), **Approved versions** (hash, when, what), actions.

### 5.10 Known threats (`FeedArtifacts.dc.html`)
Status bar: feed version, checksum verified, last sync, source "feed.corp:8080 · every 30 s", Sync now. Tabs **Signatures | Model files**; **+ Add rule** (demo).
- Signatures: Rule · What it catches (+ source / CVE) · Looks at (package / answer text / tool description / URL / shell command) · Action · Hits 24 h. Sidebar: plain explanation, pattern (mono), facts (looks at, action, severity, ATLAS/OWASP tags, source, expiry), recent hits → Traffic.
- Add rule form (writes to the **demo feed server**, which stands in for the external feed): ID, looks at, pattern, action → Publish → bundle version +1, new rule at the top.
- Model files: File · Format · Result (passed / blocked) · Finding. Sidebar: result, explanation, technical detail (opcode / header), sha256, scan time.

### 5.11 Budgets & spend (`Budgets.dc.html`)
Today / This month switch; three summary cards (spent vs limit with forecast; local GPU time; saved vs sending everything to the cloud). Tree table: Who (indented: company → groups → people / agent → session) · Used of limit (bar: accent, orange ≥ 80%, red when breaker open) · Forecast · Breaker (closed / alert at 80% / open · 4:12). Sidebar: used, limit, forecast; spend per hour bars; **By model**; "Limit set in budgets.yaml Lx / grant g-…"; Reset breaker (when open) / Change limit… / Requests in Traffic →. Default selection: research-bot session `s_77c1` with the open breaker.

### 5.12 Automation Insights (`Insights.dc.html`)
Subtitle: "Found in masked prompts, on local models. Patterns used by fewer than 5 people are hidden. People see only their own suggestions." Tabs **Repeated tasks | Skills | Specialist models**.
- Repeated tasks: task · group · people · how often · time it takes · status (new / published). Sidebar: task card (plain description + facts), **Draft skill** (name, template with `{placeholders}`, inputs, model, rules), Try with an example / **Publish skill** / Dismiss → "skill/… is live for <group>… Saved as policy v9".
- Skills: skill · available to · runs 30 d · cost per run before → now.
- Specialist models: steps (examples → trained offline → scanned → registered → evaluated → used by auto) + evaluation table. **Revisit** with the new lineup — the loan-memo specialist was built on Bielik.

## 6. Demo data and personas (as used in the prototypes)

- **Signed-in admin:** Katarzyna Wójcik (`k.wojcik`, Security analyst, group security). Other admin: Magdalena Zielińska (`m.zielinska`).
- **People:** Jan Kowalski (developers, OpenCode, device dev-jk-01), Anna Nowak (credit-analysts, LibreChat + OpenCode), Piotr Zieliński (developers), Marta Lis (credit-analysts), Tomasz Wiśniewski (credit-analysts), Ewa Grabowska (operations).
- **Groups:** developers (14, balanced, 5 USD/day), credit-analysts (9, strict, 2 USD/day), operations (12, balanced, 1 USD/day), security (6, strict, 1 USD/day).
- **Agent:** research-bot (acts for Anna; session `s_77c1` loops on web.search → breaker open, inc-0058).
- **Key stories:** Anna's PESEL+IBAN prompt (`tr_8f3a2c`, pseudonymise + route_local); Jan's `git push` after an untrusted README + a file with an API key (`apr-0193`, SEC-FLOW-01); `pip install litellm==1.82.8` blocked by FEED-PKG-0007; docs-search MCP rug pull (inc-0057); Jan's 7-day Gemini grant (`g-0412`); bash revoked for Anna (`g-0415`); external edit of `controls.yaml` → v8; threshold change → v9.
- **Rule IDs used:** SEC-PII-01, SEC-SECRET-01, SEC-PI-01, SEC-SAFE-01, SEC-EXFIL-01, SEC-FLOW-01, SEC-MCP-01, LOCK-01, LOCK-02, FEED-PKG-0007 / -0012 / -0142, FEED-EXF-0044, FEED-MCP-0009, FEED-URL-0031, FEED-CMD-0102, and engine-level IDs AUTHZ-MODEL-01, AUTHZ-TOOL-01, BUDGET-LOOP-01 (suggestion S4 — not yet in `CONCEPT.md`).
- **Seed-data fixes still needed** (README C2–C4): remove `smart` from the developers group in the seed policy (so Jan's grant matters); give credit-analysts the OpenCode `bash` tool and use one tool-naming scheme; the agent story must not read `.env` (always denied) — use a secret in another file.

## 7. Decisions and answers from the session (deltas to `CONCEPT.md`)

### 7.1 Model lineup (English demo)
| Role | Model | Where | Gets |
|---|---|---|---|
| Fast cloud (default for normal work) | **Gemini Flash** | Gemini API (paid key) | public, internal |
| Strong cloud (router picks by complexity) | **Gemini Pro** | Gemini API | public, internal |
| Local (all confidential work, confidential sessions, confidential repos) | **Qwen ~27B** — user wrote "qwen 3.8 27B"; **exact Ollama tag still to confirm** | Ollama | all classes |

No Bielik (chat or guard). GPU: a 27B model at 4-bit needs ~17–20 GB VRAM plus context → plan ≥ 24 GB, or two GPUs if the judge runs separately.

**Supporting models (local):**
- Prompt-injection classifier — Apache-licensed DeBERTa injection model, ONNX on CPU (**required**).
- PII NER — Presidio + a GLiNER PII model (**required**; licence of the checkpoint to verify).
- Embeddings — bge-m3 or a small English model (e.g. nomic-embed-text), local only (embeddings count as outbound data). Needed for the similarity check against known attacks and for Automation Insights.
- L2 judge — **reuse the local Qwen 27B** with judge prompts (tool-call alignment, contextual privacy, injected-span removal, harder PII); runs only on ~5–6% of requests.
- Content safety — optional (e.g. Qwen3Guard small) or covered by the judge.
- Flash vs Pro vs local routing — rules (complexity bands, sensitivity, budget) + embeddings; no extra model.

The fine-tuned Polish classifier / `corp/loan-memo-pl` specialist from `CONCEPT.md §15` is out of the demo unless rebuilt on a Qwen base.

### 7.2 Session security label (inspired by OpenAPPA, https://www.openappa.com/how-it-works)
OpenAPPA keeps a per-session label (audience/confidentiality × trust) that can only get stricter, and checks every action against it. Adopt for Rogatka:
- Each session carries a **high-water mark**: highest data class seen + trust (trusted / untrusted). It never goes down within a session.
- **New rule `SEC-SESSION-01`:** once a session is `confidential` (threshold editable: confidential / restricted), **every later request in that session is routed to local models only** — closes the gap where a later message without PII would send the whole (pseudonymised) history to Gemini.
- UI (not yet drawn): label chip on Traffic rows and in the trace sidebar ("Session confidential since 14:03 · local only"); one-line notice in the client ("This conversation now stays on company servers"); rule in Policies.
- Mapping of OpenAPPA remedies: authorities → approvals with time-boxed elevation; sanitizers → `sanitize` / redaction; subagents → quarantine mode (stretch).

### 7.3 Policy definition
Policies are YAML in `policy/` (controls, models, groups, budgets, routing — org locks, presets, signatures settings assumed in `controls.yaml`). Edit by hand or in the panel; both create a version, validated against a JSON Schema, hot-reloaded. Panel entry points: Policies (rules, YAML, history), Users & groups → Groups (group rules), Grants (per-person DB exceptions), Models & connectors, Budgets. Org locks are read-only in the panel.

### 7.4 OPA (recommendation, not confirmed)
Use Open Policy Agent for the **deterministic authorization step only** (model allowlist, tool tiers, grants, data-class ceilings, org locks, Rule of Two, session label): YAML stays the editable source and is compiled into OPA data/Rego. Gains: recognised policy-as-code standard, `opa test` unit tests, decision logs, signed bundles, sub-ms decisions. Costs: Rego for anyone editing raw rules; sidecar or embedded engine (e.g. WASM / regorus). Content inspection (PII, injection) stays in the Python pipeline.

### 7.5 Known threats
Not hand-written in normal use. A small feed service compiles a signed bundle from OSV / GitHub advisories (package versions), CISA KEV (exploit URLs), gitleaks (secret formats), published prompt-injection and MCP attack sets; Rogatka polls every 30 s, verifies, swaps atomically, keeps the last good bundle on failure. Hackathon scope: curated seed bundle (a few hundred rules) + one or two importers; large injection datasets feed the **similarity** corpus rather than regex rules. Manual "Add rule" is for local cases and the live demo. Difference from Policies: Policies = our behavioural rules (who may do what, where data may go); Known threats = externally maintained fingerprints of specific known-bad artefacts (like antivirus signatures vs firewall rules).

### 7.6 MCP servers added in the panel
Clients connect only to Rogatka's MCP proxy (fixed in the managed client config). The proxy returns a **personalised `tools/list`**; when an admin approves/grants a server, its tools appear on the next list refresh, and the proxy sends `notifications/tools/list_changed`. **To verify:** whether OpenCode and LibreChat reload on that notification or only on restart.

### 7.7 Secret management
- Provider keys (Gemini): only in the gateway (Docker secrets / env for the hackathon; Vault or cloud KMS in production); never in policy files or clients; panel shows "credential present / missing" only.
- MCP server credentials (GitHub, Jira): held by the proxy / server, injected per call; never sent to models; no token passthrough.
- Users: Keycloak tokens; personal API keys stored hashed, shown once.
- Secrets inside traffic: SEC-SECRET-01 blocks/redacts them in prompts, tool results and diffs.

### 7.8 Where AI ("decision") models are used
Classifier step (injection score, sensitivity, task/complexity), NER for names, similarity (embeddings), judge step (only when uncertain or risky), shadow sampling of 5% of allowed traffic, Automation Insights task cards. **They can only make a decision stricter, never grant access.** Visible in the panel as the Classifier and Judge steps of a trace.

## 8. Data the panel needs (summary)

Full TypeScript entities and endpoints: `03-screen-specs.md §3.1`. Additions / changes from this session:
- `DecisionEvent`: add `sessionLabel { dataClass, trust, since }`; client conversation/session reference `{ kind: 'conversation'|'session', id, client, messageCount, startedAt }`; `summary` sentence; `changedSteps { step: resultText }`.
- Users: `tokensIn7d`, `tokensOut7d`, `requests7d`, `blocks7d`. Groups: `tokensInToday`, `tokensOutToday`, `spendToday`, editable `preset`, `models[]`, `tools[]`, `maxCloudDataClass`, `dailyBudgetUsd`.
- Overview cost by model: `{ model, tokensIn, tokensOut, usdOrGpuS, share }`.
- Group edits and every panel change go through the policy service (draft → validate → impact → publish) and return the new version.
- Removed screens' endpoints (quality runs, performance metrics, audit search/export UI, `/me`) are not needed by the panel; the audit log and test suite themselves still exist in the backend.

## 9. Stack (unchanged from `01 §1.6`)
Next.js (App Router) + TypeScript · shadcn/ui on Radix + Tailwind · TanStack Table/Virtual/Query · Recharts · Monaco + monaco-yaml · nuqs (URL state) · cmdk (optional, no search box in the header now) · react-hook-form + zod · Auth.js with Keycloak (roles from group claims) · next-intl · Lucide (or the custom decision icons above) · SSE for live updates. All MIT/ISC.

## 10. Open questions for the implementation session
1. Exact Qwen model/tag and GPU available.
2. OPA: adopt for the authorization layer or keep a Python rules engine?
3. Re-add the two minimal reporting elements (Policies test line, Incidents audit/export) to cover Security reporting and Self-testing scores?
4. Roles: the panel was designed for an analyst/admin; group admin, management viewer, employee and judge personas from `01 §1.4` are out of scope now — confirm which Keycloak roles the panel checks.
5. Conversation/session view behind "Open full conversation →" — build, or link to Traffic filtered by session?
6. Final logo (option 1 is in use).
7. Specialist model (`auto` → specialist) — drop for the demo or rebuild on Qwen?

## 11. Suggested build order
1. Shell + tokens + decision badge / rule chip / list-and-sidebar components.
2. **Traffic with the trace sidebar** (the hero; most demo scenarios are explained here).
3. Policies (Rules + YAML + History, publish → hot reload) — judges edit YAML live.
4. Users & groups (People + Groups management) and Grants.
5. Approvals, then Incidents (rug pull + breaker evidence).
6. Models & connectors (kill switch), Tools & MCP, Known threats (add-rule demo).
7. Budgets & spend, Overview.
8. Automation Insights.

Check each against the demo scenarios in `CONCEPT.md §17` and flows F1–F12 in `02-flows.md` (ignore steps that use dropped screens).
