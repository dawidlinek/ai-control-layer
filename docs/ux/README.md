# Admin panel UX

*Status: deliverables 1–3 done and waiting for review (2026-10-03). Steps 4–7 (design system, high-fidelity, mock data, prototype) start after review.*
*Source of truth: [`../CONCEPT.md`](../CONCEPT.md). Brief: [`../prompts/admin-panel-ux.md`](../prompts/admin-panel-ux.md).*

| # | Deliverable | File |
|---|---|---|
| 1 | Information architecture: sitemap, navigation model, roles, role × view matrix, stack | [01-information-architecture.md](01-information-architecture.md) |
| — | Concept navigation map: sitemap, evidence links, concept § → panel | [navigation-map.md](navigation-map.md) (Mermaid) · [navigation-map.html](navigation-map.html) (interactive: role filter, flow paths) |
| 2 | 12 end-to-end flows as wireframe sequences | [02-flows.md](02-flows.md) |
| 3 | Screen specs for all 18 views + shared data contract + client-surface copy | [03-screen-specs.md](03-screen-specs.md) → [3a Monitor](03a-screens-monitor.md) · [3b Access](03b-screens-access.md) · [3c Govern](03c-screens-govern.md) · [3d Assure](03d-screens-assure.md) |

To view the interactive map, open the HTML file in a browser (no build step, no external requests), or serve the folder:

```bash
python -m http.server 8765 --directory docs/ux
```

## Design in one paragraph

The panel is built around the **evidence chain**: *signal → event → trace → rule → policy line → change*. Every number links towards its evidence and every setting links back to the traffic it affects. The **Decision trace** is the hero: a plain-language summary on top, then "why" (redactions, why this model, risk factors, session taint), then the full pipeline. The **rule chip** is the hub: any rule ID resolves to its exact source (policy line, org lock, feed entry, grant or budget). A global **status bar** keeps the live policy version, external edits, feed version and hash-chain status visible on every screen, so a judge who edits a YAML file sees the panel react within seconds. Security numbers never appear without their cost (FPR, utility, confidence intervals).

---

## Conflicts with CONCEPT.md

The concept wins in every case below. Where the brief or a demo scenario cannot work as written, the design follows the concept and states the fix.

| # | Conflict | What the design does | Fix needed in |
|---|---|---|---|
| C1 | **Roles.** §12 defines three panel roles (admin / analyst / viewer). The brief adds group admin, employee self-service and a judge persona. | Mapped admin → policy admin, analyst → security analyst, viewer → management viewer. Group admin, employee and judge are **additions** built only on concept mechanisms: group admins write DB grants inside the group's YAML ceiling (§11.0); employees see only their own data (personal API keys §5.2, personal insights §14); judge = union of the three concept roles in the demo realm. | CONCEPT §12 (add the roles) if accepted |
| C2 | **Jan already has `smart`.** §11.2 gives `developers` `models: [auto, local-coder, smart]`, but scenario 10 and flow 4 grant Jan `smart` as a temporary exception. | Flow F4 assumes `smart` is **not** in the developers group. | Seed policy: remove `smart` from `developers` (or move Jan to a group without it) |
| C3 | **Anna and `bash`.** `credit-analysts` has no tools in §11.2, and the group block uses `shell` while OpenCode's built-in is `bash` (§9). Revoking `bash` from Anna (scenario 12) needs her to have it first. | Flow F5 assumes `credit-analysts` is granted OpenCode built-ins (`read`, `edit`, `bash`) in `groups.yaml`; revoking for one user creates a user-level deny grant (matches the `-tool bash` example in §11.2). The UI shows one naming scheme: OpenCode built-ins vs MCP tools. | Seed policy + one tool-naming convention (`opencode.bash` vs MCP `shell`) |
| C4 | **"git push after reading `.env`".** §9 says `.env` reads are *always denied*, so the agent cannot have read it. | Flow F6 uses a secret found in a non-denied file (`config/settings.py`, redacted before the model saw it) as the `sensitive` taint source, plus untrusted README content. | Brief / demo script |
| C5 | **Break-glass vs `store_raw_payloads: false`.** The sample policy stores no raw payloads, so "reveal raw" has nothing to reveal. | Break-glass is designed for raw retention **on** (encrypted, short retention, §12), with a defined "raw not retained" state when off. | Demo policy: `store_raw_payloads: true` with short retention, if the break-glass demo is wanted |
| C6 | **Dry-run on redacted history.** §11.1 replays stored requests, but stored payloads are redacted (§13), so detector changes that need the raw text (a new regex, a new NER entity) cannot be replayed exactly. | Impact preview recomputes from stored per-control verdicts and features (thresholds, presets, actions, routing, grants are exact); results for detector changes are marked **approximate**. The deterministic test suite run against the draft covers the gap. | Backend: store per-control features needed for replay |
| C7 | **Adding feed rules from the panel.** §9.2 says the feed is externally managed; the panel is a consumer. | "Add rule" writes to the **demo feed server** (the external-system stand-in) and is labelled as such. The gateway still polls, verifies and swaps. | — (production equivalent would be a local override list in policy; not designed) |
| C8 | **Trace stages.** The brief lists normalise → deterministic → similarity → L1 → L2 → risk score → decide → egress; the concept also has Identity (§4 stage 0) and the Router (§4 stage 3), and approvals add a human stage. | Trace rows: Identity · Normalise · Deterministic · Similarity · L1 · L2 · Decide (incl. risk score) · Route · Approval (only when held) · Egress. | — |
| C9 | **Policy file split.** §11.1 lists `controls/models/groups/budgets/routing.yaml` but not where `global`, `presets`, `org_locks`, `signatures`, `reporting` live. | Assumed in `controls.yaml`; connectors + models + aliases in `models.yaml`. | CONCEPT §11.1 (confirm) |

## Assumptions (chosen, not asked)

| # | Assumption |
|---|---|
| A1 | Desktop-first at 1440 px; usable from 1280; mobile (< 768) supports Overview and Approvals only. Light and dark themes, default = system. |
| A2 | Approval timeout = **auto-deny after 10 min** (fail closed for actions, §3.9), configurable per rule. |
| A3 | Who approves is a rule property (`approver`: `user`, `group_admin` or `security`); `SEC-FLOW-01` → security team. |
| A4 | Posture score = Σ over controls of severity weight × mode factor (enforce 1, monitor 0.3, disabled / removed 0), normalised to 100; severity weights live in policy. The UI always shows the deductions. |
| A5 | Dry-run default window: last 500 decisions or 6 h, whichever is smaller; adjustable. |
| A6 | Grants to cloud models / connectors require an expiry (configurable). |
| A7 | SSE for the live stream (one-way, resumable); the panel never scopes data client-side. |
| A8 | OWASP LLM 2026 / Agentic ASI / MCP Top 10 and ATLAS IDs used in examples (`LLM01`, `ASI02`, `AML.T0010`) are placeholders until checked against the current lists (§20: moving standards). |

## Suggestions beyond CONCEPT.md

Marked *(Sx)* in the specs. None is required for the concept to work; each is cheap and aimed at judges or at closing a gap.

| # | Suggestion | Why | Pri |
|---|---|---|---|
| S1 | **Demo checklist** on the judge's Overview: scenario cards that tick automatically when a matching event is observed, each linking to its trace | Judges arrive with zero preparation; this turns curiosity into coverage of the scored scenarios | C |
| S2 | **Preview as role** (read-only, can only reduce permissions) for judges | Shows the employee and group-admin views without a second login | C |
| S3 | **Second approver** for policy publish (setting) | Brief asks for it; concept only has GitOps PR review | S |
| S4 | **Built-in rule IDs** for engine decisions not in `controls.yaml`: `AUTHZ-MODEL-01`, `AUTHZ-TOOL-01`, `AUTHZ-MCP-01`, `BUDGET-01`, `BUDGET-LOOP-01`, `NORM-01` (malformed call) — chips link to the grant / budget node | §17 scenario 12 expects "blocked with the rule ID"; authz denials have none today | M |
| S5 | **Plugin-bypass detection**: tool results in the conversation with no matching `/v1/decide` record, or LLM requests missing plugin headers → incident | The brief lists this incident type; the concept doesn't define detection | S |
| S6 | **Low-severity alert when a control is removed or disabled** by an external edit (posture drop) | Makes F3 visible even to someone not watching the status bar | S |
| S7 | Employees see **break-glass accesses to their own data** in `/me` | GDPR transparency; strengthens the "proportionate monitoring" story of §12 | C |
| S8 | **Access requests** from employees ("request an exception" in block messages → `/me` → group admin) | Gives the block message a real "what you can do" path | C |

## Next (after review)

1. **Design system** — tokens (decision / severity semantic colours for light and dark, type, spacing) and the component inventory.
2. **High fidelity** of the 10 priority screens.
3. **Mock data spec** matching §17.
4. **Prototype** — needs your answer: **Figma frames or a coded Next.js prototype with mock data?** (Recommendation: coded prototype — the same components become the real panel, and the live-update behaviour, which is most of the judging impression, can't be shown in static frames.)
