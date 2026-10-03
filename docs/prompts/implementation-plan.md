# Prompt: Implementation orchestration plan

> Paste everything below the line into a new session started in this repository. This session (the **orchestrator**) owns architecture, contracts, integration and review. Implementation work is delegated to **Sonnet subagents** (`Agent` tool, `model: "sonnet"`, `isolation: "worktree"`), run in parallel where the plan allows.

---

You are the **lead engineer and orchestrator** for the AI Control Layer hackathon project. Build it according to `docs/CONCEPT.md`, the source of truth (read it fully first). The admin-panel UX is designed in a separate session; its output lands in `docs/ux/`. Use it if present; otherwise use §12 of the concept and keep the panel work behind clear interfaces so the design can be applied later.

## 0. Operating model

- **You (orchestrator):**
  - Phase 0 (foundations and contracts) yourself;
  - writing subagent briefs;
  - merging worktrees;
  - running the full test suite;
  - reviewing security-critical code yourself (policy evaluator, taint/IFC engine, authN/authZ, grants resolution, audit hash chain, `/v1/decide`);
  - checkpoint reports.
- **Subagents:** `Agent` with `model: "sonnet"`, `isolation: "worktree"`, `run_in_background: true`. Launch **all independent tasks of a phase in one message** so they run concurrently. At most ~5 at a time.
- **One owner per directory per phase.** Briefs list the paths a subagent may write; everything else is read-only for it. Shared contracts change only through you.
- **Checkpoints are hard stops.** At the end of each phase, run the checkpoint protocol (§6) and **wait for my approval** before starting the next phase.
- If I explicitly say "use a workflow", you may run a phase as a `Workflow` script instead of individual `Agent` calls. Otherwise use `Agent`.

## 1. Confirm before starting (ask me in one batch)

1. Hackathon duration and team size (sets how much of phases 4–5 we keep).
2. Demo hardware: GPU/VRAM, OS (decides model sizes; Windows host vs Linux containers).
3. Is the UX session's output in `docs/ux/` yet?
4. Do I have a Gemini API key in `.env` (`GEMINI_API_KEY`)? Never commit it.
5. Defaults OK? Python 3.12 + `uv` (hash-locked deps), Postgres, pnpm, docker-compose.

## 2. Fixed technical decisions (don't re-litigate; subagents must follow them)

**Gateway (Python 3.12)**
- FastAPI, uvicorn, httpx, Pydantic v2, `ruamel.yaml` (round-trip), `watchfiles`, SQLAlchemy 2 (async) + asyncpg + Alembic, prometheus-client, OpenTelemetry SDK, official `mcp` SDK.
- Presidio + GLiNER, onnxruntime, yara-python (or RE2) for detection.
- Dependencies via `uv` with a hash-pinned lockfile. **LiteLLM is not a dependency.**

**Other components**
- **Panel:** Next.js (App Router) + TypeScript, shadcn/ui + Tailwind, Monaco (YAML + JSON Schema), a permissive chart library, Keycloak OIDC (e.g. Auth.js).
- **Identity:** Keycloak with `deploy/keycloak/realm-export.json` imported at start (realm, groups, demo users, clients: `gateway`, `panel`, `librechat`, `opencode` device flow, one client-credentials client per agent).
- **Clients:** OpenCode (managed config + our plugin, in a locked container), LibreChat (OIDC → Keycloak, custom endpoint → gateway).
- **Models:** Ollama. Model names come only from config; nothing is hardcoded. A deterministic **mock LLM** connector exists for tests.
- **Policy:** YAML in `policy/`, split per area; JSON Schema generated from the Pydantic models. Per-user grants in Postgres.

**Cross-cutting rules**
- Every decision emits an audit record (schema in `contracts/`). No raw sensitive values in logs.
- Every control declares `id`, `stages`, `cost_tier` (`deterministic` | `similarity` | `l1` | `l2`), `fail_mode`, `timeout_ms`.

## 3. Repository layout (create in Phase 0)

```
contracts/          # THE shared contracts: JSON Schemas + OpenAPI + examples (owned by orchestrator)
  decision.schema.json  event.schema.json  policy.schema.json  decide-api.openapi.yaml
  admin-api.openapi.yaml  feed-bundle.schema.json  examples/
gateway/            # Python package `acl` (src layout)
  src/acl/
    api/            # OpenAI-compatible endpoints, /v1/decide, admin API, SSE stream
    engine/         # pipeline, InspectionContext, Verdict, risk scoring, decide
    controls/       # one module per control family (normalise, pii, secrets, egress, signatures, similarity, classifiers, judges, taint, tools)
    policy/         # models, loader, watcher, compiler, versioning, writer (single writer)
    identity/       # JWT validation, API keys, JIT provisioning, grants resolver
    routing/        # router, connectors (ollama, openai_compatible, mock), specialists
    budgets/        # ledger, meters, breaker, loop detection
    mcp_proxy/      # MCP interception
    audit/          # hash-chained JSONL, OCSF mapping, Postgres index, OTel
    feed/           # bundle sync, verify, compile, atomic swap
    artifacts/      # model scanner
    insights/       # workflow miner worker
  tests/            # unit tests next to the package
panel/              # Next.js admin panel
plugins/opencode-guard/   # TypeScript OpenCode plugin
mcp-servers/        # governed tool server + demo servers: mail, files, core-banking DB, rug-pull, web
feed-server/        # stand-in for the external signature system
policy/             # controls.yaml models.yaml groups.yaml budgets.yaml routing.yaml + schema link
deploy/             # docker-compose.yml, keycloak/, librechat/, opencode/ (managed config, Dockerfile), ollama/ (model list), .env.example
tests/              # system tests: cases/*.yaml, e2e/, mutation/, perf/, redteam/, oracle/ (independent leak oracle, attacker sink)
training/           # WCSS fine-tuning (classifier + specialist LoRA), eval scripts
docs/               # CONCEPT.md, ux/, prompts/, checkpoints/
CLAUDE.md           # conventions + commands (create in Phase 0)
Makefile            # up, down, demo, test, test-live, bench, seed, lint
```

## 4. Phases, tasks and checkpoints

Legend: **[O]** = orchestrator does it; **[S]** = Sonnet subagent. Each [S] task lists its owned paths.

### Phase 0: Foundations and contracts [O], sequential

1. Scaffold the layout, `CLAUDE.md` (commands, structure, conventions, "never commit secrets", test commands), `Makefile`, `.gitignore`, `.env.example`.
2. **Contracts** in `contracts/`:
   - `InspectionContext`, `Verdict`, `Decision`;
   - the audit/event record (fields per concept §13);
   - policy schema (generated from the Pydantic models in `gateway/src/acl/policy/models.py`);
   - `/v1/decide` OpenAPI;
   - admin API OpenAPI (policy CRUD + dry-run, grants, users, events query, SSE, incidents, approvals, budgets, models/connectors, feed, artifacts, insights, metrics);
   - feed bundle schema;
   - example payloads for each.
3. Control plugin interface + registry skeleton; a pipeline that runs zero controls and returns `allow`.
4. `deploy/docker-compose.yml`: postgres, keycloak (realm import), ollama, gateway (hello + health), panel (hello), feed-server (stub). Healthchecks everywhere.
5. Seed policy files that validate against the schema; mock LLM connector.
6. Test harness skeleton: `pytest` config, YAML case runner, deterministic mode flag.

**CP0:**
- `make up` starts everything healthy;
- `make test` runs (even with ~0 tests);
- contracts are reviewed **by me**.

### Phase 1: Core pipeline, 5 parallel tasks

| Task | Owner paths | Scope | Acceptance |
|---|---|---|---|
| **1A Gateway core** [S] | `gateway/src/acl/{api,engine,routing,audit}` (except identity) | OpenAI-compatible `/v1/chat/completions` (streaming + non-streaming), `/v1/embeddings`; connectors: ollama, openai_compatible (Gemini), mock; pipeline execution with stage ordering, parallel controls, early exit, timeouts, fail modes, content-hash cache; audit JSONL hash chain + Postgres index; SSE event stream | Request via mock → audit record valid against schema; chain verifies; tampering detected; streaming works |
| **1B Policy engine** [S] | `gateway/src/acl/policy`, `policy/` | Pydantic models → JSON Schema export; loader; watcher with validate → compile → atomic swap; last-good fallback; version snapshots (source `file` / `panel`); single writer with ruamel round-trip + optimistic locking; org locks; dry-run replay API over stored events | Hot-reload test (<2 s); invalid YAML keeps last good + alert event; panel write preserves comments; stale-version write rejected |
| **1C Identity & grants** [S] | `gateway/src/acl/identity`, `deploy/keycloak` | Keycloak JWT validation (JWKS), API keys (hashed), JIT user provisioning, grants table + Alembic migration, effective-access resolver (org locks → group → user, expiry), personalised `/v1/models`, 403 + incident on forbidden model | Test matrix: valid / expired / forged token; revoked key; expired grant; override can't exceed lock |
| **1D Deterministic controls + feed** [S] | `gateway/src/acl/{controls/normalise,controls/pii,controls/secrets,controls/egress,controls/signatures,feed}`, `feed-server/` | NFKC / zero-width / encodings; PII T0 with validators (PESEL, NIP, REGON, PL ID card, IBAN mod-97, Luhn); secrets rules; pseudonymise vault with allow-list restore + placeholder check; redact; markdown/URL egress; signature engine + signed bundle sync + atomic swap; seed IOCs per concept §9.2 | Paired positive/negative YAML cases per control (≥5 each); adding a feed rule blocks the next request |
| **1E Test harness & oracles** [S] | `tests/` | YAML case runner (expected decision, rule ID, redaction); independent leak oracle (decodes hex/b64/substrings, shares no code with gateway); attacker sink service; scripted agent; strictness-matrix runner; JUnit + JSON metrics summary | `make test` runs deterministic mode in <60 s; the oracle detects a canary in encoded output |

**CP1 (demo slice):**
- A prompt with a PESEL via the API (as a Keycloak user) → pseudonymised → routed local → audit record with full trace → visible on the SSE stream;
- hot reload and feed-rule tests pass;
- forbidden model → 403.

### Phase 2: Agents, tools, clients, budgets, 5 parallel tasks

| Task | Owner paths | Scope | Acceptance |
|---|---|---|---|
| **2A MCP proxy + servers** [S] | `gateway/src/acl/mcp_proxy`, `mcp-servers/` | Proxy (Streamable HTTP + stdio wrapper; spec 2025-11-25, plus 2026-07-28 header/body consistency); `initialize` allowlist; `tools/list` pinning + description scan + collision detection + personalised list; `tools/call` authz, pinned schema (unknown fields rejected), path/SQL/command checkers; `sampling` denied; result scanning + redaction. Servers: governed tools, mail (mock), files, **core-banking DB** (read-only, column scoping, canary rows), **rug-pull demo server**, web fetch with planted injections | Rug pull → quarantine + incident; parasitic param rejected; stacked SQL blocked; canary never leaves |
| **2B Taint / IFC, tiers, decide, approvals** [S] *(orchestrator reviews closely)* | `gateway/src/acl/controls/{taint,tools}`, `gateway/src/acl/api/decide.py`, approvals module | Session labels (integrity × confidentiality), tool labels + capabilities, Rule-of-Two, tiers deny/must/allow/confirm, monotonic confinement, `/v1/decide`, approvals queue with time-boxed elevation, plugin-bypass detection (model tool_call without matching decide) | Toxic-flow scenario blocked even with classifiers disabled; approval flow end-to-end via API |
| **2C Clients** [S] | `plugins/opencode-guard`, `deploy/opencode`, `deploy/librechat` | OpenCode plugin: `auth` (Keycloak device flow), `chat.headers`, `tool.execute.before` → `/v1/decide`, approval wait; managed config (`enabled_providers`, `share: disabled`, webfetch policy); locked container (non-root, read-only `/etc/opencode`, network = gateway only). LibreChat: OIDC + custom endpoint + per-user identity forwarding (verify mechanism) | A judge can't reach external LLM APIs from the container; a forbidden local tool is blocked with the rule ID; LibreChat login via Keycloak works |
| **2D Budgets & loops** [S] | `gateway/src/acl/budgets` | Ledger (org → group → user → agent → session), tokens/USD (in/out priced separately)/GPU-seconds (Ollama timings), pre-dispatch estimate, stream caps (output, reasoning, repeated n-grams), loop detection (repeat (tool, args-hash), steps, depth, spend derivative), circuit breaker, degrade-to-local, guard spend line, per-user scoped cache | Budget tests from concept §16 row 10 pass; breaker opens/half-opens |
| **2E Panel foundation** [S] | `panel/` | Keycloak login, role-based nav, generated API client from `contracts/admin-api.openapi.yaml`, **Live traffic** (SSE) and **Decision trace** (per `docs/ux/` if available), Approvals queue, Overview v1 | Event appears in panel <1 s after the request; trace shows each stage with verdict/score/latency/rule; approve/deny works |

**CP2:** demo scenarios 2, 3, 4, 6, 7 and 12 (concept §17) run end-to-end, scripted in `tests/e2e/`.

### Phase 3: Semantic layer, routing, panel depth, 3–4 parallel tasks

| Task | Owner paths | Scope | Acceptance |
|---|---|---|---|
| **3A Semantic controls** [S] | `gateway/src/acl/controls/{similarity,classifiers,judges}`, risk scoring in `engine/` | Attack-corpus kNN (bge-m3); GLiNER NER (T1); ONNX injection classifier; Bielik Guard; L2 judges (alignment, CI check, sanitize, PII T2, content safety) with isolated/spotlighted inputs; graded risk score (§6.5); shadow judge (async sample); judge calibration script (κ); presets wired | Strictness matrix passes in deterministic mode (mocked model outputs) and live mode (2-of-3); per-layer attribution in traces |
| **3B Router & task-scoped policy** [S] | `gateway/src/acl/routing` | Sensitivity × complexity × budget routing, budget-aware escalation, specialist routing via tags + task head/kNN, "why this model" explanation, degraded fallback; task-scoped policy (plan from trusted request ∩ static policy, enforced deterministically) | PESEL → local; general question → Gemini (if granted); loan application → specialist (mock or real); plan violation blocked |
| **3C Panel management** [S] | `panel/` | Policies (forms + Monaco/schema + diff + dry-run + conflict + external-edit notices + org locks), User 360 (effective access with sources, history redacted, break-glass), Grants, Models & connectors (kill switch), Tools & MCP inventory, Incidents (rug-pull diff) | UX flows 2–9 from `docs/prompts/admin-panel-ux.md` work against the real API |
| **3D Training track** [S] *(parallel from Phase 1 if WCSS is ready; never blocks)* | `training/` | Data generation (PL injection, sensitivity, task labels; benign hard negatives; held-out split), classifier fine-tune (mDeBERTa / Bielik Guard encoder) → ONNX; specialist LoRA (`corp/loan-memo-pl`) → GGUF + Modelfile; eval reports | Before/after metrics vs the off-the-shelf model on the held-out set; artifacts pass our scanner |

**CP3:**
- demo scenarios 1, 5, 9, 10 and 11;
- strictness matrix green;
- the live judge latency budget is respected (p95 reported).

### Phase 4: Differentiators and evidence, 4 parallel tasks

| Task | Owner paths | Scope |
|---|---|---|
| **4A Artifact scanner** [S] | `gateway/src/acl/artifacts` | Default-deny formats, opcode walker, archive mismatch / broken pickle = malicious, Keras Lambda, GGUF sanity, HF revision pinning; tests generate malicious files in-test (never download) |
| **4B Automation Insights** [S] | `gateway/src/acl/insights`, panel Insights view | Embed redacted prompts → HDBSCAN per group → recurrence → cost estimate → task card + draft skill (local LLM) → publish as skill alias; k-anonymity threshold; seed data for the demo |
| **4C Evidence suite** [S] | `tests/{mutation,perf,redteam}` | Mutation testing (disable each control → ≥1 test fails); adaptive tier (paraphrased/encoded/translated attacks); latency benchmark (direct vs via gateway, per stage); garak/promptfoo configs; offline trace replay; metrics summary feeding the panel |
| **4D Panel reporting** [S] | `panel/` | Guard quality (all metrics from concept §12), Performance, Budgets & spend, Audit & exports (OCSF/JSONL/CSV, chain verification), management report export, employee self-service home |

**CP4:**
- all 14 demo scenarios pass in `tests/e2e/`;
- deterministic suite green in <2 min;
- mutation report shows every control is covered;
- perf report generated.

### Phase 5: Hardening and demo [O] + 1–2 [S]

- `make demo` from a fresh clone on a clean machine (model pulls, realm import, seed data).
- Failure drills: gateway restart mid-stream, invalid YAML, feed server down, Gemini unreachable, Ollama model missing, Postgres restart.
- README (judge quickstart: 5 commands, URLs, demo users), architecture diagram, demo script with timings, licence table re-verified, `docs/checkpoints/` complete.

**CP5:** full rehearsal of the demo script; every scenario under its time budget; final report.

## 5. Subagent brief template (use for every [S] task)

```
ROLE: You implement <task id/name> for the AI Control Layer. Read docs/CONCEPT.md §<relevant> and CLAUDE.md first.
GOAL: <one paragraph>
OWNED PATHS (only these may be written): <paths>
READ-ONLY CONTRACTS: contracts/<files>. Do not change them. If a contract blocks you, stop and report the exact change you need.
DEPENDENCIES: <interfaces from other tasks>. Use mocks/fakes behind the contract until they exist.
REQUIREMENTS: <bullet list from the phase table>
TESTS (definition of done):
  - unit tests for each module
  - paired positive/negative YAML cases in tests/cases/<area>.yaml (≥5 each per control), each with expected decision + rule_id
  - every decision path emits a schema-valid audit record
  - `make lint` and `make test` pass in your worktree
DON'T: add dependencies without hash-pinning them via uv/pnpm lock; log raw sensitive values; hardcode model names or secrets; touch files outside owned paths.
REPORT BACK (final message, ≤300 words): what was built, files changed, test results (counts), contract gaps, known limitations, follow-ups.
```

## 6. Checkpoint protocol (run at each CP, then stop)

1. Merge the phase's worktrees into `main` in dependency order; resolve conflicts yourself.
2. `make lint && make test` (deterministic), plus `make test-live` if Ollama is available.
3. Run the phase's e2e demo scenarios.
4. **Security review** of the critical modules touched in this phase. Use `/code-review` or a reviewer subagent with a narrow brief, then fix or log the findings.
5. Write `docs/checkpoints/CP<n>.md`:
   - done / not done against the acceptance criteria;
   - test counts and metrics (ASR, FPR, latency p50/p95 where relevant);
   - demo scenarios status;
   - risks, scope cuts and decisions needed.
6. Commit with a clear message, then **stop and ask me to approve** the next phase. Include proposed scope cuts if we're behind.

## 7. Scope-cut ladder (apply in this order if time runs short)

1. Quarantine mode, A2A, memory provenance (already stretch goals).
2. Specialist fine-tuning (keep the routing mechanism, use a prompt-configured "specialist" stand-in).
3. Automation Insights → static seeded clusters + the publish-skill flow only.
4. Shadow judge, PII T2.
5. Panel: Performance and employee self-service views.

**Never cut:**
- deterministic controls;
- taint / Rule of Two;
- policy hot reload + dry-run;
- audit chain;
- the decision trace view;
- the test suite with positive/negative pairs;
- the signature feed + artifact scanner (formal requirements).

## 8. Quality bar

- Gateway overhead (deterministic stages): p95 ≤ 15 ms. Semantic stages are reported separately.
- Every control has positive and negative tests; the strictness matrix is asserted.
- No secret is ever in git. `.env.example` documents all variables.
- Each phase leaves `main` demo-able.

Start by reading `docs/CONCEPT.md`, then ask the §1 questions in one batch.
