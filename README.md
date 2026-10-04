# Rogatka — AI Control Layer

*Every AI request passes the gate. Deterministic gates decide; AI escalates.*

Rogatka is a company-wide AI gateway. Every prompt, response, tool call, tool result, embedding and MCP message passes
through it and is classified (PII, secrets, prompt injection, data sensitivity), authorised per user / group / agent,
routed to the right model (local or cloud), budgeted, and written to a tamper-evident audit log. **Rogatka Dashboard**
is the admin panel; **Automation Insights** turns repeated AI work into governed, cheaper skills.

Full design: [`docs/CONCEPT.md`](docs/CONCEPT.md). Progress and evidence: [`docs/checkpoints/`](docs/checkpoints/)
(CP0–CP2, [CP3-panel](docs/checkpoints/CP3-panel.md), [CP3-integration](docs/checkpoints/CP3-integration.md)).

## Architecture

```
 LibreChat (chat) ─┐                         ┌─► local models on WCSS (1× H100, vLLM, reverse SSH tunnel)
 OpenCode (agent) ─┼─► Rogatka gateway ──────┤     Qwen3.8-27B (confidential work, judges)
 MCP clients ──────┘   :8000                 │     Bielik 11B v3 (Polish legal specialist)
        ▲              │  identity (Keycloak)│     Qwen3-Embedding-0.6B (embeddings)
        │ SSO          │  controls pipeline  └─► Gemini Flash / Pro (cloud, public/internal data only)
   Keycloak :8180      │  router + budgets
                       │  MCP proxy /mcp/{server}  ─► governed MCP servers (files, mail, web, core-banking, …)
                       │  audit (hash chain) ─► Postgres
                       └─► Rogatka Dashboard :3000 (admin API /admin/v1, live event stream)
   feed-server :8090 (signature feed)   attacker-sink :8099 (demo exfiltration target)
```

Request path: identity → normalise → deterministic controls (secrets, PII regex + vault pseudonymisation, signatures,
tool policy, Rule of Two, taint, budgets, loops, model access, artifact scan) → optional AI tier (can only make a
decision stricter) → decision (allow / pseudonymise / sanitize / approval / block) → router (sensitivity forces local;
`auto` picks by task and complexity; Polish legal text → Bielik) → response checks → audit.

## Quickstart (judges)

Requirements: Docker Desktop, [uv](https://docs.astral.sh/uv/), Node 22 + pnpm (panel only). Windows: use
`uv run python scripts/dev.py <target>` wherever `make <target>` is shown.

```bash
make env          # creates .env from .env.example and generates every secret (never overwrites set values)
make up           # gateway, Keycloak, Postgres, feed-server, MCP servers; waits for healthchecks
```

Optional profiles: `COMPOSE_PROFILES=clients` (LibreChat :3080, locked OpenCode), `panel` (Rogatka Dashboard :3000).

- Gateway (OpenAI-compatible): `http://localhost:8000/v1` — `/v1/chat/completions`, `/v1/embeddings`, `/v1/models`
- Keycloak: `http://localhost:8180` — demo users `adam` (admin), `anna` (credit analyst), `jan` (developer), `ola`
  (security analyst); password = `DEMO_USER_PASSWORD` from `.env`.
- Without a GPU or API keys set `ACL_DETERMINISTIC=1` in `.env`: every model is a deterministic mock and all controls
  still run, so the whole demo and test suite work offline.

Live models: set `GEMINI_API_KEY`, and for local models `LOCAL_LLM_BASE_URL` / `LOCAL_PL_BASE_URL` /
`LOCAL_EMBED_BASE_URL` (+ `LOCAL_LLM_API_KEY`). We serve them from a WCSS H100 with `scripts/wcss.py`
(`fetch` → `serve` → `tunnel`, see `deploy/wcss/`). If a local model is down the router degrades to the configured
fallback and marks the response `x-acl-degraded: true`; confidential data never fails over to the cloud.

Every response carries `x-acl-decision`, `x-acl-model`, `x-acl-trace-id`; the trace is in the dashboard (Traffic).

## Tests

```bash
make test         # deterministic: gateway unit + policy service + system YAML cases (no network, no model)
make lint         # ruff + format + contract drift check
make e2e          # against the running stack
make test-live    # cases marked live, against the real models
pnpm -C panel test && pnpm -C panel e2e
```

State at submission (2026-10-04): **1 570+ gateway unit, 36 policy-service, 711 system tests; 457/457 case cells**
(paired positive/negative cases per control, all four strictness presets); panel 367+ Vitest tests; e2e 22/22 at CP2.
Live smoke on WCSS (Qwen + Bielik on one H100): known-answer, tool calls, 401 without key, Polish legal → Bielik,
confidential data pseudonymised and kept local — see CP3-integration.

## What is in the repo

| Path | |
|---|---|
| `gateway/src/acl/` | the gateway: `engine/` (pipeline, decision composition), `controls/` (one package per control family), `routing/` (connectors, router, Polish-legal detector), `mcp_proxy/`, `budgets/`, `audit/`, `insights/`, `artifacts/` (model-file scanner), `api/` |
| `policy/` | all behaviour as YAML: controls, models, groups, tools, budgets, routing — hot-reloaded, versioned |
| `panel/` | Rogatka Dashboard (Next.js): 12 screens + session view |
| `contracts/` | generated JSON Schemas + OpenAPI (from the Pydantic models) |
| `tests/` | YAML system cases, e2e, mutation testing, red-team configs (garak, promptfoo), trace replay, benchmarks |
| `deploy/` | docker compose, Keycloak realm, LibreChat / OpenCode lock-down, WCSS job scripts |

## Honest limits

- The AI tier (prompt-injection classifier, NER, similarity, judges) was in progress at submission; the deterministic
  gates carry every decision and the tests above run without it. Names and other quasi-identifiers are not
  pseudonymised by the regex PII tier.
- Polish-legal detection is lexical (language × legal lexicon × article citations), deliberately deterministic;
  paraphrases without legal vocabulary go to the normal rules.
- Local models need the WCSS job and tunnel; the demo degrades (never fails open) when they are down.
- Single-replica state: MCP sessions and loop history are in memory.

Licences of third-party models and data: [`docs/licences.md`](docs/licences.md) (Qwen3.8, Bielik v3, Qwen3-Embedding:
Apache-2.0; Gemini via API).
