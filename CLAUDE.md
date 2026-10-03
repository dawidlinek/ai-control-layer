# AI Control Layer — conventions for humans and agents

Company-wide AI gateway: every prompt, response, tool call, tool result, embedding and MCP
message passes through it and is classified, authorised, routed, budgeted and audited.
**Source of truth: `docs/CONCEPT.md`.** Contracts: `contracts/`.

## Commands

`make <target>` wraps `uv run python scripts/dev.py <target>` (use the latter on Windows without make).

| Target | What it does |
|---|---|
| `env` | Create/complete `.env` from `.env.example`, generating empty secrets. Never overwrites set values |
| `up` / `down` / `logs` / `ps` | docker compose stack (`deploy/docker-compose.yml`), `up` waits for healthchecks |
| `test` | Deterministic suite: unit tests + YAML cases, mock connectors (`-m "not live and not e2e"`) |
| `test-live` | Cases marked `live`, against the real model server (`LOCAL_LLM_BASE_URL`, `GEMINI_API_KEY`) |
| `e2e` | `tests/e2e` against the running stack |
| `lint` | ruff check + ruff format --check + contract drift check |
| `fmt` | ruff --fix + format |
| `contracts` | Regenerate `contracts/` from the Pydantic models and FastAPI routes |

Pass extra args with `ARGS=...` (make) or after the task name (dev.py), e.g. `uv run python scripts/dev.py test -k pii`.

Python 3.12 via uv (workspace root `pyproject.toml`, member `gateway/`). Deps are hash-locked in
`uv.lock`; add deps with `uv add --package acl-gateway <pkg>` (never pip). **LiteLLM is banned.**

## Layout

```
contracts/      generated JSON Schemas + OpenAPI + examples (orchestrator-owned; never hand-edit)
gateway/src/acl/
  contracts/    contract models (orchestrator-owned): common, inspection, decision, audit, feed, decide, admin, canonical
  policy/       models.py (contract, orchestrator-owned), loader, watcher, compiler, writer
  engine/       pipeline.py (phases, timeouts, fail modes), decide.py (SECURITY-CRITICAL), engine.py facade
  controls/     base.py (Control ABC + registry); one subpackage per family, self-registering
  api/          health, decide (/v1/decide), admin/ (routers split by owning area), deps (auth)
  identity/ routing/ budgets/ mcp_proxy/ audit/ feed/ artifacts/ insights/
  testing.py    make_context()/make_principal() helpers for tests
policy/         controls.yaml models.yaml groups.yaml tools.yaml budgets.yaml routing.yaml
deploy/         docker-compose.yml, keycloak/realm-export.json, librechat/, opencode/
feed-server/    stand-in external signature system (stdlib HTTP server + bundles/)
mcp-servers/    governed + demo MCP servers
tests/          cases/*.yaml (system cases), harness/, e2e/, mutation/, perf/, redteam/, oracle/
docs/           CONCEPT.md, ux/, prompts/, checkpoints/
```

## Core interfaces (read before writing code)

- **Control**: subclass `acl.controls.base.Control`, set `type`, `phase`, `Params`, implement
  `async inspect(ctx) -> Verdict`, decorate with `@register_control`. Use `self.verdict(...)`.
  Configured in `policy/controls.yaml` (id, type, stages, cost_tier, fail_mode, timeout_ms, params).
- **InspectionContext** (`acl.contracts.inspection`): payload is a discriminated union on `kind`
  (chat, completion, tool_call, tool_result, embeddings, mcp, artifact). Controls must not mutate it;
  pass data to later phases via `Verdict.outputs` (merged into `ctx.attributes`).
- **Decision composition** (`acl.engine.decide`): final deterministic block always wins; AI tiers can
  only make outcomes stricter; shadow controls / monitor mode never enforce (recorded in `would_action`).
- **Engine** (`acl.engine.engine.Engine`): `Engine.build(policy, version)` → `await engine.evaluate(ctx)`.
  Policy swap = replace the Engine instance atomically.
- **Connectors** (`acl.routing.connectors`): OpenAI-shaped dicts; `mock` is deterministic and scriptable
  with `[[mock:...]]` directives (see `mock.py`). Model names only from policy / `env:NAME` references.
- **Wiring** (`acl.main`): packages expose `acl/<pkg>/wiring.py: install(app, settings)` and are listed in
  `main.INSTALLERS`; they add routers, `app.state.on_startup/on_shutdown` hooks and `app.state.control_deps`
  services. Never edit `create_app` itself. Rebuild the engine with `app.state.build_engine(policy, version)`.
- **Database** (`acl.db`): `Base`, tables in `acl/<pkg>/db_models.py`; migrations in `acl/migrations/versions/`
  with `down_revision = "0001_base"`; SQLite `create_all` in tests, `python -m acl.migrate` in containers.
- **Payload text** (`acl.engine.text`): `iter_texts(payload)` gives (field path, text); `apply_replacements`
  applies finding spans. Field paths are the `Finding.field` convention.
- **Audit sink** (`acl.audit.sink.AuditSink`, at `app.state.audit`): `record_decision(...)`, `record_event(...)`.
- **Sessions** (`acl.sessions`, `app.state.sessions`, control service `"sessions"`): `load(sid)`, `update(sid, fn)`;
  session ids are principal-namespaced (`acl.engine.actions.session_key`). Labels only rise (`merge_labels`);
  `compose_decision` raises `labels_after` from verdict `labels`/`data_class`; commits persist them.
- **Evaluate a point outside chat** (`acl.engine.actions.evaluate_point`): builds ctx (session, preset), evaluates,
  audits, commits (`commit_decision`: control commits + session labels/steps + flow hooks). Used by /v1/decide and MCP.
- **Flow hooks** (`acl.engine.hooks`, `app.state.flow_hooks`): `on_commit(ctx, decision)`, `on_usage(ctx, decision,
  route, usage)` — observation only (budgets ledger, loop counters, bypass detection), never enforcement.
- **Compose fragments**: `deploy/compose.mcp.yml` (2A), `deploy/compose.clients.yml` (2C) are `include`d.
- **Audit record**: `acl.contracts.audit.AuditEvent`; hash chain and canonical JSON in `acl.contracts.canonical`.

## Rules

1. **Never commit secrets.** `.env` is gitignored; secrets come from env only (`env:NAME` in policy).
   Demo users' passwords and client secrets come from `.env` via Keycloak import placeholders.
2. **No raw sensitive values in logs, audit records, verdict reasons or exceptions.** Use
   `acl.contracts.canonical.value_hash(value, salt)`, entity types and offsets.
3. **Contracts change only through the orchestrator.** If a contract blocks you, stop and report the
   exact change needed. `make lint` fails on contract drift.
4. **Fail closed** for deterministic/action controls; semantic controls fail open *with alert*. Every
   control declares `id`, `stages`, `cost_tier`, `fail_mode` (or inherits), `timeout_ms`.
5. **Deterministic gates decide; AI escalates.** An AI-tier control may never turn deny → allow.
6. **Every decision path emits a schema-valid audit record.**
7. Every control has paired positive/negative cases in `tests/cases/<area>.yaml` (≥5 each), each with
   expected action + rule id. Tests run in deterministic mode by default (no network, no model server).
8. Stay inside your owned paths (see the task brief). Policy YAML edits by subagents are limited to
   adding/enabling their own controls; the orchestrator merges.
9. Python style: ruff (line length 120), type hints, `from __future__ import annotations`, async I/O,
   Pydantic v2 models with `extra="forbid"` at trust boundaries.
10. Windows dev host + Linux containers: use `pathlib`, write files with `newline="\n"`, no shell-isms in Python.

## Ownership map (current phase is in the task brief)

| Path | Owner |
|---|---|
| `contracts/`, `gateway/src/acl/contracts/`, `gateway/src/acl/policy/models.py`, `engine/decide.py`, `CLAUDE.md`, `pyproject.toml`, `uv.lock` | orchestrator |
| `api/admin/policy.py` → 1B · `api/admin/access.py`, `api/deps.py` → 1C · `api/admin/events.py` → 1A · `api/admin/platform.py` sections → as labelled · `api/decide.py` → 2B | per phase |
