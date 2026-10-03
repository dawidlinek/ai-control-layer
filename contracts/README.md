# Contracts

Generated from code by `make contracts` (`gateway/src/acl/contracts/export.py`). **Do not hand-edit**
the generated files; change the Pydantic models / routes and regenerate. `make lint` fails on drift.

| File | Source | What it is |
|---|---|---|
| `decision.schema.json` | `acl.contracts.inspection`, `acl.contracts.decision` | `InspectionContext` (control input), `Verdict` (one control's result), `Decision` (composed outcome) under `$defs`; root validates a `Decision` |
| `event.schema.json` | `acl.contracts.audit.AuditEvent` | One line of the hash-chained audit log (concept §13) |
| `policy.schema.json` | `acl.policy.models.PolicyDocument` | Any `policy/*.yaml` file (every section optional; merged + cross-validated by the loader) |
| `feed-bundle.schema.json` | `acl.contracts.feed.FeedBundle` | Signature feed bundle served by `feed-server/` |
| `decide-api.openapi.yaml` | `acl.api.decide` | `POST /v1/decide`, approval polling / user approval |
| `admin-api.openapi.yaml` | `acl.api.admin.*`, health | Admin API for the panel (policy, grants, users, events + SSE, incidents, approvals, budgets, models, MCP, feed, artifacts, insights, metrics, audit) |
| `examples/*.json` | `export.examples()` | Valid example payloads (validated in `gateway/tests/test_contracts.py`) |

## Key rules encoded in the contracts

- **Inspection points** (`InspectionPoint`): ingress, egress, tool_call, tool_result, embeddings,
  agent_message, artifact_load, mcp_initialize, mcp_tools_list.
- **Phases** run in order: normalise → deterministic → similarity → semantic_l1 → semantic_l2 → decide → egress_hygiene.
- **Actions** and severity: allow < monitor < redact = pseudonymise < sanitize = route_local < downgrade
  < require_approval < block. `Decision.action` is the most severe; `Decision.applied` lists all
  transforms applied (e.g. `[pseudonymise, route_local]`). A `final` block always wins.
- **Monitor mode** never enforces: `action = monitor`, `would_action = <what enforce would do>`.
- **No raw values** in `Verdict`/`AuditEvent`: findings carry entity type, location, salted `value_hash`.
- **Audit hash chain**: `hash = sha256(prev_hash + "\n" + canonical_json(record − hash))`, genesis
  `prev_hash = "0"*64`, canonical JSON = sorted keys, `(",", ":")` separators, UTF-8, RFC 3339 `Z`
  timestamps (`acl.contracts.canonical`).
- **Feed bundle**: digest over canonical JSON without `signature`; `sha256` (checksum) or `ed25519`;
  monotonic `bundle_version`; verification failure keeps the last good bundle.
- **Policy**: files are `PolicyDocument`s; a section may appear in one file only; `env:NAME` strings are
  resolved from the gateway environment at compile time; org locks are evaluated before any grant.
- **Tool ids**: client built-ins `opencode.<tool>`; MCP tools `<server-alias>.<tool>`.
- **Group names**: Keycloak group paths without the leading slash (`developers`, `agents/research-bot`).
