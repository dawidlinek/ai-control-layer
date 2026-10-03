# CP1 — Core pipeline (demo slice)

*2026-10-03 · orchestrator*

## Acceptance criteria

| Criterion | Status |
|---|---|
| PESEL via the API as a Keycloak user → pseudonymised → routed local → audit record with full trace → on the SSE stream | **Done** (e2e `test_cp1_pesel_pseudonymised_routed_local_and_audited`, live stack, deterministic connectors) |
| Hot reload and feed-rule tests pass | **Done** — policy change visible on the next request < 2 s (unit + e2e); feed rule added via feed server + `/feed/sync` blocks the next request (unit + e2e) |
| Forbidden model → 403 | **Done** — 403 `forbidden_model` + incident (e2e) |
| `make lint && make test` | **Green** — lint clean, contracts in sync |

## Test counts and metrics

- Deterministic suite: **961 tests** — 594 gateway unit (parallel), 29 policy-service (serial, real file watching), 338 system
  incl. **183/183 case cells** (Wilson 95% CI 97.9–100%), case lint 0 warnings. Runtime ≈ 2 min wall (3 invocations).
- E2E CP1 slice on the compose stack: **4/4** pass.
- Deterministic-layer latency (1D micro-benchmark, 2 KB prompt, full deterministic pipeline): p50 ≈ 1.8 ms, **p95 ≈ 2.7 ms**
  ingress, ≈ 2.9 ms egress — inside the ≤ 15 ms budget. Gateway end-to-end overhead benchmark is Phase 4C.
- ASR/FPR on attack corpora: not yet meaningful (semantic layer is Phase 3); per-control detection/FPR on the YAML pairs is
  in `reports/summary.json`.
- `make test-live`: not run — no model server reachable yet (see WCSS below).

## What was built (Phase 1)

| Task | Delivered |
|---|---|
| 1A Gateway core | `/v1/chat/completions` (stream + non-stream with hold-back egress guard), `/v1/embeddings`, personalised `/v1/models`; connectors openai_compatible / ollama / mock (+ deterministic swap, kill switch, failover); router (aliases, auto by data class, LOCK-01 re-route, degraded); hash-chained JSONL audit + DB index + SSE + incidents + OCSF/CSV export + Prometheus |
| 1B Policy engine | watcher → validate → compile → atomic swap, last-good fallback + alerts, version snapshots/diff/rollback, single writer (round-trip YAML, optimistic locking), dry-run replay, `PolicySource` |
| 1C Identity & grants | Keycloak JWT (RS256/ES256, iss/aud/exp, JWKS refresh), API keys (HMAC), JIT users, DB grants + change journal + version, access resolver (org locks → group → user, expiry, deny wins), SEC-MODEL-01, `acl-e2e` client |
| 1D Deterministic controls + feed | SEC-NORM-01, SEC-PII-01 (PESEL/NIP/REGON/ID card/IBAN/Luhn/email/phone + vault), SEC-SECRET-01, SEC-EXFIL-01, SEC-SIG-01, SEC-HYG-01; signed feed (sha256/ed25519, no downgrade, atomic swap), feed server with live `POST /entries`, 25 seed signatures |
| 1E Harness & oracles | case runner through the real app wiring, matrix/redaction/live 2-of-3, Wilson-CI metrics → `reports/`, independent leak oracle (no `acl` imports), attacker sink, scripted agent, e2e scaffolding |

## Security review (CP1) — findings and status

Reviewer subagent on authN/Z, grants, decide, request flow, audit, policy writer. All fixed with regression tests:

| # | Sev | Finding | Fix |
|---|---|---|---|
| 1 | critical | verdict cache keyed on text only replayed another user's normalised payload (tools/images/tool intents) | key = full payload + views + point/preset/version; verdicts with outputs never cached; normalise non-cacheable |
| 2 | high | client-chosen session id → cross-user pseudonym restore | session ids namespaced by `sha256(subject)` at context construction (vault, future taint/budgets isolated) |
| 3 | high | unknown body keys / tools / non-text parts forwarded uninspected (LOCK-01/02 bypass) | request-key allowlists (400 `unsupported_parameter`), text-only content parts, `iter_texts` covers tools/names/params, upstream body built from the inspected payload; unaddressable spans fail closed |
| 4 | high | panel could weaken locked controls / org locks | locked controls identical except description; org locks immutable from the panel; no `global.mode: monitor` / `never_block` via panel |
| 5 | medium | user grant preset could loosen group preset; monitor preset silenced secrets | effective preset = strictest; laxer grant presets 422; **locked controls always enforced** (decide + Control base) |
| 6 | medium | API keys kept stale admin roles | key principals drop panel roles; admin API requires JWT; stale identity (> 30 d) refused |
| 7 | low/med | lone surrogate crashed audit → hid forbidden-model probes | 400 `invalid_unicode` at the API; audit writer scrubs surrogates |
| 8 | low | audit chain per-process only; torn write could glue lines | OS single-writer lock on `<log>.lock`; newline guard after failed writes |
| 9 | low | agent API keys lost `agent_id`; degraded fallback ignored force_local | agent id derived; cloud fallback refused for local-only data (503) |

Residual (logged): tool-call ids and numeric fields are type-checked but not text-inspected (covert channel, low bandwidth);
audit tail truncation detectable only via the DB index cross-check.

## Decisions taken during the phase

- Strict/paranoid presets **pseudonymise** PII; locality comes from routing (confidential → `local_only`, LOCK-01). Matches demo 5.
- SEC-MODEL-01 `missing_service: policy_only` (falls back to policy-file ceilings); `/readyz` reports **down** if any
  security-relevant control service (access, vault, signatures) or the audit sink is not wired.
- SEC-MODEL-01 timeout 250 ms (cold grant load; warm path cached; fails closed).
- `dev.py test` runs gateway unit tests in parallel (pytest-xdist, dev-only dep) and timing-sensitive policy tests serially.

## Not done / risks

- **Local model server**: WCSS tooling is ready (`deploy/wcss/`, `scripts/wcss.py`, Qwen3.8-27B-FP8 on 1× H100, SSH tunnel →
  `host.docker.internal:8001`), but WCSS SSH is currently blocked for this IP (TCP timeout after three quick connections).
  Needs: access restored + the exact SLURM account name for "solvro". Until then the stack runs `ACL_DETERMINISTIC=1`.
- `/users/{id}/activity` and break-glass still 501 (event store exists now; wire in Phase 2).
- Seed CVE ids in the feed bundle come from memory — verify against NVD before the pitch.
- Admin panel paused (by decision); admin API complete for Phase 1 areas.

## Proposed Phase 2 (for approval)

2A MCP proxy + demo servers · 2B taint / Rule of Two / tiers / `/v1/decide` / approvals (orchestrator reviews) ·
2C clients (OpenCode plugin + locked container, LibreChat OIDC) · 2D budgets & loops. 2E (panel) stays deferred.
CP2 = demo scenarios 2, 3, 4, 6, 7, 12 scripted in `tests/e2e/`.
