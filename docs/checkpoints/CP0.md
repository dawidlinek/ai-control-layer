# CP0 — Foundations and contracts

*2026-10-03 · orchestrator*

## Acceptance criteria

| Criterion | Status |
|---|---|
| `make up` starts everything healthy | **Done** — postgres, keycloak (realm imported), gateway, feed-server all `healthy` |
| `make test` runs | **Done** — 38 passed in ~8 s (deterministic) |
| `make lint` | **Done** — ruff clean, format clean, contracts in sync |
| Contracts reviewed by the user | **Pending — your review** |

Stack smoke test: `/healthz` ok, `/readyz` ok with policy `vf2ea2e81c6b4`, admin API → 401 without a token,
feed serves bundle v1 with sha256 digest, Keycloak client-credentials token for `agent-research-bot` has
`iss=http://localhost:8180/realms/acl`, `aud=gateway`, `groups=[/agents/research-bot]`, `agent_id=research-bot`;
`opencode` device flow enabled; gateway reaches JWKS on the internal network. Gemini (`gemini-flash-latest`)
answers via the OpenAI-compatible endpoint.

## What exists

- `contracts/` (generated, drift-checked): decision / event / policy / feed-bundle schemas, decide + admin
  OpenAPI (3 + 56 operations), 11 validated examples. See `contracts/README.md` for the rules they encode.
- Engine skeleton: control ABC + registry, phased pipeline (parallel per phase, timeouts, fail modes, early
  exit), decision composition with invariants tested, mock LLM connector, minimal policy loader.
- Seed policy (6 files, all 21 controls declared and disabled until implemented).
- Harness: pytest config, YAML case collector/runner (matrix support), deterministic mode flag.

## Decisions taken (from your answers)

- **Fine-tuning cut** (3D). `auto` → specialist routing stays, via the prompt-configured `local/loan-memo-pl`.
- **Models on a remote vLLM/SGLang/Ollama box**: one `local` connector (`openai_compatible`), URL + model names from
  `.env` (`LOCAL_LLM_BASE_URL`, `LOCAL_*_MODEL`). No Ollama container. GPU-seconds from upstream timings when
  present, else `pricing.gpu_seconds_per_1k_tokens` estimate.
- **Admin panel paused**: 2E/3C/4D deferred, no panel service; the admin API is still built (contract exists).
- **Gemini**: `gemini-flash-latest`; it hides ~70 reasoning tokens per call outside `completion_tokens` → meter
  output as `total_tokens − prompt_tokens`.

## Design choices for your review

1. Sixth policy file `tools.yaml` (MCP server allowlist + tool catalogue with labels/tiers/checkers).
2. Group names = Keycloak paths without leading slash (`agents/research-bot`); gateway normalises.
3. Org locks are structured (`data_class_tier`, `control_locked`, `deny_resource`), not free-text rules.
4. `Decision.action` = most severe; `Decision.applied` lists all transforms (e.g. `[pseudonymise, route_local]`).
5. Tool ids: `opencode.<tool>` for client built-ins, `<server>.<tool>` for MCP.
6. `ACL_DETERMINISTIC=1` swaps every connector for the mock while preserving its tier.
7. Keycloak runs `start-dev` with its embedded DB (realm re-imported on fresh start; user ids pinned in the export).

## Proposed Phase 1 adjustments

- 1A also implements deterministic-mode connector swap and Gemini token metering note.
- 1E absorbs the e2e scripting for CP1 (no panel).
- Everything else as planned. Policy YAML edits by subagents limited to enabling their own controls.

## Risks

- Slow network on this host (image pulls ~100 KB/s): `make demo` on a fresh machine must pre-pull images.
- Local model server URL not yet provided → live tests skip until `LOCAL_LLM_BASE_URL` is set.
- Gemini key was shared in chat; rotate after the hackathon.
