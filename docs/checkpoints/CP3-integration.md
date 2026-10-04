# CP3-integration — B + C merged, two local models live on WCSS

*2026-10-04 · local integrator (branch `integrate/cp3`, pushed as origin/main `b96c4c2`)*

## What merged

| Piece | Source | Notes |
|---|---|---|
| Automation Insights (B) | `feat/insights`, already on origin/main | Verified against `cloud-b-insights.md` "Done": input is `redacted_payload` only; drafting and embedding refuse non-local targets; k-threshold (default 5) enforced on list and get; personal suggestions only to their owner, opt-in; publish goes through `policy_writer.patch_files` (new policy version, hot reload). No fix needed. |
| Model-file scanner + evidence suite (C) | local `feat/scanner-evidence` | Reviewed by the integrator (security-critical), see below. Conflicts only in the admin router list, `main.INSTALLERS` and the `platform.py` stubs both sessions moved out. |
| Panel session work | local `main` up to `bdccb08` | Bielik on its own `local-pl` connector + specialist matcher, typed admin contract fields (approvals, incident evidence, rollback reason + migration), realm personas, panel real-gateway fixes |
| WCSS two-model job | `feat/wcss-two-models` | `fetch.sbatch` (HF checkpoints into the shared cache, CPU job), `serve.sbatch` serves one or two vLLM servers on one H100 (8 cores, 64 GB, `--time` per run), `wcss.py tunnel` forwards one local port per endpoint line |
| Docs | user | `local-integrator.md`, `cloud-d-semantic.md` (Bielik amendment), `docs/ux/STYLEGUIDE.md` |

Contracts were regenerated (`dev.py contracts`), never hand-merged; `uv.lock` needed no re-lock.

### Scanner review (C)

- The pickle walker only runs `pickletools.genops` and simulates the stack; nothing is unpickled or imported.
- A broken or truncated stream is `ART-PICKLE-03` malicious (nullifAI: the payload sits before the break); multiple
  pickles / trailing data are malicious; a 7z/other archive with a model extension is `ART-ARCHIVE-01` malicious.
- Unknown globals and unresolved `STACK_GLOBAL`s are medium → `suspicious`, so they cannot load (the gate needs `safe`).
- Default formats are `safetensors` and `gguf` only; anything else is `blocked_format` unless a sha256-bound, expiring
  exception exists; exceptions never admit a malicious file.
- Registry load gate: a model with `artifact:` is available only while the newest scan of that sha256 is `safe` (and,
  when pinned, that exact scan id).
- **Fixed during integration:** if the gate hook was not installed, a model with an `artifact:` reference was served
  unchecked (fail open). `RoutingTable.model_problem` now returns "artifact gate unavailable" in that case; regression
  test fails without the fix.

## Tests (on `b96c4c2`)

- Deterministic: **1 570** gateway unit + **36** policy-service + **711** system, **457/457 case cells** (Wilson 95 % CI
  99.2–100 %), case lint 0/0; `dev.py lint` clean, no contract drift.
- Panel: typecheck + lint clean, **367/367** Vitest tests (41 files).
- Fixed: the Bielik routing test imported `test_1a_api` under a second module name, so its test controls registered
  twice in parallel runs; two policy text fixtures no longer matched `groups.yaml` after the `bielik` grants.
- Known flakes under CPU contention (pass alone and in a quiet full run): `test_1d_latency` p95 micro-benchmarks, the
  SSE-within-a-second test, one policy reload timing test.
- Not run in this pass: `dev.py e2e`, `pnpm -C panel e2e` (the panel session is driving the live stack; next pass).

## Live smoke (WCSS job 6016390, gateway at `b96c4c2`, `ACL_DETERMINISTIC=0`)

Job: `lem-gpu-short`, 1× H100, 8 cores, 64 GB, 2 h (user decision: 2 h for now), node r14-2, ends ≈ 10:15.
Burn ≈ 1 GPU-h + 8 CPU-h per hour. Qwen3.8-27B-FP8 (`--gpu-memory-utilization 0.55`, 64k context, 19.4 GiB KV,
4.5× concurrency at 64k) and Bielik-11B-v3.0-Instruct-FP8-Dynamic (0.30, 32k) on one GPU; checkpoints fetched by a
4-minute CPU job (both Apache-2.0). Tunnel: 127.0.0.1:8001 → Qwen, :8002 → Bielik. Gateway env for Bielik set as shell
overrides only (`LOCAL_PL_BASE_URL=http://host.docker.internal:8002/v1`, `LOCAL_BIELIK_MODEL=bielik-11b`); `.env`
unchanged.

| Check | Result |
|---|---|
| vLLM endpoints without the key | **401** on both |
| `local` "17*23" | **"391"**, `x-acl-model: local/qwen3.8-27b`, `allow` (also direct: 0 reasoning tokens) |
| Tool call via gateway (`local`) | `tool_calls: get_weather({"city": "Wroclaw"})` |
| Gemini (`smart`) | "Warsaw" |
| `bielik` "Wyjaśnij krótko art. 415 k.c." | Bielik, correct (delict liability for fault) |
| `auto`, confidential Polish legal (PESEL) | **Bielik**, `pseudonymise`; model saw `<PESEL_1>`; never cloud |
| `auto`, Polish non-legal / English legal | `gemini/flash` (normal rules) |
| `auto`, "Czy umowa najmu zawarta ustnie jest ważna według kodeksu cywilnego?" | **`gemini/flash` — gap**: the lexical matcher scores below threshold. Direct Bielik answer is correct Polish. Fix in progress (deterministic lexicon detector). |

## Open items

1. Polish-legal detector (above) — subagent running.
2. Gemini answers end with `finish_reason: length` at `max_tokens: 400` on short replies (thinking tokens count) —
   subagent running.
3. Person names pass through un-pseudonymised (regex tier only): SEC-NER-01 (GLiNER ONNX) — subagent running.
4. No embeddings model is served yet (`LOCAL_EMBED_MODEL` empty): Insights mining and SEC-SIM-01 need it live. Plan:
   Qwen3-Embedding-0.6B as a third vLLM server in the next WCSS job, connector `local-embed`.
5. `.env` needs `LOCAL_PL_BASE_URL` / `LOCAL_BIELIK_MODEL` permanently (user to approve).
6. e2e and panel Playwright against the merged stack; the panel session's feed-signature/counts work (`5e66a48`) lands
   after this checkpoint.
7. Semantic models cached at `%USERPROFILE%\.cache\rogatka-models` (DeBERTa-v3 prompt-injection v2 ONNX 739 MB,
   GLiNER multi-PII int8 ONNX 349 MB; revisions and sha256 in `SHA256SUMS`).
