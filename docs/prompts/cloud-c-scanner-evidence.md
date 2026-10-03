# Cloud session C — model-file scanner + evidence suite

> Paste everything below the line into a new cloud session on `github.com/dawidlinek/ai-control-layer`.

---

You build two independent pieces for **Rogatka** (repo ai-control-layer), a company-wide AI gateway. Read, in order:
`docs/prompts/cloud-README.md` (rules for parallel cloud sessions — binding), `CLAUDE.md` (repo conventions —
binding), `docs/CONCEPT.md` §9.2 (signature feed + **model-artifact scanner**), §16 (self-testing suite), §20,
`docs/checkpoints/CP2.md`. Branch `feat/scanner-evidence`. Both are scored areas: the artifact scanner is a **formal
requirement** of the brief; the self-testing suite is 15 % of the score.

## Part 1 — model-artifact scanner (owned: `gateway/src/acl/artifacts/`, `gateway/src/acl/api/admin/artifacts.py` split
out of `api/admin/platform.py`, artifacts section of the admin contract, control type `artifact_scan` at the
`artifact_load` inspection point, `tests/cases/artifacts.yaml`, `gateway/tests/test_artifacts_*.py`)

- `POST /admin/v1/artifacts/scan` (multipart) + list; a load hook in the model registry (models with an `artifact:` ref
  must have a passing scan with the same sha256, else unavailable).
- **Default deny**: only safetensors and GGUF allowed; pickle-based formats (`.bin`, `.pt`, `.pkl`, `.pth`) blocked
  unless an explicit exception is granted in policy.
- **Pickle opcode walker** (own implementation over `pickletools.genops`, never unpickle): flag `GLOBAL` /
  `STACK_GLOBAL` / `REDUCE` / `INST` / `OBJ` / `BUILD` reaching `os`, `posix`, `nt`, `subprocess`, `builtins.exec/eval/
  compile/open/__import__`, `socket`, `runpy`, `importlib`, `shutil`, `webbrowser`, …; signature-feed `opcode` entries
  (type `opcode`, `module.attr` globs) are honoured too.
- **nullifAI-style tricks are malicious, not "unscannable"**: archive-format mismatch (7z/other where ZIP is expected for
  PyTorch zip files), broken/truncated pickle streams, multiple pickles, nested archives.
- **Keras**: `.keras` / `.h5` with `Lambda` layers or arbitrary module references → blocked (CVE-2024-3660,
  CVE-2025-1550 — verify ids before putting them in metadata).
- **GGUF**: header + metadata sanity checks (magic, version, tensor/kv counts and lengths within file size, string
  lengths, alignment) against parser memory-safety bugs. **safetensors**: header length/JSON/offsets sanity.
- PyTorch version gate note (CVE-2025-32434, `weights_only=True` RCE before 2.6.0) in docs/metadata (verify).
- Hugging Face: pin by revision SHA, repo allowlist (policy) — validation helper only, no network in tests.
- Every scan is audited (`artifact_scan` event) and appears in the Known threats → Model files screen data.
- Tests generate malicious files **in-test** (pickle with `__reduce__` → `os.system`, 7z-wrapped pickle, broken stream,
  Keras Lambda config, malformed GGUF/safetensors headers) — **never download** models or payloads. Benign safetensors /
  GGUF fixtures generated in-test too. Paired positive/negative YAML cases (≥5/≥5).

## Part 2 — evidence suite (owned: `tests/mutation/`, `tests/perf/`, `tests/redteam/`, `tests/replay/`, `scripts/dev.py`
`bench` task, report outputs under `reports/`)

1. **Mutation testing**: a script disables each control in turn (policy override, in-process) and runs the
   deterministic suite; every control must make ≥ 1 test fail. Output `reports/mutation.json` + a markdown summary;
   fail the run if a control is uncovered. (Note: SEC-TAINT-01 lacks YAML cases today — extend the case harness so a
   case can assert `labels_after` (integrity / confidentiality / taint) and add its paired cases.)
2. **Adaptive tier**: paraphrased, encoded (base64/hex/url/zero-width/homoglyph), translated (Polish) and split variants
   of the attack cases, generated deterministically from the existing negatives; report detection honestly (not 100 %),
   with Wilson CIs, per control and per preset.
3. **Offline trace replay**: replay recorded decision traces (JSONL; include a small AgentDojo-style sample you write
   yourself) through the engine without running any agent; same machinery as policy dry-run; CLI + report.
4. **Latency benchmark**: per-stage p50/p95/p99 of the deterministic pipeline in-process (mock upstream), and a script
   for the integrator that compares a direct model call vs via the gateway on the live stack (do not run it in the
   cloud). `dev.py bench`.
5. **Red team configs**: garak and promptfoo configurations pointed at the gateway's OpenAI-compatible endpoint
   (with run instructions for the integrator; do not run them in the cloud).
6. Metrics summary feeding the panel: extend `reports/summary.json` (GuardQualitySummary shape) with mutation coverage,
   adaptive-tier results and per-layer attribution.

## Done

`dev.py test` + `lint` green; mutation report shows every control covered; PR `feat/scanner-evidence` with what was
built, test counts, contract changes, and the commands the integrator runs locally (bench, garak, promptfoo).
