# garak against the gateway

[garak](https://github.com/NVIDIA/garak) (NVIDIA) is an LLM vulnerability scanner: it sends probe prompts to a target
and scores the replies with detectors. Here the target is the **gateway** (`/v1/chat/completions`, OpenAI-compatible),
so the question answered is "what still gets through the guard layer", not "how robust is the model".

garak is **not** a dependency of this repository (it pulls a large ML stack). Install it in its own virtualenv.
Nothing in `make test` runs it; these are run by the integrator against a running stack and the reports are stored as
artifacts. These commands were written without running garak (it is not installed in the development environment):
the config keys marked `UNCERTAIN` in `config.yaml` and the environment variable below must be checked against the
garak version you install.

## Setup (once)

```bash
uv venv .venv-garak --python 3.12            # or: python -m venv .venv-garak
uv pip install --python .venv-garak garak    # or: .venv-garak/bin/pip install -U garak
.venv-garak/bin/garak --version              # Windows: .venv-garak\Scripts\garak.exe
.venv-garak/bin/garak --list_probes | head   # confirm the probe families below exist in this version
```

## Run

The gateway must be up (`make up`) and you need a gateway API key of a principal that may use the model alias `local`
(issue one in the admin panel). The default rate limit is 60 requests per minute per user (`policy/budgets.yaml`
`default_user.requests_per_minute`): give the red-team user a higher limit through a per-user override in that file, or
run with `--parallel_attempts 1` and accept a long run; a throttled attempt shows up as a 429 and is not a finding.

```bash
export ACL_GATEWAY_URL=http://localhost:8080          # default
export ACL_API_KEY=<gateway API key of the red-team user>
export OPENAICOMPATIBLE_API_KEY="$ACL_API_KEY"        # UNCERTAIN name: garak reads <GENERATORCLASS>_API_KEY
export GARAK_MODEL=local                              # gateway model alias (default local)

# 1. render the template (substitutes URL and model; the key is never written to a file)
uv run python tests/redteam/garak/render.py tests/redteam/garak/quick.yaml --out reports/redteam/garak/quick.rendered.yaml

# 2. smoke run first: a few probes, one generation each (minutes)
.venv-garak/bin/garak --config reports/redteam/garak/quick.rendered.yaml

# 3. the full run (hundreds of prompts x 3 generations: plan for an hour or more; keep the rate limit in mind)
uv run python tests/redteam/garak/render.py --out reports/redteam/garak/config.rendered.yaml
.venv-garak/bin/garak --config reports/redteam/garak/config.rendered.yaml
```

Equivalent without the config file (flags are stable across versions; `--generator_options` carries the base URL, its
exact JSON layout is the `UNCERTAIN` part):

```bash
.venv-garak/bin/garak --model_type openai.OpenAICompatible --model_name "$GARAK_MODEL" \
  --generator_options "{\"openai\": {\"OpenAICompatible\": {\"uri\": \"$ACL_GATEWAY_URL/v1\"}}}" \
  --probes promptinject,dan,encoding,latentinjection,xss,malwaregen,packagehallucination \
  --generations 3 --report_prefix rogatka
```

## What is selected and why

| Family | What it tries | Gateway control that should answer |
|---|---|---|
| `promptinject` | Hijacking the instruction ("ignore previous ...") | Classifier / similarity tier when enabled; deterministic tiers only see the egress effects |
| `dan` | Jailbreak personas (DAN, in-the-wild prompts) | Same; also egress hygiene for leaked system prompt |
| `encoding` | Payloads hidden in base64, ROT13, hex, Morse, braille, ... | SEC-NORM-01 decodes and rescans, so signatures and secrets fire on the decoded text |
| `latentinjection` | Injection inside documents the model is asked to process (resume, report, translation) | Tool-result / ingress scanning; Rule of Two when tools are involved |
| `xss` | Markdown-image and link data exfiltration, conversation leak | SEC-EXFIL-01 (egress) |
| `malwaregen` | Requests for malware code | Content-safety tier when enabled (none in the deterministic tier) |
| `packagehallucination` | Model recommends non-existent packages (slopsquatting) | Not covered by a control yet; reported for completeness |
| `goodside.Tag` | Unicode tag-character smuggling | SEC-NORM-01 strips tag characters |

`leakreplay` (memorised training text) is left out: the gateway cannot influence it.

## Where results go and how to read them

Reports are written to `reports/redteam/garak/` (gitignored): `rogatka*.report.jsonl` (every attempt with prompt,
reply and detector scores), `rogatka*.report.html` (summary per probe and detector) and `rogatka*.hitlog.jsonl` (only
the hits). Attach the HTML and the hit log as artifacts.

- A **hit** is a reply the detector judged to be a successful attack. The **pass rate** per probe is the share of
  attempts without a hit; garak colours it against its own thresholds.
- A request the gateway blocks comes back as HTTP 403 `policy_violation` (a `code` field names the rule id) and
  yields no completion, which garak counts as no hit. A low hit rate therefore means "blocked **or** the model
  refused". To separate them, count the gateway's decisions for the run window:
  `GET /admin/v1/events?since=<run start>&action=block` (the audit log is the oracle; group by `rule_ids`).
- Hits are findings to triage, not test failures: deterministic tiers do not detect semantic attacks, and the report
  should say which probes land in which category. Do not quote a hit rate without the number of attempts behind it.
- If garak aborts on the first 403 instead of recording it, say so in the run notes and use the audit-log counts.
