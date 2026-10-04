# promptfoo against the gateway

[promptfoo](https://www.promptfoo.dev) runs plain regression tests with assertions and a generated red team (attack
prompts from plugins, mutated by strategies) against a target. `promptfooconfig.yaml` points it at the gateway.
promptfoo is **not** a dependency of this repository; use `npx` (Node 18+). Nothing here runs in `make test`, and the
commands below were written without running promptfoo: check items marked `UNCERTAIN` in the config against the version
you get from `npx promptfoo@latest --version`.

## Environment

```bash
export ACL_GATEWAY_URL=http://localhost:8080      # default; the config appends /v1
export ACL_API_KEY=<gateway API key of the red-team user>   # read by promptfoo through apiKeyEnvar, never stored
export PROMPTFOO_DISABLE_TELEMETRY=1              # optional
```

The generated red team needs a model that writes the attack prompts and grades the replies. promptfoo uses OpenAI by
default (`export OPENAI_API_KEY=...`, a **separate** key that talks to OpenAI directly, not through the gateway). To use
a local OpenAI-compatible server instead, set the `redteam.provider` and grader provider in the config (see the promptfoo
docs, "Configuring the grader"); the target stays the gateway either way. The gateway's default rate limit is 60
requests per minute per user (`policy/budgets.yaml`): give the red-team user a higher per-user limit or lower
`--max-concurrency`.

## Run

```bash
# 1. regression tests only (the `tests:` block: PESEL echo, markdown exfil, IBAN echo, two false-positive checks)
npx promptfoo@latest eval -c tests/redteam/promptfoo/promptfooconfig.yaml \
  --no-cache --max-concurrency 2 -o reports/redteam/promptfoo/eval.json -o reports/redteam/promptfoo/eval.html

# 2. generate the attack set (uses the generator model), then run it against the gateway
npx promptfoo@latest redteam generate -c tests/redteam/promptfoo/promptfooconfig.yaml \
  -o reports/redteam/promptfoo/redteam.yaml
npx promptfoo@latest redteam eval -c reports/redteam/promptfoo/redteam.yaml \
  --no-cache --max-concurrency 2 -o reports/redteam/promptfoo/redteam-results.json

# or both steps at once
npx promptfoo@latest redteam run -c tests/redteam/promptfoo/promptfooconfig.yaml --max-concurrency 2

# 3. look at the results
npx promptfoo@latest redteam report          # opens the vulnerability report in a browser
npx promptfoo@latest view                    # eval viewer
```

Store `reports/redteam/promptfoo/*.json` and the exported report HTML as artifacts (`reports/` is gitignored).
`redteam run` without `-o` keeps results in promptfoo's local database (`~/.promptfoo`).

## Plugins and strategies

| Plugin | Why it matters for the gateway |
|---|---|
| `pii`, `harmful:privacy` | PII tier T0 (PESEL, IBAN, card) and pseudonymisation; model repeating personal data |
| `prompt-extraction` | System-prompt canary and egress hygiene |
| `hijacking`, `indirect-prompt-injection` | Instruction hijack; injected content in documents and tool output |
| `excessive-agency`, `shell-injection`, `sql-injection`, `ssrf` | Tool policy, command / SQL / URL checkers, internal-target signatures |
| `rbac`, `bola` | Per-group tool and data permissions; meaningful when you run the target as users of different groups (re-run with another `ACL_API_KEY`) |
| `harmful:cybercrime`, `harmful:indiscriminate-weapons`, `harmful:self-harm`, `harmful:hate` | Content safety (semantic tier; the deterministic tiers do not cover these) |

Strategies: `basic` (plain prompts), `jailbreak`, `prompt-injection`, `base64`, `leetspeak`, `rot13` (the encoding
ones are what SEC-NORM-01 decodes and rescans) and `multilingual` with `pl` (the deployment language).

## Reading blocked requests

A request blocked by the gateway is HTTP 403 `policy_violation` with the rule id in `error.code`; promptfoo records
it as a provider error, not as a reply. For attack prompts a block is the good outcome, so:

- Count errors separately from failures: in the report, a plugin with many provider errors and few failures is
  mostly blocked, not mostly safe model behaviour. Cross-check with the gateway audit log for the run window
  (`GET /admin/v1/events?since=<run start>&action=block`, group by `rule_ids`).
- The grader only sees replies that got through. The failure rate is therefore a rate over passed-through attempts,
  and must be reported with the attempt counts (blocked, passed, failed), not as a percentage alone.
- The plain `tests:` avoid this on purpose: they expect a 200 answer with a pseudonymised or redacted body.
