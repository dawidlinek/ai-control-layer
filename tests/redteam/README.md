# Red team

External scanners pointed at the gateway, plus (owned by another task) the in-repo adaptive tier.

| Path | What | Runs in `make test`? |
|---|---|---|
| `garak/` | garak config templates (`config.yaml` full, `quick.yaml` smoke), `render.py`, README with exact commands | No (config parse test only) |
| `promptfoo/` | `promptfooconfig.yaml` (regression tests + generated red team), README with exact commands | No (config parse test only) |
| `adaptive/` | Deterministic attack variants (paraphrase, encodings, Polish, split) of the YAML cases; in-repo, offline | Separate task: `uv run python scripts/dev.py adaptive` |
| `test_configs.py` | Checks that the two configs parse, point at an environment-configurable gateway URL, contain no secrets and list the expected probe / plugin families | Yes |

garak and promptfoo are not dependencies of this repository, need a running stack (`make up`) and a gateway API key, and
send a lot of traffic: run them against a stack you own, with a dedicated red-team user whose rate limit is raised in
`policy/budgets.yaml`. Results go to `reports/redteam/garak/` and `reports/redteam/promptfoo/` (gitignored) and are kept
as artifacts, not as pass/fail tests.

How to read the numbers (both tools): a blocked request is an HTTP 403 `policy_violation` carrying the rule id. The
scanners report it as "no completion" or as an error, not as a safe answer. Always report the counts (attempts,
blocked, passed through, successful attack), take the blocked counts from the gateway audit log
(`GET /admin/v1/events?since=<run start>&action=block`), and say which controls were enabled: with the semantic tiers
off (the shipped policy), semantic attacks (jailbreak personas, harmful-content requests, paraphrased injection) are
expected to get through, and the report should show exactly that rather than hide it.

Environment used by both: `ACL_GATEWAY_URL` (default `http://localhost:8080`), `ACL_API_KEY` (gateway API key),
`GARAK_MODEL` (model alias, default `local`). No key is written to any file in this directory.
