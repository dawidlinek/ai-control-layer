# System test cases

One YAML file per area (`pii.yaml`, `secrets.yaml`, `egress.yaml`, ...). Each file is a list of
cases collected by `tests/conftest.py` and run in-process by `tests/harness/runner.py`.

```yaml
- id: pii-pesel-valid-pseudonymised     # unique within the file, kebab-case
  control: SEC-PII-01                   # control under test (mutation testing + attribution)
  kind: negative                        # positive = benign must pass; negative = must be caught
  pair: pii-pesel                       # links a negative to its near-miss positive
  point: ingress                        # inspection point (default ingress)
  preset: balanced                      # default balanced; ignored when `matrix` is set
  principal: {username: jan, groups: [credit-analysts]}   # + roles, kind, agent_id, client_id (Principal fields)
  session: untrusted                    # optional: preset (clean|untrusted|sensitive|untrusted_sensitive|egress_used|
                                        # downgraded|deep_agent) or SessionState fields, e.g. {preset: untrusted, step: 3}
  input: "Mój PESEL to 44051401359"     # shorthand string, or a payload dict
  expect:
    action: pseudonymise
    rule_id: SEC-PII-01                 # must be in decision.rule_ids; null = no rule may fire
    redaction: {contains: ["<PESEL_1>"], not_contains: ["44051401359"]}   # checked after apply_replacements
  matrix: {monitor: monitor, balanced: pseudonymise, strict: route_local, paranoid: route_local}
  modes: [deterministic]                # deterministic (default) | live
```

Rules: ≥5 positive and ≥5 negative cases per control; every negative has a near-miss positive
(`pair`); never put real personal data or real secrets in cases (use checksum-valid synthetic values).

## How cases are run

Every case (and every `matrix` cell) is evaluated through the real app wiring (`create_app` lifespan, once per
session, `tests/harness/host.py`) in deterministic mode; the harness falls back to a bare `Engine.build` only if the
app fails to start, and says so loudly. Extra `expect` keys: `applied: [actions]`, `would_action`, `decided_by`,
`decided_phase`, `final`. `rule_id` may be a list (all must fire); matrix cells expecting `allow` skip it. `redaction`
is checked only when a redact/pseudonymise transform is expected or applied (optionally `presets: [...]`).
Also optional: `model_requested`, `user_request`, `policy_mode: monitor`.

`ACL_TEST_MODE=live` (`make test-live`) runs the cases that list `live` in `modes` three times and passes on 2 of 3.

Reports (gitignored `reports/`): `junit.xml`, `summary.json` (shape of `GuardQualitySummary`: per-control
tp/fp/tn/fn, detection rate and FPR with Wilson 95% CIs, per-preset rows, layer attribution by `decided_phase`,
ASR) and `case_lint.json`. The case lint reports warnings for the rules above; `ACL_STRICT_CASE_LINT=1` makes them fail.

