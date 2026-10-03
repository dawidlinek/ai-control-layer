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
  principal: {username: jan, groups: [credit-analysts]}
  input: "Mój PESEL to 44051401359"     # shorthand string, or a payload dict
  expect:
    action: pseudonymise
    rule_id: SEC-PII-01                 # must be in decision.rule_ids; null = no rule may fire
    redaction: {contains: ["<PESEL_1>"], not_contains: ["44051401359"]}   # (1E implements)
  matrix: {monitor: monitor, balanced: pseudonymise, strict: route_local, paranoid: route_local}
  modes: [deterministic]                # deterministic (default) | live
```

Rules: ≥5 positive and ≥5 negative cases per control; every negative has a near-miss positive
(`pair`); never put real personal data or real secrets in cases (use checksum-valid synthetic values).
