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

### `expect.labels_after` (label-raising controls, e.g. SEC-TAINT-01)

```yaml
  expect:
    action: allow                       # a label-only control never intervenes
    rule_id: SEC-TAINT-01               # an `allow` verdict that raised labels counts as "fired" for rule_id
    labels_after:
      integrity: untrusted              # exact match on decision.labels_after (trusted | untrusted)
      confidentiality: confidential     # exact match (public | internal | confidential | restricted)
      taint: [untrusted, sensitive]     # all of these flags must be present
      taint_absent: [egress_used]       # none of these may be present
```

`labels_after` is the session's input labels joined with every verdict's label update (a blocked / held call keeps
the input labels), so a case with a `session:` preset sees what the session already carries. For these cases the
metrics treat the control by what it is for: a `negative` is a TP when the expected labels were raised by the control,
a `positive` is a FP when it raised labels it should not have. They never count towards ASR / FPR per call / layer
attribution (those measure intervention). See `taint_labels.yaml`.

### Artifact fixtures

For `kind: artifact` payload inputs (`point: artifact_load`), `local_path: "fixture:<name>"` resolves to the generated
fixture file (`acl.artifacts.testing.fixture_path`); a missing / `auto` `filename`, `sha256` and `size` are derived from
the fixture (`fixture_filename`, SHA-256 and size of the file). Explicit values are kept, so a case can lie about a hash
on purpose.

### Evidence beyond the cases

`scripts/dev.py mutation` (`tests/mutation/run.py`) switches every enabled control off in turn and re-runs all cells: a control
is killed when at least one cell fails (`reports/mutation.{json,md}`; exit 1 on a survivor, which is fixed by adding
paired cases for that control, never by weakening anything). `scripts/dev.py adaptive` (`tests/redteam/adaptive/run.py`)
generates deterministic variants (paraphrase, base64, hex, url, zero-width, homoglyph, Polish, split, case, leetspeak)
of the negative cases and reports detection with Wilson intervals (`reports/adaptive.{json,md}`). Both are merged into
`reports/summary.json` (`mutation`, `adaptive`) and mentioned in the pytest terminal summary.

`ACL_TEST_MODE=live` (`make test-live`) runs the cases that list `live` in `modes` three times and passes on 2 of 3.

Reports (gitignored `reports/`): `junit.xml`, `summary.json` (shape of `GuardQualitySummary`: per-control
tp/fp/tn/fn, detection rate and FPR with Wilson 95% CIs, per-preset rows, layer attribution by `decided_phase`,
ASR) and `case_lint.json`. The case lint reports warnings for the rules above; `ACL_STRICT_CASE_LINT=1` makes them fail.

