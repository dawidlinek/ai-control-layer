"""Case runner: evaluates a YAML case against an engine and checks its expectations.

    expect.action          primary decision action (or `matrix[preset]` for matrix cases)
    expect.rule_id         str | [str] | null. null = no rule may fire. Matrix cells expecting `allow` skip it.
    expect.redaction       {contains: [...], not_contains: [...], presets: [...]} checked against the payload
                           AFTER `apply_replacements` with the redact/pseudonymise findings of the decision
                           (only when a redact/pseudonymise transform is expected or was applied)
    expect.applied         actions that must all be in `decision.applied`
    expect.would_action    expected `decision.would_action`
    expect.decided_by / decided_phase / final   exact match on the decision fields

Live mode runs every case three times and passes on 2 of 3 (the individual runs are kept in the result).
The runner is independent of how the engine is obtained: it takes `evaluate(ctx) -> Decision`.
"""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from harness.cases import build_context, expected_action, primary_preset

from acl.contracts.common import Action
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext
from acl.engine.text import apply_replacements, iter_texts

LIVE_RUNS = 3
LIVE_REQUIRED = 2
_QUIET = {Action.allow, Action.monitor}
_TEXT_TRANSFORMS = {Action.redact, Action.pseudonymise}


@dataclass
class RunOutcome:
    """One evaluation of one case cell."""

    action: str
    would_action: str | None
    decided_by: str | None
    decided_phase: str | None
    rule_ids: list[str]
    fired_controls: list[str]
    applied: list[str]
    latency_ms: float
    failures: list[str]

    @property
    def passed(self) -> bool:
        return not self.failures

    @property
    def effective_action(self) -> str:
        """What enforcement would do: `would_action` in monitor mode, else the action."""
        return self.would_action or self.action

    @property
    def intervened(self) -> bool:
        return Action(self.effective_action) not in _QUIET


@dataclass
class CaseResult:
    case_id: str
    file: str
    control: str
    kind: str
    pair: str | None
    preset: str
    primary: bool  # the cell used for per-control statistics
    expected: str | None
    outcome: RunOutcome
    runs: list[RunOutcome] = field(default_factory=list)  # live mode: all runs
    live: bool = False

    @property
    def passed(self) -> bool:
        if self.live:
            return sum(r.passed for r in self.runs) >= LIVE_REQUIRED
        return self.outcome.passed

    @property
    def flaky(self) -> bool:
        return self.live and len({(r.action, r.passed) for r in self.runs}) > 1


RESULTS: list[CaseResult] = []


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def redacted_payload(ctx: InspectionContext, decision: Decision) -> tuple[Any, int]:
    """Payload after applying the decision's redact/pseudonymise findings; also the number of skipped findings.

    Uses the normalised payload when a normaliser published one (controls report offsets against it).
    """
    base = ctx.attributes.get("payload")
    if base is None or not hasattr(base, "kind"):
        base = ctx.payload
    findings = [f for v in decision.verdicts if v.action in _TEXT_TRANSFORMS for f in v.findings]
    out, skipped = apply_replacements(base, findings)
    return out, len(skipped)


def _check_redaction(spec: dict[str, Any], ctx: InspectionContext, decision: Decision, failures: list[str]) -> None:
    payload, skipped = redacted_payload(ctx, decision)
    texts = "\n".join(t for _, t in iter_texts(payload))
    dump = json.dumps(payload.model_dump(mode="json"), ensure_ascii=False)
    for needle in _as_list(spec.get("contains")):
        if needle not in texts and needle not in dump:
            failures.append(f"redaction: expected {needle!r} in transformed payload (skipped findings: {skipped})")
    for needle in _as_list(spec.get("not_contains")):
        if needle in texts or needle in dump:
            failures.append(f"redaction: {needle!r} still present in transformed payload (skipped findings: {skipped})")


def check_expectations(case: dict[str, Any], preset: str, ctx: InspectionContext, decision: Decision) -> list[str]:
    failures: list[str] = []
    expect = case.get("expect") or {}
    want = expected_action(case, preset)
    if want is None:
        return [f"case defines no expected action for preset {preset!r}"]
    if decision.action.value != want:
        failures.append(
            f"expected action {want}, got {decision.action.value} "
            f"(would={decision.would_action.value if decision.would_action else None}, rules={decision.rule_ids}, "
            f"decided_by={decision.decided_by})"
        )

    if "rule_id" in expect and not (case.get("matrix") and want == "allow"):
        wanted_rules = _as_list(expect["rule_id"])
        fired = set(decision.rule_ids) | {r for v in decision.verdicts if v.action != Action.allow for r in v.rule_ids}
        if not wanted_rules:
            if decision.rule_ids:
                failures.append(f"expected no rules, got {decision.rule_ids}")
        else:
            missing = [r for r in wanted_rules if r not in fired]
            if missing:
                failures.append(f"expected rule(s) {missing} among {sorted(fired)}")

    for key in ("decided_by", "decided_phase"):
        if key in expect:
            got = getattr(decision, key)
            got = got.value if hasattr(got, "value") else got
            if got != expect[key]:
                failures.append(f"expected {key}={expect[key]!r}, got {got!r}")
    if "final" in expect and decision.final != expect["final"]:
        failures.append(f"expected final={expect['final']}, got {decision.final}")
    if "would_action" in expect:
        got = decision.would_action.value if decision.would_action else None
        if got != expect["would_action"]:
            failures.append(f"expected would_action={expect['would_action']!r}, got {got!r}")
    for a in _as_list(expect.get("applied")):
        if a not in [x.value for x in decision.applied]:
            failures.append(f"expected {a!r} in applied={[x.value for x in decision.applied]}")

    red = expect.get("redaction")
    if red and (not red.get("presets") or preset in red["presets"]):
        transforms = {x.value for x in decision.applied} & {a.value for a in _TEXT_TRANSFORMS}
        if want in {a.value for a in _TEXT_TRANSFORMS} or transforms:
            _check_redaction(red, ctx, decision, failures)
    return failures


class CaseRunner:
    def __init__(
        self,
        evaluate: Callable[[InspectionContext], Decision],
        *,
        live: bool = False,
        policy_version: str = "test",
        record: bool = True,
    ) -> None:
        self.evaluate = evaluate
        self.live = live
        self.policy_version = policy_version
        self.record = record

    def run_once(self, case: dict[str, Any], preset: str) -> RunOutcome:
        ctx = build_context(case, preset, policy_version=self.policy_version)
        t0 = time.perf_counter()
        decision = self.evaluate(ctx)
        elapsed = (time.perf_counter() - t0) * 1000
        return RunOutcome(
            action=decision.action.value,
            would_action=decision.would_action.value if decision.would_action else None,
            decided_by=decision.decided_by,
            decided_phase=decision.decided_phase.value if decision.decided_phase else None,
            rule_ids=list(decision.rule_ids),
            fired_controls=sorted({v.control_id for v in decision.verdicts if v.action != Action.allow}),
            applied=[a.value for a in decision.applied],
            latency_ms=elapsed,
            failures=check_expectations(case, preset, ctx, decision),
        )

    def run(self, case: dict[str, Any], preset: str) -> CaseResult:
        """Evaluate one case cell (3× with 2-of-3 in live mode) and record the result. Never raises on mismatch."""
        n = LIVE_RUNS if self.live else 1
        runs = [self.run_once(case, preset) for _ in range(n)]
        if self.live:
            counts = Counter((r.action, r.passed) for r in runs)
            modal = counts.most_common(1)[0][0]
            outcome = next(r for r in runs if (r.action, r.passed) == modal)
        else:
            outcome = runs[0]
        result = CaseResult(
            case_id=case["id"],
            file=case.get("_file", ""),
            control=str(case.get("control", "none")),
            kind=str(case.get("kind", "positive")),
            pair=case.get("pair"),
            preset=preset,
            primary=preset == primary_preset(case),
            expected=expected_action(case, preset),
            outcome=outcome,
            runs=runs if self.live else [],
            live=self.live,
        )
        if self.record:
            RESULTS.append(result)
        return result


def assert_result(result: CaseResult) -> None:
    if result.passed:
        return
    runs = result.runs or [result.outcome]
    lines = [f"{f}" for r in runs for f in r.failures]
    prefix = (
        f"live: {sum(r.passed for r in runs)}/{len(runs)} runs passed (need {LIVE_REQUIRED}); " if result.live else ""
    )
    raise AssertionError(prefix + "; ".join(dict.fromkeys(lines)))


def run_case(case: dict[str, Any], preset: str) -> CaseResult:
    """Entry point used by the pytest collector: session host, record, raise on mismatch."""
    from harness.host import get_host

    host = get_host()
    runner = CaseRunner(host.evaluate, live=not host.deterministic)
    result = runner.run(case, preset)
    assert_result(result)
    return result
