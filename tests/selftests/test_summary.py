"""summary.json: shape (validated against GuardQualitySummary), per-control confusion counts, CIs, attribution."""

from __future__ import annotations

import json
from typing import Any

import pytest
from harness.metrics import build_summary, validate_summary
from harness.runner import CaseResult, RunOutcome
from harness.stats import wilson

from acl.contracts.admin import GuardQualitySummary


def outcome(
    action: str = "allow",
    *,
    fired: list[str] | None = None,
    would: str | None = None,
    phase: str | None = None,
    failures: list[str] | None = None,
) -> RunOutcome:
    return RunOutcome(
        action=action,
        would_action=would,
        decided_by=(fired or [None])[0] if action != "allow" else None,
        decided_phase=phase,
        rule_ids=list(fired or []),
        fired_controls=list(fired or []),
        applied=[],
        latency_ms=1.0,
        failures=failures or [],
    )


def result(
    cid: str,
    control: str,
    kind: str,
    out: RunOutcome,
    *,
    preset: str = "balanced",
    primary: bool = True,
    expected: str | None = None,
) -> CaseResult:
    return CaseResult(
        case_id=cid,
        file="x.yaml",
        control=control,
        kind=kind,
        pair=None,
        preset=preset,
        primary=primary,
        expected=expected,
        outcome=out,
    )


def sample() -> list[CaseResult]:
    caught = outcome("block", fired=["SEC-A-01"], phase="deterministic")
    return [
        # SEC-A-01: 3 negatives (2 caught, 1 missed), 4 positives (1 false positive)
        result("a-n1", "SEC-A-01", "negative", caught),
        result("a-n2", "SEC-A-01", "negative", outcome("pseudonymise", fired=["SEC-A-01"], phase="deterministic")),
        result("a-n3", "SEC-A-01", "negative", outcome("allow")),
        result("a-p1", "SEC-A-01", "positive", outcome("allow")),
        result("a-p2", "SEC-A-01", "positive", outcome("allow")),
        result("a-p3", "SEC-A-01", "positive", outcome("allow")),
        result(
            "a-p4",
            "SEC-A-01",
            "positive",
            outcome("block", fired=["SEC-A-01"], phase="deterministic", failures=["expected allow"]),
        ),
        # SEC-B-01: negative caught only by ANOTHER control -> FN for B, counted in caught_by_other
        result("b-n1", "SEC-B-01", "negative", outcome("block", fired=["SEC-A-01"], phase="semantic_l1")),
        # monitor cell: enforcement would block, but the action is monitor; excluded from ASR, included per preset
        result(
            "a-n1",
            "SEC-A-01",
            "negative",
            outcome("monitor", would="block", fired=["SEC-A-01"], phase="deterministic"),
            preset="monitor",
            primary=False,
        ),
        # infrastructure case
        result("smoke", "none", "positive", outcome("allow")),
    ]


def test_summary_validates_against_the_contract() -> None:
    summary = build_summary(sample(), mode="deterministic")
    validate_summary(summary)
    model = GuardQualitySummary.model_validate(json.loads(json.dumps(summary)))  # JSON round trip
    assert model.suite == "system-cases" and model.mode == "deterministic"
    assert {c.control_id for c in model.per_control} == {"SEC-A-01", "SEC-B-01"}


def test_empty_results_still_validate() -> None:
    summary = build_summary([], mode="live")
    validate_summary(summary)
    assert summary["per_control"] == [] and summary["asr"] is None


def test_per_control_confusion_and_wilson_intervals() -> None:
    summary = build_summary(sample(), mode="deterministic")
    a = next(c for c in summary["per_control"] if c["control_id"] == "SEC-A-01")
    assert (a["tp"], a["fn"], a["tn"], a["fp"]) == (2, 1, 3, 1)
    p, lo, hi = wilson(2, 3)
    assert a["detection_rate"] == {
        "value": pytest.approx(p, abs=1e-6),
        "ci_low": pytest.approx(lo, abs=1e-6),
        "ci_high": pytest.approx(hi, abs=1e-6),
        "n": 3,
    }
    p, lo, hi = wilson(1, 4)
    assert a["fpr"]["value"] == pytest.approx(p, abs=1e-6) and a["fpr"]["n"] == 4
    assert a["fpr"]["ci_low"] == pytest.approx(lo, abs=1e-6) and a["fpr"]["ci_high"] == pytest.approx(hi, abs=1e-6)
    b = next(c for c in summary["per_control"] if c["control_id"] == "SEC-B-01")
    assert (b["tp"], b["fn"]) == (0, 1) and b["fpr"] is None
    assert summary["extra"]["caught_by_other"] == 1


def test_asr_fpr_and_layers_use_enforcing_cells_only() -> None:
    s = build_summary(sample(), mode="deterministic")
    # negatives (primary, non-monitor): a-n1 caught, a-n2 caught, a-n3 missed, b-n1 caught by someone -> 1 of 4 succeeds
    assert s["asr"]["n"] == 4 and s["asr"]["value"] == pytest.approx(0.25)
    assert s["fpr_per_call"]["n"] == 4 and s["fpr_per_call"]["value"] == pytest.approx(0.25)
    assert s["layer_attribution"] == {"deterministic": 2, "semantic_l1": 1, "missed": 1}


def test_per_preset_rows_include_monitor_by_would_action() -> None:
    s = build_summary(sample(), mode="deterministic")
    assert set(s["per_preset"]) == {"balanced", "monitor"}
    mon = s["per_preset"]["monitor"]
    assert mon["cells"] == 1 and mon["detection_rate"] == 1.0  # would_action=block counts as detection
    bal = s["per_preset"]["balanced"]
    assert bal["cells"] == 9 and bal["passed"] == 8 and bal["pass_rate"] == pytest.approx(8 / 9, abs=1e-5)
    assert all(isinstance(v, float) for row in s["per_preset"].values() for v in row.values())


def test_failures_and_flaky_are_listed() -> None:
    results = sample()
    live = result("flaky-1", "SEC-A-01", "negative", outcome("block", fired=["SEC-A-01"], phase="deterministic"))
    live.live = True
    live.runs = [outcome("block", fired=["SEC-A-01"]), outcome("allow"), outcome("block", fired=["SEC-A-01"])]
    s = build_summary([*results, live], mode="live", extra={"engine_host": {"mode": "app"}})
    assert s["extra"]["failed_cases"] == ["a-p4[balanced]"]
    assert s["extra"]["flaky_cases"] == ["flaky-1[balanced]"]
    assert s["extra"]["engine_host"] == {"mode": "app"} and s["mode"] == "live"


def test_leak_rate_by_channel_passes_through() -> None:
    s = build_summary([], mode="deterministic", leak_rate_by_channel={"final_text": 0.0, "sink": 0.25})
    validate_summary(s)
    assert s["leak_rate_by_channel"]["sink"] == 0.25


def test_contract_rejects_a_malformed_summary() -> None:
    bad: dict[str, Any] = build_summary([], mode="deterministic")
    bad["mode"] = "sometimes"
    with pytest.raises(ValueError):
        validate_summary(bad)
