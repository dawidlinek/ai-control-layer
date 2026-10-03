"""Case lint (>=5 positive/negative per control, paired negatives) and the report on the real corpus."""

from __future__ import annotations

import json
import os
import warnings
from typing import Any

from harness.cases import load_all_cases
from harness.lint import lint_cases, policy_controls
from harness.plugin import REPORTS, lint_corpus, write_json


def mk(cid: str, control: str, kind: str, pair: str | None = None, **kw: Any) -> dict[str, Any]:
    c = {"id": cid, "control": control, "kind": kind, "input": "x", "expect": {"action": "allow", "rule_id": None}}
    if pair:
        c["pair"] = pair
    return {**c, **kw}


def full_set(control: str) -> list[dict[str, Any]]:
    cases = []
    for i in range(5):
        cases.append(mk(f"{control}-p{i}", control, "positive", pair=f"{control}-{i}"))
        cases.append(mk(f"{control}-n{i}", control, "negative", pair=f"{control}-{i}", expect={"action": "block"}))
    cases[0]["matrix"] = {"balanced": "allow"}
    return cases


def codes(report, level: str | None = None) -> list[str]:  # type: ignore[no-untyped-def]
    return [i.code for i in report.issues if level is None or i.level == level]


def test_complete_control_is_clean() -> None:
    rep = lint_cases(full_set("SEC-A-01"))
    assert rep.errors == [] and rep.warnings == []
    assert rep.per_control["SEC-A-01"] == {"positive": 5, "negative": 5, "paired_negatives": 5, "matrix_cases": 1}


def test_too_few_cases_are_reported_per_kind() -> None:
    rep = lint_cases(full_set("SEC-A-01")[:-2])  # drops the last positive+negative pair... leaving 4/4
    assert "few-positives" in codes(rep, "warn") and "few-negatives" in codes(rep, "warn")


def test_unpaired_and_orphan_negatives() -> None:
    cases = full_set("SEC-A-01")
    cases.append(mk("lonely", "SEC-A-01", "negative"))
    cases.append(mk("orphan", "SEC-A-01", "negative", pair="no-positive-has-this"))
    rep = lint_cases(cases)
    assert [i.case for i in rep.issues if i.code == "unpaired-negative"] == ["lonely"]
    assert [i.case for i in rep.issues if i.code == "orphan-negative"] == ["orphan"]


def test_structural_errors() -> None:
    bad = [
        mk("dup", "SEC-A-01", "positive"),
        mk("dup", "SEC-A-01", "positive"),
        mk("k", "SEC-A-01", "maybe"),
        mk("a", "SEC-A-01", "positive", expect={"action": "explode"}),
        mk("pt", "SEC-A-01", "positive", point="nowhere"),
        mk("m", "SEC-A-01", "positive", matrix={"relaxed": "allow"}),
        {"id": "nocontrol", "kind": "positive", "input": "x", "expect": {"action": "allow"}},
    ]
    found = set(codes(lint_cases(bad), "error"))
    assert {"duplicate-id", "bad-kind", "bad-expect", "bad-point", "bad-matrix", "missing-control"} <= found


def test_infrastructure_cases_are_exempt() -> None:
    rep = lint_cases([mk("smoke", "none", "positive")])
    assert rep.issues == [] and rep.per_control == {}


def test_policy_cross_checks() -> None:
    rep = lint_cases(full_set("SEC-NOPE-99"), known_controls={"SEC-REAL-01": True, "SEC-OFF-01": False})
    assert "unknown-control" in codes(rep, "warn")
    uncovered = {i.control: i.level for i in rep.issues if i.code == "uncovered-control"}
    assert uncovered == {"SEC-REAL-01": "warn", "SEC-OFF-01": "info"}


def test_report_serialises() -> None:
    d = lint_cases(full_set("SEC-A-01")).to_dict()
    assert json.loads(json.dumps(d))["errors"] == 0


def test_case_corpus_lint_report() -> None:
    """The real corpus: structural errors fail; the rest is a warning report (strict: ACL_STRICT_CASE_LINT=1)."""
    rep = lint_corpus()
    write_json(REPORTS / "case_lint.json", rep.to_dict())
    assert not rep.errors, rep.format(limit=50)
    if rep.warnings:
        warnings.warn(rep.format(limit=10), UserWarning, stacklevel=1)
    if os.environ.get("ACL_STRICT_CASE_LINT") == "1":
        assert not rep.warnings, rep.format(limit=50)


def test_corpus_and_policy_are_loadable() -> None:
    assert isinstance(load_all_cases(), list)
    assert isinstance(policy_controls(), dict) and policy_controls()
