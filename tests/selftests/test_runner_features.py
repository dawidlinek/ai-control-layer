"""Runner features, exercised with a tiny fake control in a test-only registry (no real controls needed)."""

from __future__ import annotations

from typing import Any

import pytest
from harness.cases import build_context, mode_markers, primary_preset
from harness.runner import CaseRunner
from selftests.fakes import FAKE_ID, fake_engine, sync_evaluator

from acl.contracts.common import Action, InspectionPoint


def runner_for(**params: Any) -> CaseRunner:
    engine, _ = fake_engine(**params)
    return CaseRunner(sync_evaluator(engine), record=False)


def case(**kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "t-case",
        "control": FAKE_ID,
        "kind": "negative",
        "input": "this contains SEKRET inside",
        "expect": {"action": "pseudonymise", "rule_id": FAKE_ID},
    }
    return {**base, **kw}


# ---------------------------------------------------------------- action + rule id


def test_action_and_rule_id_pass() -> None:
    res = runner_for(replacement="<X_1>").run(case(), "balanced")
    assert res.passed and res.outcome.action == "pseudonymise" and res.outcome.rule_ids == [FAKE_ID]
    assert res.outcome.decided_by == FAKE_ID and res.outcome.decided_phase == "deterministic"


def test_wrong_action_fails_with_a_useful_message() -> None:
    res = runner_for(action="block").run(case(), "balanced")
    assert not res.passed
    assert "expected action pseudonymise, got block" in res.outcome.failures[0]


def test_rule_id_null_means_no_rule_may_fire() -> None:
    ok = runner_for().run(case(input="nothing here", expect={"action": "allow", "rule_id": None}), "balanced")
    assert ok.passed
    bad = runner_for().run(case(expect={"action": "pseudonymise", "rule_id": None}), "balanced")
    assert not bad.passed and "expected no rules" in bad.outcome.failures[0]


def test_missing_rule_fails_and_rule_list_is_all_of() -> None:
    res = runner_for().run(case(expect={"action": "pseudonymise", "rule_id": "TST-OTHER-99"}), "balanced")
    assert not res.passed and "TST-OTHER-99" in res.outcome.failures[0]
    res = runner_for().run(case(expect={"action": "pseudonymise", "rule_id": [FAKE_ID, "TST-OTHER-99"]}), "balanced")
    assert not res.passed


def test_decision_field_expectations() -> None:
    expect = {
        "action": "block",
        "rule_id": FAKE_ID,
        "decided_by": FAKE_ID,
        "decided_phase": "deterministic",
        "final": True,
    }
    assert runner_for(action="block").run(case(expect=expect), "balanced").passed
    expect["decided_by"] = "TST-NOPE-01"
    assert not runner_for(action="block").run(case(expect=expect), "balanced").passed


# ---------------------------------------------------------------- redaction


def test_redaction_checks_the_payload_after_apply_replacements() -> None:
    expect = {
        "action": "pseudonymise",
        "rule_id": FAKE_ID,
        "redaction": {"contains": ["this contains <X_1> inside"], "not_contains": ["SEKRET"]},
    }
    assert runner_for(replacement="<X_1>").run(case(expect=expect), "balanced").passed


def test_redaction_fails_when_the_value_survives() -> None:
    expect = {"action": "pseudonymise", "rule_id": FAKE_ID, "redaction": {"not_contains": ["SEKRET"]}}
    # control flags but provides no replacement -> nothing is redacted -> the oracle must notice
    res = runner_for(replacement=None).run(case(expect=expect), "balanced")
    assert not res.passed and "still present" in res.outcome.failures[0]
    res = runner_for(replacement="<X_1>").run(
        case(expect={**expect, "redaction": {"contains": ["<NOT_THERE>"]}}), "balanced"
    )
    assert not res.passed and "expected '<NOT_THERE>'" in res.outcome.failures[0]


def test_redaction_on_tool_call_arguments_and_multiple_fields() -> None:
    c = case(
        point="tool_call",
        input={"tool": "mail.send", "arguments": {"to": "a@corp.example", "body": "SEKRET and SEKRET"}},
        expect={
            "action": "pseudonymise",
            "rule_id": FAKE_ID,
            "redaction": {"contains": ["<X_1>"], "not_contains": ["SEKRET"]},
        },
    )
    assert runner_for(replacement="<X_1>").run(c, "balanced").passed


def test_redaction_skipped_when_not_a_redacting_action() -> None:
    c = case(expect={"action": "block", "rule_id": FAKE_ID, "redaction": {"not_contains": ["SEKRET"]}})
    assert runner_for(action="block").run(c, "balanced").passed


# ---------------------------------------------------------------- matrix


MATRIX = {"monitor": "monitor", "balanced": "pseudonymise", "strict": "route_local", "paranoid": "block"}


def test_matrix_runs_each_preset_with_its_own_expectation() -> None:
    by_preset = {"balanced": "pseudonymise", "strict": "route_local", "paranoid": "block", "monitor": "block"}
    runner = runner_for(by_preset=by_preset, replacement="<X_1>")
    c = case(matrix=MATRIX, expect={"rule_id": FAKE_ID, "redaction": {"not_contains": ["SEKRET"]}})
    results = {p: runner.run(c, p) for p in MATRIX}
    assert all(r.passed for r in results.values()), {p: r.outcome.failures for p, r in results.items()}
    # monitor never enforces: the primary action is `monitor`, the would-be action is kept
    assert results["monitor"].outcome.would_action == "block" and results["monitor"].outcome.intervened
    assert results["balanced"].primary and not results["strict"].primary
    assert primary_preset(c) == "balanced"


def test_matrix_wrong_cell_fails_only_that_cell() -> None:
    runner = runner_for(by_preset={"strict": "block"})
    c = case(matrix={"balanced": "pseudonymise", "strict": "route_local"}, expect={"rule_id": FAKE_ID})
    assert runner.run(c, "balanced").passed
    strict = runner.run(c, "strict")
    assert not strict.passed and "expected action route_local, got block" in strict.outcome.failures[0]


def test_matrix_allow_cell_does_not_require_the_rule() -> None:
    runner = runner_for(by_preset={"monitor": "allow", "balanced": "block"})
    c = case(matrix={"monitor": "allow", "balanced": "block"}, expect={"rule_id": FAKE_ID})
    assert runner.run(c, "monitor").passed and runner.run(c, "balanced").passed


# ---------------------------------------------------------------- principal and session


def test_principal_is_passed_to_the_control() -> None:
    runner = runner_for(allow_groups=["admins"])
    allowed = case(principal={"username": "adam", "groups": ["admins"]}, expect={"action": "allow", "rule_id": None})
    assert runner.run(allowed, "balanced").passed
    assert runner.run(case(principal={"username": "x", "groups": ["developers"]}), "balanced").passed


def test_principal_extra_fields() -> None:
    ctx = build_context(
        case(principal={"username": "bot", "groups": ["agents/research-bot"], "kind": "agent"}), "strict"
    )
    assert ctx.principal.kind.value == "agent" and ctx.principal.groups == ["agents/research-bot"]
    assert ctx.preset.value == "strict"


def test_session_presets_and_overrides() -> None:
    runner = runner_for(needs_taint="untrusted", action="block")
    clean = case(expect={"action": "allow", "rule_id": None})
    tainted = case(session="untrusted", expect={"action": "block", "rule_id": FAKE_ID})
    assert runner.run(clean, "balanced").passed
    assert runner.run(tainted, "balanced").passed
    ctx = build_context(case(session={"preset": "untrusted_sensitive", "step": 4}), "balanced")
    assert ctx.session.step == 4
    assert ctx.session.labels.integrity.value == "untrusted"
    assert ctx.session.labels.confidentiality.value == "confidential"
    assert {t.value for t in ctx.session.labels.taint} == {"untrusted", "sensitive"}


def test_unknown_session_preset_is_an_error() -> None:
    with pytest.raises(KeyError):
        build_context(case(session="nope"), "balanced")


def test_points_without_shorthand_use_full_payloads() -> None:
    c = case(point="mcp_tools_list", input={"kind": "mcp", "server": "demo", "method": "tools/list"})
    ctx = build_context(c, "balanced")
    assert ctx.point == InspectionPoint.mcp_tools_list and ctx.payload.kind == "mcp"


# ---------------------------------------------------------------- modes and live (2-of-3)


def test_mode_markers() -> None:
    assert mode_markers({}, "deterministic") == []
    assert mode_markers({"modes": ["deterministic", "live"]}, "deterministic") == []
    assert mode_markers({"modes": ["live"]}, "deterministic") == ["skip", "live"]
    assert mode_markers({"modes": ["live"]}, "live") == ["live"]
    assert mode_markers({"modes": ["deterministic", "live"]}, "live") == ["live"]
    assert mode_markers({}, "live") == ["skip", "live"]


def _live(script: list[str]) -> CaseRunner:
    engine, _ = fake_engine(script=script)
    return CaseRunner(sync_evaluator(engine), live=True, record=False)


def test_live_passes_with_two_of_three() -> None:
    res = _live(["block", "allow", "block"]).run(case(expect={"action": "block", "rule_id": FAKE_ID}), "balanced")
    assert res.passed and len(res.runs) == 3 and res.flaky
    assert [r.action for r in res.runs] == ["block", "allow", "block"]


def test_live_fails_with_one_of_three() -> None:
    res = _live(["block", "allow", "allow"]).run(case(expect={"action": "block", "rule_id": FAKE_ID}), "balanced")
    assert not res.passed and res.flaky


def test_live_unanimous_is_not_flaky() -> None:
    res = _live(["block"] * 3).run(case(expect={"action": "block", "rule_id": FAKE_ID}), "balanced")
    assert res.passed and not res.flaky


def test_results_are_recorded_by_default() -> None:
    from harness import runner as runner_mod

    engine, _ = fake_engine()
    before = len(runner_mod.RESULTS)
    try:
        CaseRunner(sync_evaluator(engine)).run(case(id="recorded-1"), "balanced")
        assert len(runner_mod.RESULTS) == before + 1 and runner_mod.RESULTS[-1].case_id == "recorded-1"
    finally:
        del runner_mod.RESULTS[before:]


def test_fake_control_uses_the_real_decision_engine() -> None:
    engine, _ = fake_engine(action="block")
    ctx = build_context(case(), "balanced")
    decision = sync_evaluator(engine)(ctx)
    assert decision.action == Action.block and decision.final
