"""`expect.labels_after`: pass and fail cases, label-only metrics, evidence merge, artifact fixture shorthand."""

from __future__ import annotations

import hashlib
import json
import sys
import types
from pathlib import Path
from typing import Any

import pytest
from harness.cases import build_context, resolve_artifact_fixture
from harness.metrics import build_summary, merge_evidence, remerge_summary_file, validate_summary
from harness.runner import CaseRunner
from selftests.fakes import FAKE_ID, fake_engine, sync_evaluator

from acl.contracts.admin import AdaptiveTierSummary, MutationCoverage
from acl.contracts.inspection import ArtifactPayload

RAISE = {"integrity_untrusted": True, "confidentiality": "confidential", "taint": ["sensitive"]}


def runner_for(**params: Any) -> CaseRunner:
    engine, _ = fake_engine(action="allow", **params)
    return CaseRunner(sync_evaluator(engine), record=False)


def case(labels_after: dict[str, Any], **kw: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "id": "t-labels",
        "control": FAKE_ID,
        "kind": "negative",
        "input": "this contains SEKRET inside",
        "expect": {"action": "allow", "rule_id": FAKE_ID, "labels_after": labels_after},
    }
    return {**base, **kw}


# ---------------------------------------------------------------- the expectation


def test_raised_labels_match_exactly() -> None:
    spec = {"integrity": "untrusted", "confidentiality": "confidential", "taint": ["sensitive", "untrusted"]}
    res = runner_for(labels=RAISE).run(case(spec), "balanced")
    assert res.passed, res.outcome.failures
    assert res.label_case
    assert res.outcome.labels_after["integrity"] == "untrusted"
    assert res.outcome.labels_after["confidentiality"] == "confidential"
    assert res.outcome.labels_after["taint"] == "sensitive,untrusted"
    assert res.outcome.label_controls == [FAKE_ID]
    # an allow verdict that raised labels counts as "fired" for rule_id, but rule_ids of the decision stay empty
    assert res.outcome.rule_ids == []


def test_wrong_integrity_fails() -> None:
    res = runner_for(labels={"confidentiality": "confidential"}).run(case({"integrity": "untrusted"}), "balanced")
    assert not res.passed
    assert "expected integrity='untrusted', got 'trusted'" in res.outcome.failures[0]


def test_wrong_confidentiality_fails() -> None:
    res = runner_for(labels={"integrity_untrusted": True}).run(case({"confidentiality": "confidential"}), "balanced")
    assert not res.passed
    assert "expected confidentiality='confidential', got 'public'" in res.outcome.failures[0]


def test_missing_taint_flag_fails_and_extra_flags_are_fine() -> None:
    res = runner_for(labels={"taint": ["sensitive"]}).run(case({"taint": ["sensitive", "egress_used"]}), "balanced")
    assert not res.passed and "egress_used" in res.outcome.failures[0]
    ok = runner_for(labels=RAISE).run(case({"taint": ["sensitive"]}), "balanced")  # `untrusted` also present: fine
    assert ok.passed, ok.outcome.failures


def test_taint_absent_fails_when_the_flag_is_present() -> None:
    res = runner_for(labels=RAISE).run(case({"taint_absent": ["sensitive"]}), "balanced")
    assert not res.passed and "must be absent" in res.outcome.failures[0]
    ok = runner_for(labels={"integrity_untrusted": True}).run(case({"taint_absent": ["sensitive"]}), "balanced")
    assert ok.passed, ok.outcome.failures


def test_no_hit_keeps_the_session_labels_as_input() -> None:
    """A missing label update means labels_after == the session's own labels (labels only rise)."""
    quiet = case({"integrity": "untrusted", "taint": ["untrusted"]}, input="nothing here", session="untrusted")
    quiet["expect"] = {**quiet["expect"], "rule_id": None}
    res = runner_for(labels=RAISE).run(quiet, "balanced")
    assert res.passed, res.outcome.failures
    assert res.outcome.label_controls == []
    clean = case({"integrity": "trusted"}, input="nothing here")
    clean["expect"] = {**clean["expect"], "rule_id": None}
    assert runner_for(labels=RAISE).run(clean, "balanced").passed


def test_labels_never_fall() -> None:
    c = case({"integrity": "trusted"}, session="untrusted")
    c["expect"] = {**c["expect"], "rule_id": None}
    res = runner_for(labels={"integrity_untrusted": False}).run(c, "balanced")
    assert not res.passed and "expected integrity='trusted', got 'untrusted'" in res.outcome.failures[0]


def test_blocked_decision_discards_label_updates() -> None:
    engine, _ = fake_engine(action="block", labels=RAISE)
    runner = CaseRunner(sync_evaluator(engine), record=False)
    c = case({"integrity": "trusted", "confidentiality": "public", "taint_absent": ["sensitive"]})
    c["expect"] = {**c["expect"], "action": "block"}
    res = runner.run(c, "balanced")
    assert res.passed, res.outcome.failures
    assert res.outcome.label_controls == []  # nothing raised: the labels did not make it into labels_after


def test_cases_without_the_key_are_not_label_cases() -> None:
    plain = case({}, expect={"action": "allow", "rule_id": FAKE_ID})
    res = runner_for(labels=RAISE).run(plain, "balanced")
    assert res.passed and not res.label_case


# ---------------------------------------------------------------- metrics for label-only controls


def _results(*specs: tuple[str, str, bool]) -> list[Any]:
    """(kind, raises-labels, passes) -> CaseResults of the label control."""
    out = []
    for i, (kind, raises, passes) in enumerate(specs):
        params: dict[str, Any] = {"labels": RAISE} if raises == "raise" else {}
        c = case({"integrity": "untrusted"} if passes else {"integrity": "trusted"}, id=f"t-{i}", kind=kind)
        if raises != "raise":
            c["input"] = "nothing here"
            c["expect"] = {"action": "allow", "rule_id": None, "labels_after": {"integrity": "trusted"}}
            if not passes:
                c["expect"]["labels_after"] = {"integrity": "untrusted"}
        runner = runner_for(**params)
        runner.record = False
        out.append(runner.run(c, "balanced"))
    return out


def test_label_cases_count_as_tp_fn_fp_tn_and_stay_out_of_intervention_rates() -> None:
    results = _results(
        ("negative", "raise", True),  # raised + expected -> TP
        ("negative", "raise", True),  # TP
        ("negative", "none", False),  # control raised nothing, labels expected -> FN
        ("positive", "none", True),  # nothing raised, nothing expected -> TN
        ("positive", "raise", False),  # raised labels the case said must not appear -> FP
    )
    s = build_summary(results, mode="deterministic")
    validate_summary(s)
    c = next(x for x in s["per_control"] if x["control_id"] == FAKE_ID)
    assert (c["tp"], c["fn"], c["tn"], c["fp"]) == (2, 1, 1, 1)
    assert s["asr"] is None and s["fpr_per_call"] is None and s["layer_attribution"] == {}
    assert "detection_rate" not in s["per_preset"]["balanced"]


# ---------------------------------------------------------------- evidence merge


def _mutation() -> dict[str, Any]:
    return json.loads(
        MutationCoverage(
            generated_at="2026-10-04T10:00:00Z",  # type: ignore[arg-type]
            suite="system-cases",
            controls_mutated=2,
            controls_killed=2,
            score=1.0,
        ).model_dump_json()
    )


def _adaptive() -> dict[str, Any]:
    return json.loads(
        AdaptiveTierSummary(generated_at="2026-10-04T10:00:00Z", variants=3).model_dump_json()  # type: ignore[arg-type]
    )


def test_merge_evidence_adds_valid_reports_only(tmp_path: Path) -> None:
    summary = build_summary([], mode="deterministic")
    assert merge_evidence(dict(summary), tmp_path).get("mutation") is None  # nothing there
    (tmp_path / "mutation.json").write_text(json.dumps(_mutation()), encoding="utf-8")
    (tmp_path / "adaptive.json").write_text(json.dumps({"variants": "many"}), encoding="utf-8")  # invalid
    merged = merge_evidence(dict(summary), tmp_path)
    assert merged["mutation"]["controls_killed"] == 2 and "adaptive" not in merged
    (tmp_path / "adaptive.json").write_text(json.dumps(_adaptive()), encoding="utf-8")
    merged = merge_evidence(dict(summary), tmp_path)
    validate_summary(merged)
    assert merged["adaptive"]["variants"] == 3
    (tmp_path / "mutation.json").write_text("{not json", encoding="utf-8")
    assert "mutation" not in merge_evidence(dict(merged), tmp_path)  # a stale key is dropped, never kept


def test_remerge_updates_an_existing_summary_file(tmp_path: Path) -> None:
    assert remerge_summary_file(tmp_path) is False  # no summary yet
    (tmp_path / "summary.json").write_text(json.dumps(build_summary([], mode="deterministic")), encoding="utf-8")
    (tmp_path / "mutation.json").write_text(json.dumps(_mutation()), encoding="utf-8")
    assert remerge_summary_file(tmp_path) is True
    on_disk = json.loads((tmp_path / "summary.json").read_text(encoding="utf-8"))
    validate_summary(on_disk)
    assert on_disk["mutation"]["score"] == 1.0
    (tmp_path / "summary.json").write_text("garbage", encoding="utf-8")
    assert remerge_summary_file(tmp_path) is False


# ---------------------------------------------------------------- artifact fixture shorthand


@pytest.fixture
def fake_artifact_testing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stand-in `acl.artifacts.testing` so this test does not depend on the artifact scanner task."""
    fixture = tmp_path / "model.bin"
    fixture.write_bytes(b"hello fixture")

    mod = types.ModuleType("acl.artifacts.testing")
    mod.fixture_path = lambda name: tmp_path / f"{name}.bin"  # type: ignore[attr-defined]
    mod.fixture_filename = lambda name: f"{name}.safetensors"  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "acl.artifacts.testing", mod)
    import acl.artifacts as pkg

    monkeypatch.setattr(pkg, "testing", mod, raising=False)
    return fixture


def test_fixture_shorthand_fills_path_filename_hash_and_size(fake_artifact_testing: Path) -> None:
    data = {"kind": "artifact", "local_path": "fixture:model", "sha256": "auto", "size": "auto"}
    out = resolve_artifact_fixture(data)
    assert out["local_path"] == str(fake_artifact_testing)
    assert out["filename"] == "model.safetensors"
    assert out["sha256"] == hashlib.sha256(b"hello fixture").hexdigest()
    assert out["size"] == len(b"hello fixture")
    assert data["local_path"] == "fixture:model"  # input untouched


def test_fixture_shorthand_keeps_explicit_values_and_fills_missing(fake_artifact_testing: Path) -> None:
    out = resolve_artifact_fixture(
        {"kind": "artifact", "local_path": "fixture:model", "filename": "x.pkl", "sha256": "ab" * 32, "size": 7}
    )
    assert (out["filename"], out["sha256"], out["size"]) == ("x.pkl", "ab" * 32, 7)
    sparse = resolve_artifact_fixture({"kind": "artifact", "local_path": "fixture:model"})
    assert sparse["filename"] == "model.safetensors" and sparse["size"] == len(b"hello fixture")


def test_fixture_shorthand_builds_an_artifact_context(fake_artifact_testing: Path) -> None:
    c = {"id": "art-1", "input": {"kind": "artifact", "local_path": "fixture:model", "sha256": "auto"}}
    c["point"] = "artifact_load"
    ctx = build_context(c, "balanced")
    assert isinstance(ctx.payload, ArtifactPayload)
    assert ctx.payload.local_path == str(fake_artifact_testing) and ctx.payload.size == len(b"hello fixture")


def test_other_inputs_never_touch_the_testing_module(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "acl.artifacts.testing", None)  # importing it would raise ImportError
    assert resolve_artifact_fixture("plain text") == "plain text"
    chat = {"messages": [{"role": "user", "content": "fixture:model"}]}
    assert resolve_artifact_fixture(chat) is chat
    real_path = {"kind": "artifact", "filename": "a.bin", "sha256": "0" * 64, "size": 1, "local_path": "/tmp/a.bin"}
    assert resolve_artifact_fixture(real_path) is real_path
