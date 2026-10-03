"""Pipeline skeleton + decide invariants (security-critical)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from pydantic import BaseModel, ConfigDict

from acl.contracts.common import Action, CostTier, FailMode, InspectionPoint, Phase, PolicyMode, VerdictStatus
from acl.contracts.decision import Verdict
from acl.controls.base import Control, ControlDeps, ControlRegistry
from acl.engine.decide import compose_decision
from acl.engine.engine import Engine
from acl.engine.pipeline import Pipeline
from acl.policy.loader import load_policy_dir
from acl.policy.models import ControlConfig, GlobalSettings
from acl.testing import make_context

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


async def test_zero_controls_allows() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    policy = loaded.policy.model_copy(update={"controls": []})
    engine = Engine.build(policy, loaded.version)
    d = await engine.evaluate(make_context("hello"))
    assert d.action == Action.allow
    assert d.verdicts == []
    assert d.versions.policy


# ---------------------------------------------------------------- fake controls


class _AnyParams(BaseModel):
    model_config = ConfigDict(extra="allow")


class _Fixed(Control):
    type = "fixed"
    Params = _AnyParams

    async def inspect(self, ctx):  # type: ignore[override]
        p = self.config.params
        if p.get("sleep"):
            await asyncio.sleep(p["sleep"])
        if p.get("raise"):
            raise RuntimeError("boom")
        return self.verdict(
            action=Action(p.get("action", "allow")),
            final=p.get("final", False),
            rule_ids=[self.id] if p.get("action", "allow") != "allow" else [],
            outputs=p.get("outputs", {}),
        )


class _Seen(Control):
    type = "seen"
    phase = Phase.semantic_l1
    Params = _AnyParams

    async def inspect(self, ctx):  # type: ignore[override]
        return self.verdict(reason=f"saw:{ctx.attributes.get('norm', '-')}")


def _registry() -> ControlRegistry:
    r = ControlRegistry()
    r.register(_Fixed)
    r.register(_Seen)
    return r


def _cfg(cid: str, tier: CostTier = CostTier.deterministic, ctype: str = "fixed", **params) -> ControlConfig:
    return ControlConfig(
        id=cid,
        type=ctype,
        stages=[InspectionPoint.ingress],
        cost_tier=tier,
        timeout_ms=params.pop("timeout_ms", 200),
        fail_mode=params.pop("fail_mode", None),
        mode=params.pop("mode", None),
        params=params,
    )


def _pipeline(*cfgs: ControlConfig, settings: GlobalSettings | None = None) -> Pipeline:
    r = _registry()
    deps = ControlDeps()
    return Pipeline([r.build(c, deps) for c in cfgs], settings or GlobalSettings())


async def test_most_severe_action_wins() -> None:
    d = await _pipeline(_cfg("T-A-01", action="redact"), _cfg("T-B-01", action="require_approval")).run(
        make_context("x")
    )
    assert d.action == Action.require_approval
    assert Action.redact in d.applied
    assert d.decided_by == "T-B-01"


async def test_final_block_exits_early_and_wins() -> None:
    d = await _pipeline(
        _cfg("T-DET-01", action="block", final=True),
        _cfg("T-L1-01", CostTier.l1, ctype="seen"),
    ).run(make_context("x"))
    assert d.action == Action.block and d.final
    assert [v.control_id for v in d.verdicts] == ["T-DET-01"]  # semantic phase never ran


async def test_outputs_flow_to_later_phases() -> None:
    d = await _pipeline(_cfg("T-N-01", outputs={"norm": "abc"}), _cfg("T-S-01", CostTier.l1, ctype="seen")).run(
        make_context("x")
    )
    assert next(v for v in d.verdicts if v.control_id == "T-S-01").reason == "saw:abc"


@pytest.mark.parametrize(
    ("tier", "fail_mode", "expected"),
    [
        (CostTier.deterministic, None, Action.block),  # global default: deterministic fails closed
        (CostTier.l1, None, Action.allow),  # global default: semantic fails open with alert
        (CostTier.l1, FailMode.closed, Action.block),
    ],
)
async def test_timeout_follows_fail_mode(tier: CostTier, fail_mode: FailMode | None, expected: Action) -> None:
    d = await _pipeline(_cfg("T-SLOW-01", tier, sleep=1.0, timeout_ms=20, fail_mode=fail_mode)).run(make_context("x"))
    assert d.action == expected
    assert d.verdicts[0].status == VerdictStatus.timeout


async def test_exception_follows_fail_mode() -> None:
    d = await _pipeline(_cfg("T-ERR-01", **{"raise": True})).run(make_context("x"))
    assert d.action == Action.block and d.verdicts[0].status == VerdictStatus.error


async def test_shadow_control_never_enforces() -> None:
    d = await _pipeline(_cfg("T-SH-01", action="block", final=True, mode=PolicyMode.monitor)).run(make_context("x"))
    assert d.action == Action.allow


async def test_monitor_mode_records_would_action() -> None:
    d = await _pipeline(_cfg("T-B-01", action="block"), settings=GlobalSettings(mode=PolicyMode.monitor)).run(
        make_context("x")
    )
    assert d.action == Action.monitor and d.would_action == Action.block and not d.final


def test_semantic_cannot_relax_deterministic_block() -> None:
    ctx = make_context("x")
    det = Verdict(
        control_id="D-1",
        control_type="t",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.block,
        final=True,
        rule_ids=["D-1"],
    )
    ai = Verdict(
        control_id="A-1",
        control_type="t",
        phase=Phase.semantic_l2,
        cost_tier=CostTier.l2,
        action=Action.allow,
        score=0.0,
    )
    d = compose_decision(ctx, [det, ai], GlobalSettings())
    assert d.action == Action.block and d.final and d.rule_ids == ["D-1"]


def test_no_verdicts_allow() -> None:
    d = compose_decision(make_context("x"), [], GlobalSettings())
    assert d.action == Action.allow and d.rule_ids == []


async def test_never_block_preset_records_would_action() -> None:
    from acl.contracts.common import Preset
    from acl.policy.models import PresetSettings

    r = _registry()
    p = Pipeline(
        [r.build(_cfg("T-B-01", action="block", final=True), ControlDeps())],
        GlobalSettings(),
        presets={Preset.monitor: PresetSettings(injection_threshold=0.8, never_block=True)},
    )
    d = await p.run(make_context("x", preset=Preset.monitor))
    assert d.action == Action.monitor and d.would_action == Action.block


async def test_engine_controls_see_their_policy() -> None:
    loaded = load_policy_dir(POLICY_DIR)
    engine = Engine.build(loaded.policy, loaded.version)
    assert engine.deps.get("policy") is loaded.policy


# ---------------------------------------------------------------- locked controls (LOCK-02: secrets never leave)


def _locked_cfg(cid: str, **params) -> ControlConfig:
    cfg = _cfg(cid, **params)
    return cfg.model_copy(update={"locked": True})


async def test_locked_control_enforced_under_never_block_preset() -> None:
    from acl.contracts.common import Preset
    from acl.policy.models import PresetSettings

    r = _registry()
    deps = ControlDeps()
    p = Pipeline(
        [r.build(_locked_cfg("T-LOCK-01", action="block"), deps), r.build(_cfg("T-OTHER-01", action="redact"), deps)],
        GlobalSettings(),
        presets={Preset.monitor: PresetSettings(injection_threshold=0.8, never_block=True)},
    )
    d = await p.run(make_context("x", preset=Preset.monitor))
    assert d.action == Action.block and d.final
    assert d.applied == [Action.block]  # the unlocked redact stays shadowed


async def test_locked_control_preset_monitor_hit_becomes_block() -> None:
    r = _registry()
    d = await Pipeline([r.build(_locked_cfg("T-LOCK-01", action="monitor"), ControlDeps())], GlobalSettings()).run(
        make_context("x")
    )
    assert d.action == Action.block and d.final


async def test_locked_control_not_shadowed_and_monitor_mode_still_enforces_it() -> None:
    r = _registry()
    cfg = _locked_cfg("T-LOCK-01", action="block", mode=PolicyMode.monitor)
    d = await Pipeline([r.build(cfg, ControlDeps())], GlobalSettings(mode=PolicyMode.monitor)).run(make_context("x"))
    assert d.action == Action.block


async def test_real_secrets_control_blocks_under_monitor_preset() -> None:
    from acl.contracts.common import Preset

    loaded = load_policy_dir(POLICY_DIR)
    engine = Engine.build(loaded.policy, loaded.version)
    d = await engine.evaluate(make_context("key AKIAIOSFODNN7EXAMPLQ please", preset=Preset.monitor))
    assert d.action == Action.block and "SEC-SECRET-01" in d.rule_ids


# ---------------------------------------------------------------- IFC labels (monotonic)


def test_labels_rise_from_data_class_and_updates_but_not_on_block() -> None:
    from acl.contracts.common import DataClass, Integrity, TaintFlag
    from acl.contracts.decision import LabelUpdate

    ctx = make_context("x")
    pii = Verdict(
        control_id="P-1",
        control_type="t",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.pseudonymise,
        rule_ids=["P-1"],
        data_class=DataClass.confidential,
    )
    tr = Verdict(
        control_id="T-1",
        control_type="t",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        labels=LabelUpdate(integrity_untrusted=True),
    )
    d = compose_decision(ctx, [pii, tr], GlobalSettings())
    assert d.labels_after.confidentiality == DataClass.confidential
    assert d.labels_after.integrity == Integrity.untrusted
    assert set(d.labels_after.taint) == {TaintFlag.sensitive, TaintFlag.untrusted}
    assert ctx.session.labels.taint == []  # input untouched
    blk = Verdict(
        control_id="B-1",
        control_type="t",
        phase=Phase.deterministic,
        cost_tier=CostTier.deterministic,
        action=Action.block,
        final=True,
        rule_ids=["B-1"],
    )
    d2 = compose_decision(ctx, [pii, blk], GlobalSettings())
    assert d2.labels_after.taint == []


async def test_session_store_merge_is_monotonic() -> None:
    from acl.contracts.common import DataClass, Integrity, TaintFlag
    from acl.contracts.inspection import SessionLabels
    from acl.sessions import InMemorySessionStore, merge_labels

    a = SessionLabels(integrity=Integrity.untrusted, confidentiality=DataClass.restricted, taint=[TaintFlag.untrusted])
    b = SessionLabels(confidentiality=DataClass.internal, taint=[TaintFlag.sensitive])
    m = merge_labels(a, b)
    assert m.integrity == Integrity.untrusted and m.confidentiality == DataClass.restricted
    assert set(m.taint) == {TaintFlag.untrusted, TaintFlag.sensitive}
    store = InMemorySessionStore()
    await store.update("s", lambda s: s.model_copy(update={"labels": a}))
    await store.update("s", lambda s: s.model_copy(update={"labels": merge_labels(s.labels, b)}))
    assert (await store.load("s")).labels.confidentiality == DataClass.restricted
