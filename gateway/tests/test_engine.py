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
    engine = Engine.build(loaded.policy, loaded.version)
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
