"""A tiny fake control + test-only registry for exercising the case runner without real controls."""

from __future__ import annotations

import asyncio
from typing import Any

from harness.host import ROOT
from pydantic import BaseModel, ConfigDict

from acl.contracts.common import Action, CostTier, InspectionPoint
from acl.contracts.decision import Decision, Finding
from acl.contracts.inspection import InspectionContext
from acl.controls.base import Control, ControlRegistry
from acl.engine.engine import Engine
from acl.engine.text import iter_texts
from acl.policy.loader import load_policy_dir
from acl.policy.models import ControlConfig

FAKE_ID = "TST-FAKE-01"


class _Params(BaseModel):
    model_config = ConfigDict(extra="allow")


class FakeControl(Control):
    """Configurable by `params`:

    needle        text to look for (default: "SEKRET"); no match -> allow
    by_preset     {preset: action}; default action for presets not listed: `action` (default pseudonymise)
    replacement   placeholder for redact/pseudonymise findings (None -> flag only, no span replacement)
    needs_taint   only act when the session carries this taint flag (session presets)
    allow_groups  principals in one of these groups are allowed (principal handling)
    script        list of actions returned on successive calls (live 2-of-3 tests)
    """

    type = "fake"
    Params = _Params

    def __init__(self, *a: Any, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.calls = 0

    async def inspect(self, ctx: InspectionContext):  # type: ignore[override]
        p = self.config.params
        self.calls += 1
        if p.get("script"):
            action = Action(p["script"][min(self.calls, len(p["script"])) - 1])
            return self.verdict(
                action=action, final=action == Action.block, rule_ids=[self.id] if action != "allow" else []
            )
        if set(p.get("allow_groups", [])) & set(ctx.principal.groups):
            return self.verdict()
        if p.get("needs_taint") and p["needs_taint"] not in [t.value for t in ctx.session.labels.taint]:
            return self.verdict()
        needle = p.get("needle", "SEKRET")
        findings: list[Finding] = []
        for field, text in iter_texts(ctx.payload):
            at = text.find(needle)
            while at >= 0:
                findings.append(
                    Finding(
                        entity_type="FAKE",
                        field=field,
                        start=at,
                        end=at + len(needle),
                        replacement=p.get("replacement"),
                        rule_id=self.id,
                    )
                )
                at = text.find(needle, at + len(needle))
        if not findings:
            return self.verdict()
        action = Action((p.get("by_preset") or {}).get(ctx.preset.value, p.get("action", "pseudonymise")))
        return self.verdict(
            action=action,
            final=action == Action.block,
            rule_ids=[self.id],
            findings=findings if action in (Action.redact, Action.pseudonymise) else [],
        )


def fake_engine(
    stages: list[InspectionPoint] | None = None, *, control_id: str = FAKE_ID, **params: Any
) -> tuple[Engine, FakeControl]:
    """Real policy (presets, groups, ...) with one fake control, built through a private registry."""
    registry = ControlRegistry()
    registry.register(FakeControl)
    loaded = load_policy_dir(ROOT / "policy")
    cfg = ControlConfig(
        id=control_id,
        type="fake",
        stages=stages or [InspectionPoint.ingress, InspectionPoint.tool_call],
        cost_tier=CostTier.deterministic,
        timeout_ms=500,
        params=params,
    )
    policy = loaded.policy.model_copy(update={"controls": [cfg]})
    engine = Engine.build(policy, "v-selftest", control_registry=registry, load_builtins=False)
    control = engine.pipeline.controls[0]
    assert isinstance(control, FakeControl)
    return engine, control


def sync_evaluator(engine: Engine):  # type: ignore[no-untyped-def]
    def evaluate(ctx: InspectionContext) -> Decision:
        return asyncio.run(engine.evaluate(ctx))

    return evaluate
