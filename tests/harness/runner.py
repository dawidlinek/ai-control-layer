"""In-process case runner (deterministic mode). Phase 1E extends: redaction checks against the
transformed payload, live 2-of-3 mode, JUnit/JSON metrics summary."""

from __future__ import annotations

import asyncio
from functools import lru_cache
from pathlib import Path
from typing import Any

from acl.contracts.common import Action, InspectionPoint, Preset
from acl.engine.engine import Engine
from acl.policy.loader import load_policy_dir
from acl.testing import make_context, make_principal

ROOT = Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def engine() -> Engine:
    loaded = load_policy_dir(ROOT / "policy")
    return Engine.build(loaded.policy, loaded.version)


def run_case(case: dict[str, Any], preset: str) -> None:
    point = InspectionPoint(case.get("point", "ingress"))
    p = case.get("principal") or {}
    principal = make_principal(p.get("username", "anna"), p.get("groups"))
    ctx = make_context(case["input"], point=point, principal=principal, preset=Preset(preset))
    decision = asyncio.run(engine().evaluate(ctx))

    expect = case.get("expect", {})
    expected_action = Action(case["matrix"][preset]) if case.get("matrix") else Action(expect["action"])
    assert decision.action == expected_action, (
        f"expected {expected_action.value}, got {decision.action.value} "
        f"(rules={decision.rule_ids}, decided_by={decision.decided_by})"
    )
    if "rule_id" in expect:
        rid = expect["rule_id"]
        if rid is None:
            assert not decision.rule_ids, f"expected no rules, got {decision.rule_ids}"
        else:
            assert rid in decision.rule_ids, f"expected rule {rid} in {decision.rule_ids}"
