"""`model_access` control (SEC-MODEL-01): positive/negative, fail-closed, paired with the real resolver."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from acl.contracts.admin import GrantCreate
from acl.contracts.common import Action, GrantResourceType, InspectionPoint
from acl.controls.base import ControlDeps
from acl.db import create_all, make_engine, make_sessionmaker
from acl.engine.engine import Engine
from acl.identity.access import DefaultAccessResolver, grant_keys
from acl.identity.grants import GrantStore
from acl.identity.testing import FakeClock, load_repo_policy, patch_policy
from acl.policy.models import Policy
from acl.testing import make_context, make_principal

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
ADMIN = make_principal("adam", ["admins"], roles=["acl-admin"])


def with_params(policy: Policy, **params: Any) -> Policy:
    def patch(d: dict[str, Any]) -> None:
        for c in d["controls"]:
            if c["id"] == "SEC-MODEL-01":
                c["enabled"] = True
                c["params"] = params

    return patch_policy(policy, patch)


def build(policy: Policy, **services: Any) -> Engine:
    return Engine.build(policy, "t1", deps=ControlDeps(**services))


@pytest.fixture
def policy() -> Policy:
    return load_repo_policy(POLICY_DIR)


def ctx(model: str | None, groups: list[str], point: InspectionPoint = InspectionPoint.ingress):
    data = "hello" if point == InspectionPoint.ingress else {"messages": [{"role": "user", "content": "x"}]}
    return make_context(data, point=point, principal=make_principal("u", groups), model_requested=model)


def test_repo_policy_enables_the_control(policy: Policy) -> None:
    cfg = next(c for c in policy.controls if c.id == "SEC-MODEL-01")
    assert cfg.enabled and cfg.type == "model_access" and cfg.cost_tier.value == "deterministic"
    assert set(cfg.stages) == {InspectionPoint.ingress, InspectionPoint.embeddings}


async def test_allowed_model_passes(policy: Policy) -> None:
    engine = build(policy, access=DefaultAccessResolver(lambda: (policy, "t1")))
    d = await engine.evaluate(ctx("smart", ["developers"]))
    assert d.action == Action.allow and d.rule_ids == []
    v = next(v for v in d.verdicts if v.control_id == "SEC-MODEL-01")
    assert v.reason == "allowed by group developers"


async def test_forbidden_model_is_final_block_with_rule_id(policy: Policy) -> None:
    engine = build(policy, access=DefaultAccessResolver(lambda: (policy, "t1")))
    d = await engine.evaluate(ctx("smart", ["credit-analysts"]))
    assert d.action == Action.block and d.final and d.decided_by == "SEC-MODEL-01"
    assert d.rule_ids == ["SEC-MODEL-01"]
    assert "not granted" in d.reason


async def test_org_lock_rule_id_is_propagated(policy: Policy) -> None:
    def lock(d: dict[str, Any]) -> None:
        d["org_locks"].append(
            {"kind": "deny_resource", "id": "LOCK-05", "resource_type": "alias", "resources": ["smart"]}
        )

    p = patch_policy(policy, lock)
    engine = build(p, access=DefaultAccessResolver(lambda: (p, "t1")))
    d = await engine.evaluate(ctx("smart", ["developers"]))
    assert d.action == Action.block and "LOCK-05" in d.rule_ids and "SEC-MODEL-01" in d.rule_ids


async def test_embeddings_stage_is_checked(policy: Policy) -> None:
    engine = build(policy, access=DefaultAccessResolver(lambda: (policy, "t1")))
    assert (await engine.evaluate(ctx("local-pl", ["developers"], InspectionPoint.embeddings))).action == Action.block
    assert (
        await engine.evaluate(ctx("local-pl", ["credit-analysts"], InspectionPoint.embeddings))
    ).action == Action.allow


async def test_other_stages_are_not_checked(policy: Policy) -> None:
    engine = build(policy, access=DefaultAccessResolver(lambda: (policy, "t1")))
    c = make_context("x", point=InspectionPoint.egress, principal=make_principal("u", []), model_requested="smart")
    assert (await engine.evaluate(c)).action == Action.allow


async def test_no_model_requested_is_not_a_model_request(policy: Policy) -> None:
    engine = build(policy, access=DefaultAccessResolver(lambda: (policy, "t1")))
    assert (await engine.evaluate(ctx(None, []))).action == Action.allow


async def test_missing_service_fails_closed_with_a_clear_reason(policy: Policy) -> None:
    engine = build(with_params(policy, missing_service="block"))
    d = await engine.evaluate(ctx("auto", ["developers"]))
    assert d.action == Action.block and d.final and d.rule_ids == ["SEC-MODEL-01"]
    assert "access service is not available" in d.reason


async def test_missing_service_policy_only_fallback(policy: Policy) -> None:
    engine = build(with_params(policy, missing_service="policy_only"))
    assert (await engine.evaluate(ctx("auto", ["developers"]))).action == Action.allow
    assert (await engine.evaluate(ctx("auto", []))).action == Action.block
    assert (await engine.evaluate(ctx("smart", ["credit-analysts"]))).action == Action.block


async def test_resolver_error_fails_closed(policy: Policy) -> None:
    class Broken:
        async def check_model(self, principal, name):
            raise RuntimeError("db down")

    engine = build(policy, access=Broken())
    d = await engine.evaluate(ctx("auto", ["developers"]))
    assert d.action == Action.block and d.final  # deterministic controls fail closed


async def test_control_sees_db_grants_and_revocation(policy: Policy, tmp_path: Path) -> None:
    db = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'c.db'}")
    await create_all(db)
    sm = make_sessionmaker(db)
    clock = FakeClock()
    grants = GrantStore(lambda: sm, clock=clock.monotonic, now=clock.now)
    resolver = DefaultAccessResolver(lambda: (policy, "t1"), grants, now=clock.now)
    engine = build(policy, access=resolver)
    c = ctx("smart", ["credit-analysts"])

    async def warm() -> None:  # what the authenticator does before the pipeline runs (10 ms control timeout)
        await grants.active_for(*grant_keys(c.principal))

    await warm()
    assert (await engine.evaluate(c)).action == Action.block
    g = await grants.create(
        GrantCreate(
            subject_type="user",
            subject="u",
            resource_type=GrantResourceType.alias,
            resource="smart",
            reason="pilot",
        ),
        ADMIN,
    )
    await warm()
    assert (await engine.evaluate(c)).action == Action.allow
    await grants.revoke(g.id, ADMIN, "pilot over")
    await warm()
    assert (await engine.evaluate(c)).action == Action.block
    await db.dispose()


def test_resolver_protocol_is_registered_as_control_service() -> None:
    from acl.main import create_app
    from acl.settings import Settings

    app = create_app(Settings(policy_dir=POLICY_DIR, database_url="sqlite+aiosqlite:///:memory:"))
    assert app.state.control_deps.get("access") is app.state.access
    assert callable(app.state.authenticator)
