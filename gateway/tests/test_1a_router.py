"""1A: minimal router (aliases, auto, org locks, degraded fallback)."""

from __future__ import annotations

from pathlib import Path

import pytest

from acl.contracts.common import Action, ConnectorTier, DataClass
from acl.policy.loader import load_policy_dir
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import RouteError, Router, RouteRequest, max_data_class

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


@pytest.fixture
def setup():  # type: ignore[no-untyped-def]
    loaded = load_policy_dir(POLICY_DIR)
    registry = ConnectorRegistry(deterministic=True)
    table = registry.table_for(loaded.policy, loaded.version)
    access = PermissiveAccess(lambda: loaded.policy)

    async def usable():  # type: ignore[no-untyped-def]
        return await access.usable_models(None)  # type: ignore[arg-type]

    return loaded.policy, registry, Router(loaded.policy, table), usable


async def route(setup, requested: str, data_class=DataClass.public, **kw):  # type: ignore[no-untyped-def]
    _, _, router, usable = setup
    return router.route(RouteRequest(requested=requested, data_class=data_class, usable=await usable(), **kw))


async def test_model_id_and_alias_resolution(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "local/qwen3.8-27b")
    assert r.info.model == "local/qwen3.8-27b" and r.info.connector == "local" and r.info.tier == ConnectorTier.local
    assert not r.info.degraded and r.info.model_requested == "local/qwen3.8-27b"
    r = await route(setup, "smart")  # alias declared on a model
    assert (
        r.info.model == "gemini/flash"
        and r.info.tier == ConnectorTier.cloud
        and "smart → gemini/flash" in r.info.reason
    )
    assert (await route(setup, "fast")).info.model == "local/qwen3.8-27b"


async def test_fixed_alias_and_skill(setup) -> None:  # type: ignore[no-untyped-def]
    policy, registry, _, usable = setup
    policy = policy.model_copy(deep=True)
    from acl.policy.models import AliasConfig

    policy.aliases["coding"] = AliasConfig(strategy="fixed", target="local/loan-memo")
    router = Router(policy, registry.table_for(policy, "v-fixed"))
    r = router.route(RouteRequest(requested="coding", usable=await usable()))
    assert r.info.model == "local/loan-memo"
    r = router.route(RouteRequest(requested="skill/loan-memo-summary", usable=await usable()))
    assert r.info.model == "local/loan-memo" and r.model.system_prompt


async def test_unknown_name_is_404(setup) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RouteError) as exc:
        await route(setup, "gpt-9000")
    assert exc.value.status == 404 and exc.value.code == "model_not_found"


async def test_auto_follows_data_class_sensitivity(setup) -> None:  # type: ignore[no-untyped-def]
    low = await route(setup, "auto", DataClass.internal)
    assert low.info.model == "gemini/flash" and low.info.factors["sensitivity"] == "low"
    high = await route(setup, "auto", DataClass.confidential)
    assert high.info.model == "local/qwen3.8-27b" and high.info.factors["sensitivity_rule"] == "local_only"
    assert "confidential" in high.info.reason and "local_only" in high.info.reason


async def test_auto_falls_back_to_local_when_ext_not_usable(setup) -> None:  # type: ignore[no-untyped-def]
    _, _, router, usable = setup
    only_local = {k: v for k, v in (await usable()).items() if not k.startswith("gemini")}
    r = router.route(RouteRequest(requested="auto", data_class=DataClass.public, usable=only_local))
    assert r.info.model == "local/qwen3.8-27b" and "not usable" in r.info.reason


async def test_org_lock_reroutes_to_local_and_cites_lock(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "smart", DataClass.restricted)
    assert r.info.model == "local/qwen3.8-27b" and "LOCK-01" in r.info.reason and r.info.factors["lock"] == "LOCK-01"
    assert not r.info.degraded


async def test_strict_presets_refuse_instead_of_rerouting(setup) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RouteError) as exc:
        await route(setup, "smart", DataClass.confidential, sensitive_external_action=Action.block)
    assert exc.value.status == 403 and exc.value.rule_id == "LOCK-01"


async def test_route_local_obligation_forces_local(setup) -> None:  # type: ignore[no-untyped-def]
    r = await route(setup, "smart", DataClass.public, force_local=True, force_reason="route_local")
    assert r.info.model == "local/qwen3.8-27b" and r.info.factors["forced_local"] is True


async def test_unavailable_connector_degrades(setup) -> None:  # type: ignore[no-untyped-def]
    _, registry, _, _ = setup
    registry.set_kill_switch("gemini", True, "incident")
    r = await route(setup, "smart")
    assert r.info.degraded and r.info.model == "local/qwen3.8-27b" and "kill switch" in r.info.reason
    assert r.info.factors["degraded_from"] == "gemini/flash"
    registry.set_kill_switch("gemini", False, "over")


async def test_no_degraded_fallback_is_503(setup) -> None:  # type: ignore[no-untyped-def]
    _, registry, _, _ = setup
    registry.set_kill_switch("local", True, "down")
    with pytest.raises(RouteError) as exc:
        await route(setup, "local/qwen3.8-27b")
    assert exc.value.status == 503
    registry.set_kill_switch("local", False, "up")


async def test_capability_mismatch(setup) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(RouteError) as exc:
        await route(setup, "local/embed")  # an embedder cannot chat
    assert exc.value.status == 400
    r = await route(setup, "local/embed", capability="embeddings")
    assert r.info.model == "local/embed"


def test_max_data_class() -> None:
    assert max_data_class([]) == DataClass.public
    assert (
        max_data_class([None, DataClass.internal, DataClass.restricted, DataClass.confidential]) == DataClass.restricted
    )
