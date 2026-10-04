"""Access resolution: org locks → group policy → DB grants (expiry, deny, caps, revocation, presets, tools)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

from acl.audit.sink import RecordingSink
from acl.contracts.admin import GrantConstraints, GrantCreate
from acl.contracts.audit import EventType
from acl.contracts.common import DataClass, GrantResourceType, Preset
from acl.contracts.inspection import Principal
from acl.db import create_all, make_engine, make_sessionmaker
from acl.identity.access import AccessUnavailable, DefaultAccessResolver, expand_groups
from acl.identity.db_models import GrantChangeRow, GrantRow
from acl.identity.grants import GrantAlreadyRevoked, GrantNotFound, GrantStore
from acl.identity.testing import FakeClock, load_repo_policy, patch_policy
from acl.policy.models import Policy
from acl.testing import make_principal

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
ADMIN = make_principal("adam", ["admins"], roles=["acl-admin"])


def wide_cloud(d: dict[str, Any]) -> None:
    """Make the cloud model nominally able to take every data class, so only LOCK-01 can cap it."""
    for m in d["models"]:
        if m["id"] == "gemini/flash":
            m["data_classes"] = ["public", "internal", "confidential", "restricted"]


class Env(SimpleNamespace):
    policy: Policy
    clock: FakeClock
    grants: GrantStore
    resolver: DefaultAccessResolver
    audit: RecordingSink
    engine: SimpleNamespace  # stands in for app.state.engine


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    db = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'access.db'}")
    await create_all(db)
    sm = make_sessionmaker(db)
    clock = FakeClock()
    audit = RecordingSink()
    grants = GrantStore(lambda: sm, audit=lambda: audit, clock=clock.monotonic, now=clock.now)
    await grants.ensure_meta()
    policy = patch_policy(load_repo_policy(POLICY_DIR), wide_cloud)
    engine = SimpleNamespace(policy=policy, policy_version="v1")
    resolver = DefaultAccessResolver(lambda: (engine.policy, engine.policy_version), grants, now=clock.now)
    yield Env(policy=policy, clock=clock, grants=grants, resolver=resolver, audit=audit, engine=engine, sm=sm)
    await db.dispose()


def anna() -> Principal:
    return make_principal("anna", ["developers"])


def jan() -> Principal:
    return make_principal("jan", ["credit-analysts"])


def olga() -> Principal:
    return make_principal("olga", ["operations"])


async def grant(env: Env, **kw: Any):
    body = GrantCreate(
        **{
            "subject_type": "user",
            "subject": "jan",
            "resource_type": GrantResourceType.alias,
            "resource": "smart",
            "reason": "pilot",
            **kw,
        }
    )
    return await env.grants.create(body, ADMIN)


# ---------------------------------------------------------------- group policy


async def test_group_policy_allows_and_default_denies(env: Env) -> None:
    r = env.resolver
    ok = await r.check_model(olga(), "smart")  # operations hold the cloud alias
    assert ok.allowed and ok.source == "group:operations" and ok.rule_id is None
    assert (await r.check_model(anna(), "auto")).allowed
    assert (await r.check_model(anna(), "local")).allowed
    no = await r.check_model(jan(), "smart")  # credit-analysts have no `smart`
    assert not no.allowed and no.rule_id == "SEC-MODEL-01" and no.source == "default"
    assert "secret" not in no.reason.lower()
    dev = await r.check_model(anna(), "smart")  # developers have no cloud model unless granted
    assert not dev.allowed and dev.rule_id == "SEC-MODEL-01" and dev.source == "default"


async def test_concrete_id_not_granted_by_alias_but_alias_follows_id(env: Env) -> None:
    r = env.resolver
    # developers hold alias `local`, not the concrete id: picking the id directly is refused
    assert (await r.check_model(anna(), "local")).allowed
    assert not (await r.check_model(anna(), "local/qwen3.8-27b")).allowed
    # a concrete-model grant also covers that model's aliases
    assert not (await r.check_model(anna(), "smart")).allowed
    await grant(env, subject="anna", resource_type=GrantResourceType.model, resource="gemini/flash")
    assert (await r.check_model(anna(), "gemini/flash")).allowed
    assert (await r.check_model(anna(), "smart")).allowed
    assert not (await r.check_model(anna(), "smart-pro")).allowed  # a different model: not covered


async def test_unknown_names_and_skills(env: Env) -> None:
    r = env.resolver
    assert not (await r.check_model(anna(), "gpt-4o")).allowed
    assert not (await r.check_model(anna(), "")).allowed
    assert (await r.check_model(jan(), "skill/loan-memo-summary")).allowed
    assert not (await r.check_model(anna(), "skill/loan-memo-summary")).allowed


async def test_no_groups_no_access(env: Env) -> None:
    nobody = make_principal("mallory", [])
    assert not (await env.resolver.check_model(nobody, "auto")).allowed
    assert await env.resolver.usable_models(nobody) == {}
    assert await env.resolver.visible_names(nobody) == []


async def test_child_group_inherits_parent_policy(env: Env) -> None:
    assert expand_groups(["agents/research-bot", "/developers"]) == ["agents/research-bot", "agents", "developers"]

    def add_parent(d: dict[str, Any]) -> None:
        d["groups"]["agents"] = {"models": ["smart"]}

    env.engine.policy = patch_policy(env.policy, add_parent)
    bot = make_principal("bot", ["agents/research-bot"])
    assert (await env.resolver.check_model(bot, "smart")).allowed  # inherited from `agents`
    assert (await env.resolver.check_model(bot, "local")).allowed  # its own group


async def test_disabled_model_denied(env: Env) -> None:
    def disable(d: dict[str, Any]) -> None:
        for m in d["models"]:
            if m["id"] == "gemini/flash":
                m["enabled"] = False

    env.engine.policy = patch_policy(env.policy, disable)
    c = await env.resolver.check_model(olga(), "smart")
    assert not c.allowed and "disabled" in c.reason
    assert "gemini/flash" not in await env.resolver.usable_models(olga())


async def test_policy_is_read_at_call_time(env: Env) -> None:
    assert (await env.resolver.check_model(olga(), "smart")).allowed

    def drop_smart(d: dict[str, Any]) -> None:
        d["groups"]["operations"]["models"].remove("smart")

    env.engine.policy = patch_policy(env.policy, drop_smart)  # hot swap
    assert not (await env.resolver.check_model(olga(), "smart")).allowed


async def test_no_policy_loaded_fails_closed() -> None:
    r = DefaultAccessResolver(lambda: None)
    with pytest.raises(AccessUnavailable):
        await r.check_model(anna(), "auto")


# ---------------------------------------------------------------- org locks


async def test_deny_resource_lock_beats_group_grant_and_user_grant(env: Env) -> None:
    def lock_smart(d: dict[str, Any]) -> None:
        d["org_locks"].append(
            {
                "kind": "deny_resource",
                "id": "LOCK-09",
                "description": "no cloud for contractors",
                "resource_type": "connector",
                "resources": ["gemini"],
                "except_groups": ["admins"],
            }
        )

    env.engine.policy = patch_policy(env.policy, lock_smart)
    c = await env.resolver.check_model(olga(), "smart")
    assert not c.allowed and c.rule_id == "LOCK-09" and c.source == "org_lock:LOCK-09"
    await grant(env, subject="olga", resource="smart")  # a user grant cannot lift a lock
    assert (await env.resolver.check_model(olga(), "smart")).rule_id == "LOCK-09"
    # the concrete id is locked through its connector too
    assert (await env.resolver.check_model(olga(), "gemini/flash")).rule_id == "LOCK-09"
    # exempt group
    adam = make_principal("adam", ["admins"])
    assert (await env.resolver.check_model(adam, "smart")).allowed
    assert "smart" not in await env.resolver.visible_names(olga())


async def test_tier_lock_caps_group_cloud_access_to_ceiling(env: Env) -> None:
    usable = await env.resolver.usable_models(olga())
    assert usable["gemini/flash"] == [DataClass.public, DataClass.internal]  # max_external_data_class + LOCK-01
    assert usable["local/qwen3.8-27b"] == [
        DataClass.public,
        DataClass.internal,
        DataClass.confidential,
        DataClass.restricted,
    ]


async def test_user_grant_cannot_exceed_lock_01(env: Env) -> None:
    kim = make_principal("kim", [])  # no group access at all: everything below comes from the grant
    g = await grant(
        env,
        subject="kim",
        resource="smart",
        constraints=GrantConstraints(data_classes=[DataClass.internal, DataClass.confidential, DataClass.restricted]),
    )
    assert (await env.resolver.check_model(kim, "smart")).allowed
    usable = await env.resolver.usable_models(kim)
    assert usable == {"gemini/flash": [DataClass.internal]}  # confidential/restricted removed by LOCK-01
    eff = await env.resolver.effective_access(kim)
    item = next(i for i in eff.items if i.source_ref == g.id)
    assert item.capped_by_lock == "LOCK-01" and item.source == "user"
    assert item.constraints.data_classes == [DataClass.internal]
    assert item.resource == "smart" and item.effect == "allow"


async def test_grant_with_only_locked_classes_is_denied_by_the_lock(env: Env) -> None:
    kim = make_principal("kim", [])
    await grant(env, subject="kim", resource="smart", constraints=GrantConstraints(data_classes=[DataClass.restricted]))
    c = await env.resolver.check_model(kim, "smart")
    assert not c.allowed and c.rule_id == "LOCK-01" and c.source == "org_lock:LOCK-01"
    assert await env.resolver.usable_models(kim) == {}


async def test_local_model_grant_is_not_capped(env: Env) -> None:
    kim = make_principal("kim", [])
    await grant(env, subject="kim", resource_type=GrantResourceType.model, resource="local/qwen3.8-27b")
    assert (await env.resolver.usable_models(kim))["local/qwen3.8-27b"] == list(DataClass)


# ---------------------------------------------------------------- DB grants


async def test_user_grant_extends_access_and_expired_grant_is_ignored(env: Env) -> None:
    assert not (await env.resolver.check_model(jan(), "smart")).allowed
    g = await grant(env, resource="smart", expires_at=env.clock.t + timedelta(days=7))
    c = await env.resolver.check_model(jan(), "smart")
    assert c.allowed and c.source == f"grant:{g.id}"
    env.clock.advance(7 * 86400 + 1)
    assert not (await env.resolver.check_model(jan(), "smart")).allowed  # expiry needs no cache flush
    eff = await env.resolver.effective_access(jan())
    assert all(i.source_ref != g.id for i in eff.items)


async def test_expiry_is_journalled_once(env: Env) -> None:
    g = await grant(env, resource="smart", expires_at=env.clock.t + timedelta(hours=1))
    env.clock.advance(7200)
    assert [x.id for x in await env.grants.sweep_expired()] == [g.id]
    assert await env.grants.sweep_expired() == []
    changes = await env.grants.changes()
    assert [c.change for c in changes if c.grant_id == g.id] == ["expire", "create"]
    assert [e[1]["detail"]["change"] for e in env.audit.events if e[0] == EventType.grant_change] == [
        "create",
        "expire",
    ]


async def test_deny_grant_removes_group_access(env: Env) -> None:
    assert (await env.resolver.check_model(olga(), "smart")).allowed
    g = await grant(env, subject="olga", resource="smart", effect="deny", reason="incident 42")
    c = await env.resolver.check_model(olga(), "smart")
    assert not c.allowed and c.source == f"grant:{g.id}" and c.rule_id == "SEC-MODEL-01"
    assert "smart" not in await env.resolver.visible_names(olga())
    assert "gemini/flash" not in await env.resolver.usable_models(olga())  # also gone from routing candidates
    assert (await env.resolver.check_model(olga(), "local")).allowed  # unrelated access untouched
    eff = await env.resolver.effective_access(olga())
    assert any(i.effect == "deny" and i.source_ref == g.id for i in eff.items)


async def test_deny_beats_allow_across_user_and_group_grants(env: Env) -> None:
    await grant(env, subject="jan", resource="smart")
    await grant(env, subject_type="group", subject="credit-analysts", resource="smart", effect="deny")
    assert not (await env.resolver.check_model(jan(), "smart")).allowed


async def test_group_grant_from_db(env: Env) -> None:
    await grant(env, subject_type="group", subject="credit-analysts", resource="smart")
    assert (await env.resolver.check_model(jan(), "smart")).allowed
    assert not (await env.resolver.check_model(anna(), "smart")).allowed  # another group is not affected


async def test_revocation_is_effective_on_the_next_call_despite_cache(env: Env) -> None:
    g = await grant(env, resource="smart")
    assert (await env.resolver.check_model(jan(), "smart")).allowed  # warms the cache
    assert (await env.resolver.check_model(jan(), "smart")).allowed
    revoked = await env.grants.revoke(g.id, ADMIN, "pilot over")
    assert revoked.revoked_by == "adam" and not revoked.active
    assert not (await env.resolver.check_model(jan(), "smart")).allowed  # no TTL wait
    with pytest.raises(GrantAlreadyRevoked):
        await env.grants.revoke(g.id, ADMIN, "again")
    with pytest.raises(GrantNotFound):
        await env.grants.revoke("grt_nope", ADMIN, "x")


async def test_cross_replica_revocation_is_bounded_by_the_cache_ttl(env: Env) -> None:
    """A revocation made by *another* process is seen within ttl (+ one background refresh), never later than 5 s."""
    g = await grant(env, resource="smart")
    assert (await env.resolver.check_model(jan(), "smart")).allowed  # populates the cache
    async with env.sm() as s, s.begin():  # type: ignore[operator]
        (await s.get(GrantRow, g.id)).revoked_at = env.clock.t  # written behind this process's back
    assert (await env.resolver.check_model(jan(), "smart")).allowed  # still inside the TTL
    env.clock.advance(3)  # past ttl (2 s): the stale view is served once while a refresh runs
    assert (await env.resolver.check_model(jan(), "smart")).allowed
    await asyncio.gather(*env.grants._tasks)
    assert not (await env.resolver.check_model(jan(), "smart")).allowed
    # and a view older than 5 s is never served at all
    g2 = await grant(env, resource="auto")
    assert (await env.resolver.check_model(jan(), "auto")).allowed
    async with env.sm() as s, s.begin():  # type: ignore[operator]
        (await s.get(GrantRow, g2.id)).revoked_at = env.clock.t
    env.clock.advance(6)
    assert (await env.resolver.check_model(jan(), "auto")).allowed  # jan's group already allows `auto`
    assert [x.id for x in await env.grants.active_for(["jan"], ["credit-analysts"])] == []


async def test_cache_ttl_is_bounded(env: Env) -> None:
    assert GrantStore(lambda: None, ttl_s=60).ttl_s <= 5.0  # type: ignore[arg-type,return-value]


async def test_grants_version_is_monotonic_and_changes_are_append_only(env: Env) -> None:
    v0 = await env.grants.version()
    g1 = await grant(env, resource="smart")
    g2 = await grant(env, resource="auto")
    await env.grants.revoke(g1.id, ADMIN, "done")
    assert await env.grants.version() == v0 + 3
    eff = await env.resolver.effective_access(jan())
    assert eff.grants_version == str(v0 + 3) and eff.policy_version == "v1"
    changes = await env.grants.changes()
    assert [(c.change, c.grant_id) for c in changes] == [("revoke", g1.id), ("create", g2.id), ("create", g1.id)]
    assert changes[0].snapshot.revoked_at is not None and changes[2].snapshot.revoked_at is None  # point-in-time
    assert [c.change for c in await env.grants.changes(subject="jan", limit=1)] == ["revoke"]
    kinds = [(e[1]["detail"]["change"], e[1]["detail"]["grants_version"]) for e in env.audit.events]
    assert kinds == [("create", v0 + 1), ("create", v0 + 2), ("revoke", v0 + 3)]
    # the journal is keyed uniquely per (grant, change): a second `revoke` row cannot be inserted
    async with env.sm() as s:  # type: ignore[operator]
        assert len((await s.execute(select(GrantChangeRow))).scalars().all()) == 3
        with pytest.raises(SQLAlchemyError):
            await s.execute(
                text(
                    "INSERT INTO grant_changes (grant_id, change, actor, reason, at, snapshot) "
                    f"VALUES ('{g1.id}', 'revoke', 'x', 'x', '2026-01-01', '{{}}')"
                )
            )


async def test_list_filters(env: Env) -> None:
    g1 = await grant(env, resource="smart")
    g2 = await grant(env, resource="auto", expires_at=env.clock.t + timedelta(minutes=1))
    await env.grants.revoke(g1.id, ADMIN, "x")
    env.clock.advance(120)
    assert [g.id for g in await env.grants.list(active=True)] == []
    assert {g.id for g in await env.grants.list(active=False)} == {g1.id, g2.id}
    assert {g.id for g in await env.grants.list(active=None, resource="auto")} == {g2.id}
    assert {g.id for g in await env.grants.list(active=None, subject="jan")} == {g1.id, g2.id}


# ---------------------------------------------------------------- visibility, routing candidates, presets


async def test_visible_names_and_usable_models_for_developers(env: Env) -> None:
    names = await env.resolver.visible_names(anna())
    assert names == ["auto", "bielik", "local"]  # no cloud alias by default
    usable = await env.resolver.usable_models(anna())
    # `auto` expands to the routing targets (local, Flash, Pro): the cloud models are reachable only through `auto`
    assert set(usable) == {"local/qwen3.8-27b", "local/bielik", "gemini/flash", "gemini/pro"}
    assert usable["gemini/pro"] == [DataClass.public, DataClass.internal]  # still capped by LOCK-01
    assert not (await env.resolver.check_model(anna(), "smart")).allowed  # but not selectable by name
    assert not (await env.resolver.check_model(anna(), "smart-pro")).allowed
    # a personal grant (demo story F4) adds the explicit cloud alias
    await grant(env, subject="anna", resource="smart")
    assert await env.resolver.visible_names(anna()) == ["auto", "bielik", "local", "smart"]
    assert (await env.resolver.check_model(anna(), "smart")).allowed
    assert not (await env.resolver.check_model(anna(), "smart-pro")).allowed


async def test_visible_names_follow_grants(env: Env) -> None:
    before = await env.resolver.visible_names(jan())
    assert "smart" not in before and "skill/loan-memo-summary" in before and "auto" in before
    await grant(env, resource="smart")
    assert "smart" in await env.resolver.visible_names(jan())


async def test_effective_preset_resolution(env: Env) -> None:
    r = env.resolver
    assert await r.effective_preset(jan()) == Preset.strict  # group preset
    both = make_principal("x", ["developers", "credit-analysts"])
    assert await r.effective_preset(both) == Preset.strict  # strictest group wins
    assert await r.effective_preset(make_principal("nobody", [])) == env.policy.global_.default_preset
    g = await grant(env, resource="smart", constraints=GrantConstraints(preset=Preset.paranoid))
    assert await r.effective_preset(jan()) == Preset.paranoid  # a user grant can tighten the group preset ...
    eff = await r.effective_access(jan())
    assert eff.preset == Preset.paranoid and eff.preset_source == f"grant:{g.id}"
    lax = await grant(env, resource="local", constraints=GrantConstraints(preset=Preset.balanced))
    assert await r.effective_preset(jan()) == Preset.paranoid  # ... but never loosen it (test_sec_identity_*)
    await env.grants.revoke(lax.id, ADMIN, "x")
    await env.grants.revoke(g.id, ADMIN, "x")
    assert await r.effective_preset(jan()) == Preset.strict
    assert (await r.effective_access(jan())).preset_source == "group:credit-analysts"


async def test_effective_access_lists_sources(env: Env) -> None:
    eff = await env.resolver.effective_access(jan())
    assert eff.groups == ["credit-analysts"] and eff.preset == Preset.strict
    by_key = {(i.resource_type.value, i.resource): i for i in eff.items}
    assert by_key[("alias", "auto")].source == "group" and by_key[("alias", "auto")].source_ref == "credit-analysts"
    assert by_key[("mcp_server", "core-banking")].effect == "allow"
    assert by_key[("tool", "bank.query")].source_ref == "credit-analysts"
    assert by_key[("skill", "skill/loan-memo-summary")]


# ---------------------------------------------------------------- tools and MCP servers


async def test_tools_from_group_and_server_grants(env: Env) -> None:
    r = env.resolver
    c = await r.check_tool(anna(), "opencode.bash")
    assert c.allowed and c.source == "group:developers"
    assert not (await r.check_tool(anna(), "opencode.webfetch")).allowed  # group tier: deny → not granted
    assert (await r.check_tool(anna(), "mail.send")).allowed
    bad = await r.check_tool(jan(), "opencode.write")  # credit-analysts: read/edit/bash only
    assert not bad.allowed and bad.rule_id == "SEC-TOOL-01" and bad.source == "default"
    assert (await r.check_tool(jan(), "bank.query")).allowed
    assert not (await r.check_tool(jan(), "no.such-tool")).allowed


async def test_server_grant_covers_its_tools_and_user_tool_grant(env: Env) -> None:
    r = env.resolver
    assert not (await r.check_tool(jan(), "mail.read")).allowed
    g = await grant(env, resource_type=GrantResourceType.mcp_server, resource="mcp:mail")  # `mcp:` prefix accepted
    assert (await r.check_tool(jan(), "mail.read")).source == f"grant:{g.id}"
    assert (await r.check_tool(jan(), "mail.anything-new")).allowed  # unlisted tool of a granted server
    assert (await r.check_mcp_server(jan(), "mail")).allowed
    assert not (await r.check_tool(jan(), "opencode.write")).allowed
    await grant(env, subject="jan", resource_type=GrantResourceType.tool, resource="opencode.write")
    assert (await r.check_tool(jan(), "opencode.write")).allowed


async def test_user_tool_deny_and_revocation(env: Env) -> None:
    g = await grant(env, subject="anna", resource_type=GrantResourceType.tool, resource="opencode.bash", effect="deny")
    assert not (await env.resolver.check_tool(anna(), "opencode.bash")).allowed
    assert "opencode.bash" not in await env.resolver.visible_tools(anna())
    await env.grants.revoke(g.id, ADMIN, "restored")
    assert (await env.resolver.check_tool(anna(), "opencode.bash")).allowed


async def test_tool_org_lock_and_server_allowlist(env: Env) -> None:
    def patch(d: dict[str, Any]) -> None:
        d["org_locks"].append(
            {"kind": "deny_resource", "id": "LOCK-07", "resource_type": "tool", "resources": ["mail.send"]}
        )
        d["mcp_servers"]["web"]["allowed"] = False

    env.engine.policy = patch_policy(env.policy, patch)
    c = await env.resolver.check_tool(anna(), "mail.send")
    assert not c.allowed and c.rule_id == "LOCK-07"
    w = await env.resolver.check_tool(anna(), "web.fetch")
    assert not w.allowed and "allowlist" in w.reason
    assert not (await env.resolver.check_mcp_server(anna(), "web")).allowed


async def test_agent_group_tools(env: Env) -> None:
    bot = make_principal("bot", ["agents/research-bot"], kind="agent", agent_id="research-bot")
    assert (await env.resolver.check_tool(bot, "web.fetch")).allowed
    assert not (await env.resolver.check_tool(bot, "opencode.bash")).allowed
    assert (await env.resolver.check_model(bot, "local")).allowed
    assert not (await env.resolver.check_model(bot, "auto")).allowed
    assert set(await env.resolver.usable_models(bot)) == {"local/qwen3.8-27b"}


# ---------------------------------------------------------------- grant validation (admin API uses it)


async def test_validate_grant(env: Env) -> None:
    v = env.resolver.validate_grant
    assert v(GrantResourceType.alias, "smart") is None
    assert "unknown" in (v(GrantResourceType.model, "nope/x") or "")
    assert "unknown" in (v(GrantResourceType.tool, "nope.x") or "")
    assert "unknown" in (v(GrantResourceType.mcp_server, "mcp:nope") or "")
    assert v(GrantResourceType.connector, "connector:gemini") is None

    def lock(d: dict[str, Any]) -> None:
        d["org_locks"].append(
            {
                "kind": "deny_resource",
                "id": "LOCK-08",
                "resource_type": "connector",
                "resources": ["gemini"],
                "except_groups": ["admins"],
            }
        )

    env.engine.policy = patch_policy(env.policy, lock)
    assert "LOCK-08" in (v(GrantResourceType.alias, "smart", group_subject="developers") or "")
    assert v(GrantResourceType.alias, "smart", group_subject="admins") is None  # exempt group
    assert v(GrantResourceType.alias, "smart") is None  # user grant: enforced at request time
