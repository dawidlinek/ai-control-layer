"""Approvals service: lifecycle (create → decide → wait → expiry), scope rules, elevations, audit."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from acl.approvals.service import (
    ApprovalConflict,
    ApprovalForbidden,
    ApprovalNotFound,
    ApprovalService,
    is_privileged,
)
from acl.approvals.testing import build_engine, tool_ctx
from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.contracts.common import Action, ApprovalStatus, AuthMethod
from acl.contracts.inspection import Principal
from acl.db import create_all, make_engine, make_sessionmaker
from acl.testing import make_principal


class Clock:
    def __init__(self) -> None:
        self.t = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.t

    def advance(self, **kw: float) -> None:
        self.t += timedelta(**kw)


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[tuple[ApprovalService, Clock, RecordingSink]]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
    await create_all(engine)
    maker = make_sessionmaker(engine)
    clock, audit = Clock(), RecordingSink()
    svc = ApprovalService(lambda: maker, lambda: audit, now=clock, salt=lambda: "test-salt")
    yield svc, clock, audit
    await engine.dispose()


async def _held(
    svc: ApprovalService, *, user: str = "anna", scope: str = "user", session: str = "s1", tool: str = "mail.send"
):
    eng = build_engine(["SEC-TOOL-01"])
    ctx = tool_ctx(tool, {"to": "a@corp.example", "body": "SECRETBODY"}, username=user, session_id=session)
    decision = await eng.evaluate(ctx)
    assert decision.action == Action.require_approval
    ref = await svc.create(ctx, decision, approver_scope=scope, preview="mail.send\nto: a@corp.example")  # type: ignore[arg-type]
    return ref, ctx


def admin(name: str = "adam", roles: tuple[str, ...] = ("acl-admin",), **kw) -> Principal:
    return make_principal(name, ["admins"], roles=list(roles), **kw)


async def test_create_returns_a_pending_ref_and_audits(env) -> None:
    svc, clock, audit = env
    ref, ctx = await _held(svc)
    assert ref.status == ApprovalStatus.pending and ref.approver_scope == "user"
    assert ref.expires_at == clock.t + timedelta(minutes=15)
    a = await svc.get(ref.approval_id)
    assert a.status == ApprovalStatus.pending and a.tool == "mail.send" and a.requested_by == "anna"
    assert a.session_id == ctx.session_id and a.trace_id == ctx.trace_id
    assert "SEC-TOOL-01" in a.rule_ids and a.arguments_preview.startswith("mail.send")
    kinds = [(t, k["detail"]["state"]) for t, k in audit.events]
    assert kinds == [(EventType.approval, "created")]
    detail = audit.events[0][1]["detail"]
    assert detail["args_hash"] and "SECRETBODY" not in str(detail)


async def test_user_approves_own_user_scope_request(env) -> None:
    svc, _, audit = env
    ref, ctx = await _held(svc)
    out = await svc.decide(ref.approval_id, approve=True, actor=ctx.principal, elevation_minutes=None, note="ok")
    assert out.status == ApprovalStatus.approved and out.decided_by == "anna" and out.decided_at
    assert await svc.wait(ref.approval_id, 1.0) == ApprovalStatus.approved
    states = [k["detail"]["state"] for _, k in audit.events]
    assert states == ["created", "approved"]
    assert audit.events[-1][1]["detail"]["note_len"] == 2 and "ok" not in str(audit.events[-1][1]["detail"].values())


async def test_deny_and_double_decision_conflicts(env) -> None:
    svc, _, _ = env
    ref, ctx = await _held(svc)
    out = await svc.decide(ref.approval_id, approve=False, actor=ctx.principal, elevation_minutes=None, note=None)
    assert out.status == ApprovalStatus.denied
    assert await svc.wait(ref.approval_id, 0.5) == ApprovalStatus.denied
    with pytest.raises(ApprovalConflict):
        await svc.decide(ref.approval_id, approve=True, actor=ctx.principal, elevation_minutes=None, note=None)


async def test_scope_rules(env) -> None:
    svc, _, _ = env
    ref, _ = await _held(svc, scope="user")
    other = make_principal("eve", ["developers"], roles=[])
    with pytest.raises(ApprovalForbidden):  # another user may not decide
        await svc.decide(ref.approval_id, approve=True, actor=other, elevation_minutes=None, note=None)
    key_admin = admin(auth_method=AuthMethod.api_key)
    assert not is_privileged(key_admin)
    with pytest.raises(ApprovalForbidden):  # an API key never counts as an admin sign-in
        await svc.decide(ref.approval_id, approve=True, actor=key_admin, elevation_minutes=None, note=None)
    assert is_privileged(admin()) and is_privileged(admin(roles=("acl-analyst",)))
    assert not is_privileged(admin(roles=("acl-viewer",)))
    with pytest.raises(ApprovalForbidden):  # viewers cannot decide
        await svc.decide(
            ref.approval_id, approve=True, actor=admin(roles=("acl-viewer",)), elevation_minutes=None, note=None
        )

    adm_ref, adm_ctx = await _held(svc, scope="admin")
    with pytest.raises(ApprovalForbidden):  # the requester may not decide an admin-scope approval
        await svc.decide(adm_ref.approval_id, approve=True, actor=adm_ctx.principal, elevation_minutes=None, note=None)
    ok = await svc.decide(
        adm_ref.approval_id, approve=True, actor=admin(roles=("acl-analyst",)), elevation_minutes=None, note=None
    )
    assert ok.status == ApprovalStatus.approved and ok.decided_by == "adam"

    # an admin can also decide a user-scope approval of someone else
    out = await svc.decide(ref.approval_id, approve=False, actor=admin(), elevation_minutes=None, note=None)
    assert out.status == ApprovalStatus.denied


async def test_unknown_id(env) -> None:
    svc, _, _ = env
    with pytest.raises(ApprovalNotFound):
        await svc.get("apr-nope")


async def test_expiry_default_15_minutes(env) -> None:
    svc, clock, audit = env
    ref, ctx = await _held(svc)
    clock.advance(minutes=14, seconds=59)
    assert (await svc.get(ref.approval_id)).status == ApprovalStatus.pending
    clock.advance(seconds=2)
    assert (await svc.get(ref.approval_id)).status == ApprovalStatus.expired
    with pytest.raises(ApprovalConflict):
        await svc.decide(ref.approval_id, approve=True, actor=ctx.principal, elevation_minutes=None, note=None)
    assert await svc.wait(ref.approval_id, 0.2) == ApprovalStatus.expired
    assert [k["detail"]["state"] for _, k in audit.events].count("expired") == 1  # audited exactly once


async def test_list_filters_and_expires_stale(env) -> None:
    svc, clock, _ = env
    r1, c1 = await _held(svc, session="a")
    r2, _ = await _held(svc, session="b")
    await svc.decide(r1.approval_id, approve=True, actor=c1.principal, elevation_minutes=None, note=None)
    assert {a.id for a in await svc.list(ApprovalStatus.pending)} == {r2.approval_id}
    assert {a.id for a in await svc.list(ApprovalStatus.approved)} == {r1.approval_id}
    clock.advance(minutes=16)
    assert await svc.list(ApprovalStatus.pending) == []
    assert {a.id for a in await svc.list(ApprovalStatus.expired)} == {r2.approval_id}
    assert {a.id for a in await svc.list(None)} == {r1.approval_id, r2.approval_id}


async def test_wait_returns_pending_on_timeout_and_wakes_on_decision(env) -> None:
    svc, _, _ = env
    ref, ctx = await _held(svc)
    t0 = asyncio.get_running_loop().time()
    assert await svc.wait(ref.approval_id, 0.15) == ApprovalStatus.pending
    assert asyncio.get_running_loop().time() - t0 < 1.0

    waiter = asyncio.create_task(svc.wait(ref.approval_id, 5.0))
    await asyncio.sleep(0.05)
    await svc.decide(ref.approval_id, approve=True, actor=ctx.principal, elevation_minutes=None, note=None)
    assert await asyncio.wait_for(waiter, 1.0) == ApprovalStatus.approved


async def test_elevation_lifecycle(env) -> None:
    svc, clock, _ = env
    ref, ctx = await _held(svc, session="sess-e", tool="mail.send")
    assert await svc.elevation(ctx.session_id, "mail.send") is None  # pending approvals do not elevate
    out = await svc.decide(ref.approval_id, approve=True, actor=admin(), elevation_minutes=10, note=None)
    assert out.elevation and out.elevation.scope == "tool:mail.send"
    until = await svc.elevation(ctx.session_id, "mail.send")
    assert until == clock.t + timedelta(minutes=10)
    assert await svc.elevation(ctx.session_id, "opencode.write") is None  # bound to the tool
    assert await svc.elevation("another-session", "mail.send") is None  # and to the session
    clock.advance(minutes=9, seconds=59)
    assert await svc.elevation(ctx.session_id, "mail.send") is not None
    clock.advance(seconds=2)
    assert await svc.elevation(ctx.session_id, "mail.send") is None  # expired


async def test_denied_or_plain_approvals_grant_no_elevation(env) -> None:
    svc, _, _ = env
    r1, c1 = await _held(svc, session="s-d")
    await svc.decide(r1.approval_id, approve=False, actor=admin(), elevation_minutes=30, note=None)
    r2, c2 = await _held(svc, session="s-p")
    await svc.decide(r2.approval_id, approve=True, actor=admin(), elevation_minutes=None, note=None)
    assert await svc.elevation(c1.session_id, "mail.send") is None
    assert await svc.elevation(c2.session_id, "mail.send") is None


async def test_elevation_caps(env) -> None:
    svc, clock, _ = env
    r1, c1 = await _held(svc, session="s-u")
    await svc.decide(r1.approval_id, approve=True, actor=c1.principal, elevation_minutes=240, note=None)
    assert await svc.elevation(c1.session_id, "mail.send") == clock.t + timedelta(minutes=60)  # users: 60
    r2, c2 = await _held(svc, session="s-a")
    await svc.decide(r2.approval_id, approve=True, actor=admin(), elevation_minutes=240, note=None)
    assert await svc.elevation(c2.session_id, "mail.send") == clock.t + timedelta(minutes=240)


async def test_after_approve_hook_runs_only_on_approval(env) -> None:
    svc, _, _ = env
    seen: list[str] = []

    async def hook(row) -> None:
        seen.append(row.id)

    svc.after_approve = hook
    r1, c1 = await _held(svc, session="h1")
    r2, c2 = await _held(svc, session="h2")
    await svc.decide(r1.approval_id, approve=True, actor=c1.principal, elevation_minutes=None, note=None)
    await svc.decide(r2.approval_id, approve=False, actor=c2.principal, elevation_minutes=None, note=None)
    assert seen == [r1.approval_id]


async def test_approval_ids_are_unguessable_and_unique(env) -> None:
    svc, _, _ = env
    ids = {(await _held(svc, session=f"s{i}"))[0].approval_id for i in range(5)}
    assert len(ids) == 5 and all(i.startswith("apr-") and len(i) >= 20 for i in ids)
