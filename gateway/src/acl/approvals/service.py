"""Approval service: the human-in-the-loop queue for `require_approval` decisions (concept §6.3, §9).

    create(ctx, decision, approver_scope=, preview=) -> ApprovalRef     hold a call; expires after `ttl` (15 min)
    get(id) -> Approval                                                 (expires lazily)
    list(status=) -> [Approval]
    decide(id, approve=, actor=, elevation_minutes=, note=) -> Approval approve / deny, optional elevation
    wait(id, timeout_s) -> ApprovalStatus                               long-poll (in-process wake-up + 1 s DB poll)
    elevation(session_id, tool_id) -> datetime | None                   active time-boxed elevation (SEC-TOOL-01)

Scope rules (`approver_scope`):
  * `user`  – confirm-tier decisions on the user's own tools: the requesting user may decide; admins / analysts too;
  * `admin` – everything else (Rule of Two, signature feed holds, ...): analysts / admins only (admin API).
An API-key principal never counts as admin/analyst (admin roles need a fresh Keycloak sign-in, see `api/deps.py`).
Elevation (approve + `elevation_minutes`) is bound to `(session, tool)`, capped at 240 min for admins and 60 min for
users, and only waives SEC-TOOL-01's own approval reasons; it never relaxes a block or the Rule of Two.

Every create / decision / expiry is written to the audit log as an `approval` event (no raw arguments: preview text is
redacted by the caller, arguments appear only as a salted hash; approver notes only as length + hash).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import uuid
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta
from typing import Any, Literal

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.approvals.db_models import ApprovalRow
from acl.contracts.admin import Approval
from acl.contracts.audit import EventType
from acl.contracts.canonical import canonical_json, value_hash
from acl.contracts.common import Action, ApprovalStatus, AuthMethod, Severity
from acl.contracts.decide import Elevation
from acl.contracts.decision import ApprovalRef, Decision
from acl.contracts.inspection import InspectionContext, Principal, ToolCallPayload
from acl.controls.taint.sinks import call_is_sink
from acl.engine.transforms import enforced_verdicts
from acl.identity.db_models import utcnow

log = logging.getLogger(__name__)

DEFAULT_TTL = timedelta(minutes=15)
ADMIN_ELEVATION_MAX_MIN = 240
USER_ELEVATION_MAX_MIN = 60
PRIVILEGED_ROLES = frozenset({"acl-admin", "acl-analyst"})
Scope = Literal["user", "admin"]


class ApprovalError(Exception):
    status_code = 400


class ApprovalNotFound(ApprovalError):
    status_code = 404


class ApprovalForbidden(ApprovalError):
    status_code = 403


class ApprovalConflict(ApprovalError):
    status_code = 409


def is_privileged(principal: Principal) -> bool:
    """Analyst or admin sign-in (never an API key)."""
    return principal.auth_method != AuthMethod.api_key and bool(PRIVILEGED_ROLES & set(principal.roles))


def approver_scope_for(engine: Any, decision: Decision) -> Scope:
    """Who may decide a held call. `user` only when every enforced approval request comes from SEC-TOOL-01 (the
    user's own confirm-tier tools, unlisted shell commands, writes); the Rule of Two, signature-feed holds and any
    other control need an administrator. Shared by `/v1/decide` and the MCP proxy."""
    holders = [v for v in enforced_verdicts(engine, decision) if v.action == Action.require_approval]
    return "user" if holders and all(v.control_type == "tool_policy" for v in holders) else "admin"


def _label(principal: Principal) -> str:
    return principal.username or principal.subject


class ApprovalService:
    def __init__(
        self,
        sessions: Callable[[], async_sessionmaker[AsyncSession]],
        audit: Callable[[], Any] = lambda: None,
        *,
        ttl: timedelta = DEFAULT_TTL,
        now: Callable[[], datetime] = utcnow,
        salt: Callable[[], str] = lambda: "dev-salt",
        policy_view: Callable[[], Any] = lambda: None,
    ) -> None:
        self._policy_view = policy_view
        self._sessions = sessions
        self._audit = audit
        self.ttl = ttl
        self._now = now
        self._salt = salt
        self._events: dict[str, asyncio.Event] = {}
        # Called after an approval was granted so the caller's labels (egress_used, untrusted/sensitive output of the
        # now-allowed call) reach the session: `async (row: ApprovalRow) -> None`. Observation only.
        self.after_approve: Callable[[ApprovalRow], Awaitable[None]] | None = None

    # ------------------------------------------------------------ helpers

    def _event(self, approval_id: str) -> asyncio.Event:
        return self._events.setdefault(approval_id, asyncio.Event())

    def _wake(self, approval_id: str) -> None:
        ev = self._events.get(approval_id)
        if ev is not None:
            ev.set()

    def to_contract(self, row: ApprovalRow) -> Approval:
        elev = None
        if row.elevation_until is not None and row.elevation_scope:
            elev = Elevation(scope=row.elevation_scope, until=row.elevation_until)
        return Approval(
            id=row.id,
            status=ApprovalStatus(row.status),
            approver_scope=row.approver_scope,  # type: ignore[arg-type]
            created_at=row.created_at,
            expires_at=row.expires_at,
            requested_by=row.requested_by,
            session_id=row.session_id,
            trace_id=row.trace_id,
            tool=row.tool,
            server=row.server,
            arguments_preview=row.arguments_preview,
            reason=row.reason,
            rule_ids=list(row.rule_ids or []),
            risk_score=row.risk_score,
            decided_by=row.decided_by,
            decided_at=row.decided_at,
            elevation=elev,
        )

    async def _record(self, state: str, row: ApprovalRow, actor: Principal | None = None, **extra: Any) -> None:
        sink = self._audit()
        if sink is None:
            return
        detail = {
            "approval_id": row.id,
            "state": state,
            "approver_scope": row.approver_scope,
            "tool": row.tool,
            "server": row.server,
            "rule_ids": list(row.rule_ids or []),
            "args_hash": row.args_hash,
            "requested_by": row.requested_by,
            "expires_at": row.expires_at.isoformat(),
            **extra,
        }
        severity = Severity.medium if state in ("denied", "expired") else Severity.info
        try:
            await sink.record_event(
                EventType.approval,
                severity=severity,
                detail=detail,
                principal=actor,
                trace_id=row.trace_id,
                session_id=row.session_id,
            )
        except Exception:  # an audit failure must not lose the approval state, but is loud
            log.exception("could not record approval event %s", row.id)

    async def _expire_due(self, s: AsyncSession, rows: list[ApprovalRow]) -> list[ApprovalRow]:
        now = self._now()
        expired: list[ApprovalRow] = []
        for row in rows:
            if row.status == ApprovalStatus.pending.value and row.expires_at <= now:
                res = await s.execute(
                    update(ApprovalRow)
                    .where(ApprovalRow.id == row.id, ApprovalRow.status == ApprovalStatus.pending.value)
                    .values(status=ApprovalStatus.expired.value)
                )
                if res.rowcount:
                    row.status = ApprovalStatus.expired.value
                    expired.append(row)
        if expired:
            await s.commit()
        return expired

    async def _after_expiry(self, expired: list[ApprovalRow]) -> None:
        for row in expired:
            self._wake(row.id)
            await self._record("expired", row)

    # ------------------------------------------------------------ API

    async def create(
        self, ctx: InspectionContext, decision: Decision, *, approver_scope: Scope, preview: str
    ) -> ApprovalRef:
        now = self._now()
        payload = ctx.payload
        tool = server = args_hash = None
        egress = False
        if isinstance(payload, ToolCallPayload):
            tool, server = payload.tool, payload.server
            args_hash = value_hash(canonical_json(payload.arguments), self._salt(), 64)  # same as the audit record
            policy = self._policy_view()
            catalogue = policy.tools.get(tool) if policy is not None else None
            egress = catalogue is not None and call_is_sink(catalogue, payload)[0]
        row = ApprovalRow(
            id=f"apr-{uuid.uuid4().hex[:16]}",
            status=ApprovalStatus.pending.value,
            approver_scope=approver_scope,
            created_at=now,
            expires_at=now + self.ttl,
            requester_subject=ctx.principal.subject,
            requested_by=_label(ctx.principal),
            session_id=ctx.session_id,
            trace_id=ctx.trace_id,
            decision_id=decision.decision_id,
            tool=tool,
            server=server,
            arguments_preview=preview[:2000],
            args_hash=args_hash,
            egress=egress,
            reason=(decision.reason or "")[:1000],
            rule_ids=list(decision.rule_ids),
            risk_score=decision.risk_score,
            detail={},
        )
        async with self._sessions()() as s:
            s.add(row)
            await s.commit()
        await self._record("created", row, ctx.principal)
        return ApprovalRef(
            approval_id=row.id, status=ApprovalStatus.pending, expires_at=row.expires_at, approver_scope=approver_scope
        )

    async def _load(self, approval_id: str) -> ApprovalRow:
        async with self._sessions()() as s:
            row = await s.get(ApprovalRow, approval_id)
            if row is None:
                raise ApprovalNotFound(f"approval {approval_id!r} not found")
            expired = await self._expire_due(s, [row])
        await self._after_expiry(expired)
        return row

    async def get_row(self, approval_id: str) -> ApprovalRow:
        return await self._load(approval_id)

    async def get(self, approval_id: str) -> Approval:
        return self.to_contract(await self._load(approval_id))

    async def list(self, status: ApprovalStatus | None = None, *, limit: int = 200) -> list[Approval]:
        async with self._sessions()() as s:
            due = (
                (
                    await s.execute(
                        select(ApprovalRow).where(
                            ApprovalRow.status == ApprovalStatus.pending.value, ApprovalRow.expires_at <= self._now()
                        )
                    )
                )
                .scalars()
                .all()
            )
            expired = await self._expire_due(s, list(due))
            stmt = select(ApprovalRow).order_by(ApprovalRow.created_at.desc()).limit(limit)
            if status is not None:
                stmt = stmt.where(ApprovalRow.status == status.value)
            rows = (await s.execute(stmt)).scalars().all()
        await self._after_expiry(expired)
        return [self.to_contract(r) for r in rows]

    async def decide(
        self,
        approval_id: str,
        *,
        approve: bool,
        actor: Principal,
        elevation_minutes: int | None = None,
        note: str | None = None,
    ) -> Approval:
        row = await self._load(approval_id)
        privileged = is_privileged(actor)
        if not privileged and not (row.approver_scope == "user" and row.requester_subject == actor.subject):
            raise ApprovalForbidden(
                "this approval can only be decided by its requester (user scope) or an administrator"
            )
        if row.status != ApprovalStatus.pending.value:
            raise ApprovalConflict(f"approval is already {row.status}")
        now = self._now()
        until: datetime | None = None
        scope: str | None = None
        if approve and elevation_minutes and row.tool:
            cap = ADMIN_ELEVATION_MAX_MIN if privileged else USER_ELEVATION_MAX_MIN
            until = now + timedelta(minutes=min(elevation_minutes, cap))
            scope = f"tool:{row.tool}"
        new_status = ApprovalStatus.approved if approve else ApprovalStatus.denied
        async with self._sessions()() as s:
            res = await s.execute(
                update(ApprovalRow)
                .where(
                    ApprovalRow.id == approval_id,
                    ApprovalRow.status == ApprovalStatus.pending.value,
                    ApprovalRow.expires_at > now,
                )
                .values(
                    status=new_status.value,
                    decided_by=_label(actor),
                    decided_at=now,
                    note=note,
                    elevation_scope=scope,
                    elevation_until=until,
                )
            )
            await s.commit()
            if not res.rowcount:
                raise ApprovalConflict("approval is no longer pending (decided or expired concurrently)")
            row = await s.get(ApprovalRow, approval_id)  # type: ignore[assignment]
        assert row is not None
        self._wake(approval_id)
        await self._record(
            new_status.value,
            row,
            actor,
            decided_by=_label(actor),
            elevation_until=until.isoformat() if until else None,
            note_len=len(note) if note else 0,
            note_hash=value_hash(note, self._salt()) if note else None,
        )
        if approve and self.after_approve is not None:
            try:
                await self.after_approve(row)
            except Exception:
                log.exception("post-approval label update failed for %s", approval_id)
        return self.to_contract(row)

    async def wait(self, approval_id: str, timeout_s: float) -> ApprovalStatus:
        loop = asyncio.get_running_loop()
        deadline = loop.time() + max(0.0, timeout_s)
        event = self._event(approval_id)
        while True:
            event.clear()
            row = await self._load(approval_id)
            status = ApprovalStatus(row.status)
            remaining = deadline - loop.time()
            if status != ApprovalStatus.pending or remaining <= 0:
                return status
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(event.wait(), timeout=min(remaining, 1.0))

    async def elevation(self, session_id: str, tool_id: str) -> datetime | None:
        """Latest active elevation end for `(session, tool)`, else None."""
        now = self._now()
        async with self._sessions()() as s:
            stmt = (
                select(ApprovalRow.elevation_until)
                .where(
                    ApprovalRow.session_id == session_id,
                    ApprovalRow.tool == tool_id,
                    ApprovalRow.status == ApprovalStatus.approved.value,
                    ApprovalRow.elevation_until.is_not(None),
                    ApprovalRow.elevation_until > now,
                )
                .order_by(ApprovalRow.elevation_until.desc())
                .limit(1)
            )
            return (await s.execute(stmt)).scalar_one_or_none()
