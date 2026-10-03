"""Grant store: per-user / per-group assignments in the DB (concept §11).

* every change is journalled in the append-only `grant_changes` table and bumps a monotonic version
  in the same transaction;
* reads go through a short-lived cache (<= 5 s) that is cleared immediately on any local change, so a
  revocation applies on the next request (other gateway replicas see it within the TTL);
* expired grants are ignored at resolution time (checked against the clock on every use, never
  cached) and journalled as `expire` lazily by `sweep_expired()`.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import and_, desc, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from acl.contracts.admin import Grant, GrantChange, GrantConstraints, GrantCreate
from acl.contracts.audit import EventType
from acl.contracts.common import GrantResourceType, Severity
from acl.contracts.inspection import Principal
from acl.identity.db_models import GrantChangeRow, GrantRow, GrantsMetaRow, utcnow
from acl.identity.users import SessionMaker

log = logging.getLogger(__name__)

MAX_TTL_S = 5.0  # hard ceiling for the cache TTL
MAX_STALE_S = 5.0  # a cached view older than this is never served


class GrantNotFound(LookupError):
    pass


class GrantAlreadyRevoked(ValueError):
    pass


def grant_from_row(row: GrantRow, *, now: datetime | None = None) -> Grant:
    now = now or utcnow()
    active = row.revoked_at is None and (row.expires_at is None or row.expires_at > now)
    return Grant(
        id=row.id,
        subject_type=row.subject_type,  # type: ignore[arg-type]
        subject=row.subject,
        resource_type=GrantResourceType(row.resource_type),
        resource=row.resource,
        effect=row.effect,  # type: ignore[arg-type]
        constraints=GrantConstraints.model_validate(row.constraints or {}),
        expires_at=row.expires_at,
        reason=row.reason,
        created_by=row.created_by,
        created_at=row.created_at,
        revoked_at=row.revoked_at,
        revoked_by=row.revoked_by,
        active=active,
    )


def is_live(grant: Grant, now: datetime) -> bool:
    return grant.revoked_at is None and (grant.expires_at is None or grant.expires_at > now)


def normalise_resource(resource_type: GrantResourceType, resource: str) -> str:
    resource = resource.strip()
    if resource_type == GrantResourceType.mcp_server:
        return resource.removeprefix("mcp:")
    if resource_type == GrantResourceType.connector:
        return resource.removeprefix("connector:")
    return resource


class GrantStore:
    def __init__(
        self,
        sessions: SessionMaker,
        *,
        audit: Callable[[], Any] = lambda: None,
        ttl_s: float = 2.0,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = utcnow,
        sweep_interval_s: float = 30.0,
    ) -> None:
        self._sessions = sessions
        self._audit = audit
        self.ttl_s = min(ttl_s, MAX_TTL_S)
        self._clock = clock
        self._now = now
        self._sweep_interval_s = sweep_interval_s
        self._cache: dict[tuple[frozenset[str], frozenset[str]], tuple[float, list[Grant]]] = {}
        self._version_cache: tuple[float, int] | None = None
        self._epoch = 0
        self._last_sweep: float | None = None
        self._refreshing: set[tuple[frozenset[str], frozenset[str]]] = set()
        self._tasks: set[asyncio.Task[None]] = set()

    # ------------------------------------------------------------ cache

    def invalidate(self) -> None:
        self._epoch += 1
        self._cache.clear()
        self._version_cache = None

    async def version(self) -> int:
        cached = self._version_cache
        if cached is not None and self._clock() - cached[0] < self.ttl_s:
            return cached[1]
        epoch = self._epoch
        async with self._sessions()() as s:
            row = await s.get(GrantsMetaRow, 1)
            version = int(row.version) if row else 0
        if epoch == self._epoch:
            self._version_cache = (self._clock(), version)
        return version

    async def ensure_meta(self) -> None:
        async with self._sessions()() as s:
            try:
                async with s.begin():
                    if await s.get(GrantsMetaRow, 1) is None:
                        s.add(GrantsMetaRow(id=1, version=0))
            except IntegrityError:  # another replica created it first
                pass

    async def active_for(self, user_keys: Sequence[str], groups: Sequence[str]) -> list[Grant]:
        """Live (non-revoked, non-expired) grants addressed to this user (subject/username) or these groups.

        Cache: fresh for `ttl_s`; between `ttl_s` and `MAX_STALE_S` the previous result is served while one
        background refresh runs (keeps DB latency out of the request path); older than that, or after any local
        change (`invalidate()`), the call waits for the DB. A DB failure then propagates (callers fail closed).
        """
        key = (frozenset(user_keys), frozenset(groups))
        now = self._now()
        cached = self._cache.get(key)
        if cached is not None:
            age = self._clock() - cached[0]
            if age < self.ttl_s:
                return [g for g in cached[1] if is_live(g, now)]
            if age < MAX_STALE_S:
                self._refresh_in_background(key, user_keys, groups)
                return [g for g in cached[1] if is_live(g, now)]
        grants = await self._load(key, user_keys, groups)
        await self._maybe_sweep()
        return [g for g in grants if is_live(g, now)]

    async def _load(
        self, key: tuple[frozenset[str], frozenset[str]], user_keys: Sequence[str], groups: Sequence[str]
    ) -> list[Grant]:
        epoch = self._epoch
        conds = []
        if user_keys:
            conds.append(and_(GrantRow.subject_type == "user", GrantRow.subject.in_(list(user_keys))))
        if groups:
            conds.append(and_(GrantRow.subject_type == "group", GrantRow.subject.in_(list(groups))))
        if not conds:
            return []
        async with self._sessions()() as s:
            rows = (await s.execute(select(GrantRow).where(GrantRow.revoked_at.is_(None), or_(*conds)))).scalars().all()
        now = self._now()
        grants = [grant_from_row(r, now=now) for r in rows]
        if epoch == self._epoch:  # a change landed while we were reading: do not cache a possibly stale view
            self._cache[key] = (self._clock(), grants)
        return grants

    def _refresh_in_background(
        self, key: tuple[frozenset[str], frozenset[str]], user_keys: Sequence[str], groups: Sequence[str]
    ) -> None:
        if key in self._refreshing:
            return
        self._refreshing.add(key)

        async def run() -> None:
            try:
                await self._load(key, user_keys, groups)
            except Exception:
                log.warning("background grant refresh failed; serving the previous view until it expires")
            finally:
                self._refreshing.discard(key)

        task = asyncio.get_running_loop().create_task(run())
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    # ------------------------------------------------------------ writes

    async def _bump_version(self, s: AsyncSession) -> int:
        res = await s.execute(
            update(GrantsMetaRow).where(GrantsMetaRow.id == 1).values(version=GrantsMetaRow.version + 1)
        )
        if res.rowcount == 0:
            s.add(GrantsMetaRow(id=1, version=1))
            return 1
        await s.flush()
        row = await s.get(GrantsMetaRow, 1, populate_existing=True)
        return int(row.version) if row else 0

    async def create(self, body: GrantCreate, actor: Principal) -> Grant:
        now = self._now()
        resource = normalise_resource(body.resource_type, body.resource)
        subject = body.subject.strip("/") if body.subject_type == "group" else body.subject.strip()
        row = GrantRow(
            id=f"grt_{uuid.uuid4().hex[:16]}",
            subject_type=body.subject_type,
            subject=subject,
            resource_type=body.resource_type.value,
            resource=resource,
            effect=body.effect,
            constraints=body.constraints.model_dump(mode="json", exclude_none=True),
            expires_at=body.expires_at,
            reason=body.reason,
            created_by=_actor_name(actor),
            created_at=now,
        )
        async with self._sessions()() as s, s.begin():
            s.add(row)
            await s.flush()
            grant = grant_from_row(row, now=now)
            version = await self._bump_version(s)
            s.add(
                GrantChangeRow(
                    grant_id=row.id,
                    change="create",
                    actor=row.created_by,
                    reason=body.reason,
                    at=now,
                    snapshot=grant.model_dump(mode="json"),
                )
            )
        self.invalidate()
        await self._emit("create", grant, actor, version)
        return grant

    async def revoke(self, grant_id: str, actor: Principal, reason: str) -> Grant:
        now = self._now()
        async with self._sessions()() as s, s.begin():
            row = await s.get(GrantRow, grant_id)
            if row is None:
                raise GrantNotFound(grant_id)
            if row.revoked_at is not None:
                raise GrantAlreadyRevoked(grant_id)
            row.revoked_at = now
            row.revoked_by = _actor_name(actor)
            grant = grant_from_row(row, now=now)
            version = await self._bump_version(s)
            s.add(
                GrantChangeRow(
                    grant_id=row.id,
                    change="revoke",
                    actor=row.revoked_by,
                    reason=reason,
                    at=now,
                    snapshot=grant.model_dump(mode="json"),
                )
            )
        self.invalidate()
        await self._emit("revoke", grant, actor, version, reason=reason)
        return grant

    async def _maybe_sweep(self) -> None:
        if self._last_sweep is not None and self._clock() - self._last_sweep < self._sweep_interval_s:
            return
        self._last_sweep = self._clock()
        try:
            await self.sweep_expired()
        except Exception:  # journalling expiry must never break authorisation
            log.exception("grant expiry sweep failed")

    async def sweep_expired(self) -> list[Grant]:
        """Journal an `expire` change for every grant whose expiry passed (idempotent, unique per grant)."""
        now = self._now()
        done: list[Grant] = []
        async with self._sessions()() as s:
            rows = (
                (
                    await s.execute(
                        select(GrantRow).where(
                            GrantRow.revoked_at.is_(None), GrantRow.expires_at.is_not(None), GrantRow.expires_at <= now
                        )
                    )
                )
                .scalars()
                .all()
            )
            known = set(
                (await s.execute(select(GrantChangeRow.grant_id).where(GrantChangeRow.change == "expire"))).scalars()
            )
        for row in rows:
            if row.id in known:
                continue
            grant = grant_from_row(row, now=now)
            try:
                async with self._sessions()() as s, s.begin():
                    s.add(
                        GrantChangeRow(
                            grant_id=row.id,
                            change="expire",
                            actor="system",
                            reason="grant expired",
                            at=row.expires_at or now,
                            snapshot=grant.model_dump(mode="json"),
                        )
                    )
            except IntegrityError:
                continue
            done.append(grant)
            await self._emit("expire", grant, None, None, reason="grant expired")
        return done

    # ------------------------------------------------------------ reads

    async def get(self, grant_id: str) -> Grant | None:
        async with self._sessions()() as s:
            row = await s.get(GrantRow, grant_id)
            return grant_from_row(row) if row else None

    async def list(
        self,
        *,
        subject: str | None = None,
        resource_type: GrantResourceType | None = None,
        resource: str | None = None,
        active: bool | None = True,
    ) -> list[Grant]:
        stmt = select(GrantRow).order_by(desc(GrantRow.created_at), desc(GrantRow.id))
        if subject:
            stmt = stmt.where(GrantRow.subject == subject.strip("/"))
        if resource_type:
            stmt = stmt.where(GrantRow.resource_type == resource_type.value)
        if resource:
            stmt = stmt.where(GrantRow.resource == resource)
        async with self._sessions()() as s:
            rows = (await s.execute(stmt)).scalars().all()
        now = self._now()
        grants = [grant_from_row(r, now=now) for r in rows]
        if active is not None:
            grants = [g for g in grants if g.active == active]
        return grants

    async def changes(self, *, subject: str | None = None, limit: int = 100) -> list[GrantChange]:
        await self._maybe_sweep()
        stmt = select(GrantChangeRow).order_by(desc(GrantChangeRow.id))
        async with self._sessions()() as s:
            rows = (await s.execute(stmt)).scalars().all()
        out: list[GrantChange] = []
        for r in rows:
            snap = Grant.model_validate(r.snapshot)
            if subject and snap.subject != subject.strip("/"):
                continue
            out.append(
                GrantChange(
                    id=r.id,
                    grant_id=r.grant_id,
                    change=r.change,  # type: ignore[arg-type]
                    actor=r.actor,
                    reason=r.reason,
                    at=r.at,
                    snapshot=snap,
                )
            )
            if len(out) >= max(1, min(limit, 1000)):
                break
        return out

    # ------------------------------------------------------------ audit

    async def _emit(
        self, change: str, grant: Grant, actor: Principal | None, version: int | None, *, reason: str | None = None
    ) -> None:
        sink = self._audit()
        if sink is None:
            return
        detail = {
            "change": change,
            "grant_id": grant.id,
            "subject_type": grant.subject_type,
            "subject": grant.subject,
            "resource_type": grant.resource_type.value,
            "resource": grant.resource,
            "effect": grant.effect,
            "expires_at": grant.expires_at.astimezone(UTC).isoformat() if grant.expires_at else None,
            "reason": reason or grant.reason,
            "grants_version": version,
        }
        try:
            await sink.record_event(
                EventType.grant_change,
                severity=Severity.medium if grant.effect == "allow" and change == "create" else Severity.info,
                detail=detail,
                principal=actor,
            )
        except Exception:
            log.exception("failed to record grant_change audit event")


def _actor_name(actor: Principal) -> str:
    return actor.username or actor.subject
