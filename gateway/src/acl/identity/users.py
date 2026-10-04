"""User store: just-in-time provisioning from authenticated principals, lookups for the admin API."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.contracts.admin import User
from acl.contracts.common import PrincipalKind
from acl.contracts.inspection import Principal
from acl.identity.db_models import UserRow, utcnow
from acl.identity.tokens import AGENT_CLIENT_PREFIX, SERVICE_ACCOUNT_PREFIX

SessionMaker = Callable[[], async_sessionmaker[AsyncSession]]


def user_from_row(row: UserRow) -> User:
    return User(
        id=row.id,
        subject=row.subject,
        username=row.username,
        email=row.email,
        display_name=row.display_name,
        kind=PrincipalKind(row.kind),
        groups=list(row.groups or []),
        roles=list(row.roles or []),
        first_seen=row.first_seen,
        last_seen=row.last_seen,
        disabled=row.disabled,
    )


def agent_id_for(row: UserRow) -> str | None:
    """Agent id of an agent principal's user row (kind `agent`, or a Keycloak service-account user
    `service-account-agent-<id>`), derived from the stored username; None for people."""
    if PrincipalKind(row.kind) != PrincipalKind.agent and not row.username.startswith(SERVICE_ACCOUNT_PREFIX):
        return None
    return row.username.removeprefix(SERVICE_ACCOUNT_PREFIX).removeprefix(AGENT_CLIENT_PREFIX) or None


def principal_from_row(row: UserRow) -> Principal:
    """The identity an admin sees when inspecting a user (no auth method: nobody is authenticating)."""
    agent_id = agent_id_for(row)
    return Principal(
        subject=row.subject,
        kind=PrincipalKind.agent if agent_id else PrincipalKind(row.kind),
        username=row.username,
        groups=list(row.groups or []),
        roles=list(row.roles or []),
        agent_id=agent_id,
    )


class UserStore:
    """JIT upsert is throttled per subject: a DB write only when something changed or `refresh_s` elapsed."""

    def __init__(self, sessions: SessionMaker, *, refresh_s: float = 30.0, clock: Callable[[], float] = time.monotonic):
        self._sessions = sessions
        self._refresh_s = refresh_s
        self._clock = clock
        self._seen: dict[str, tuple[tuple[Any, ...], float, bool]] = {}  # subject -> (fingerprint, at, disabled)

    async def provision(
        self, principal: Principal, *, email: str | None = None, display_name: str | None = None
    ) -> bool:
        """Upsert the user for an authenticated principal. Returns True if the account is disabled."""
        fp = (
            principal.username,
            tuple(principal.groups),
            tuple(principal.roles),
            principal.kind.value,
            email,
            display_name,
        )
        cached = self._seen.get(principal.subject)
        if cached is not None and cached[0] == fp and self._clock() - cached[1] < self._refresh_s:
            return cached[2]
        for attempt in (0, 1):
            try:
                disabled = await self._upsert(principal, email, display_name)
                break
            except IntegrityError:  # two first requests raced on the unique subject: retry as an update
                if attempt:
                    raise
        self._seen[principal.subject] = (fp, self._clock(), disabled)
        return disabled

    async def _upsert(self, principal: Principal, email: str | None, display_name: str | None) -> bool:
        now = utcnow()
        async with self._sessions()() as s, s.begin():
            row = (await s.execute(select(UserRow).where(UserRow.subject == principal.subject))).scalar_one_or_none()
            if row is None:
                row = UserRow(
                    id=str(uuid.uuid4()),
                    subject=principal.subject,
                    username=principal.username or principal.subject,
                    first_seen=now,
                )
                s.add(row)
            row.username = principal.username or principal.subject
            row.groups = list(principal.groups)
            row.roles = list(principal.roles)
            row.kind = principal.kind.value
            if email:
                row.email = email
            if display_name:
                row.display_name = display_name
            row.last_seen = now
            return row.disabled

    def forget(self, subject: str | None = None) -> None:
        if subject is None:
            self._seen.clear()
        else:
            self._seen.pop(subject, None)

    # ------------------------------------------------------------ admin lookups

    async def get(self, ref: str, session: AsyncSession | None = None) -> UserRow | None:
        """Resolve by internal id, then Keycloak subject, then username."""

        async def _q(s: AsyncSession) -> UserRow | None:
            for col in (UserRow.id, UserRow.subject, UserRow.username):
                row = (await s.execute(select(UserRow).where(col == ref).limit(1))).scalar_one_or_none()
                if row is not None:
                    return row
            return None

        if session is not None:
            return await _q(session)
        async with self._sessions()() as s:
            return await _q(s)

    async def list(self, *, q: str | None = None, group: str | None = None, limit: int = 100) -> list[UserRow]:
        return (await self.list_page(q=q, group=group, limit=limit))[0]

    async def list_page(
        self, *, q: str | None = None, group: str | None = None, limit: int = 100
    ) -> tuple[list[UserRow], int]:
        """(rows up to `limit`, total rows matching the filters)."""
        stmt = select(UserRow).order_by(UserRow.username)
        if q:
            like = f"%{q.lower()}%"
            stmt = stmt.where(
                or_(
                    func.lower(UserRow.username).like(like),
                    func.lower(func.coalesce(UserRow.email, "")).like(like),
                    func.lower(func.coalesce(UserRow.display_name, "")).like(like),
                )
            )
        async with self._sessions()() as s:
            rows = list((await s.execute(stmt)).scalars())
        if group:
            g = group.strip("/")
            rows = [r for r in rows if g in (r.groups or [])]
        return rows[: max(1, min(limit, 1000))], len(rows)

    async def all_group_counts(self) -> dict[str, int]:
        async with self._sessions()() as s:
            rows = list((await s.execute(select(UserRow.groups))).scalars())
        counts: dict[str, int] = {}
        for groups in rows:
            for g in groups or []:
                counts[g] = counts.get(g, 0) + 1
        return counts
