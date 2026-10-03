"""Incidents: created from audit events, grouped by (category, subject) within 10 minutes."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.audit.db_models import IncidentRow
from acl.contracts.admin import Incident, IncidentNote
from acl.contracts.common import Severity

INCIDENT_WINDOW = timedelta(minutes=10)
_OPEN = ("open", "triaged")
_SEV_ORDER = list(Severity)


def as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


def incident_from_row(row: IncidentRow) -> Incident:
    return Incident(
        id=row.id,
        title=row.title,
        category=row.category,
        severity=Severity(row.severity),
        status=row.status,  # type: ignore[arg-type]
        created_at=as_utc(row.created_at),
        updated_at=as_utc(row.updated_at),
        assignee=row.assignee,
        subject=row.subject,
        event_ids=list(row.event_ids or []),
        rule_ids=list(row.rule_ids or []),
        notes=[IncidentNote.model_validate(n) for n in (row.notes or [])],
        detail=dict(row.detail or {}),
    )


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.index(Severity(a)) >= _SEV_ORDER.index(Severity(b)) else b


async def record_incident(
    sessions: async_sessionmaker[AsyncSession],
    *,
    category: str,
    title: str,
    severity: Severity,
    subject: str | None,
    event_ids: list[str],
    rule_ids: list[str],
    detail: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> Incident:
    """Append to the open incident of the same category+subject updated within 10 minutes, else open one."""
    now = now or datetime.now(UTC)
    async with sessions() as s:
        stmt = (
            select(IncidentRow)
            .where(
                IncidentRow.category == category,
                IncidentRow.status.in_(_OPEN),
                IncidentRow.updated_at >= now - INCIDENT_WINDOW,
                IncidentRow.subject.is_(None) if subject is None else IncidentRow.subject == subject,
            )
            .order_by(IncidentRow.updated_at.desc())
            .limit(1)
        )
        row = (await s.execute(stmt)).scalar_one_or_none()
        if row is None:
            row = IncidentRow(
                id=f"inc-{uuid.uuid4().hex[:12]}",
                title=title[:300],
                category=category,
                severity=severity.value,
                status="open",
                created_at=now,
                updated_at=now,
                subject=subject,
                event_ids=list(dict.fromkeys(event_ids)),
                rule_ids=list(dict.fromkeys(rule_ids)),
                notes=[],
                detail=detail or {},
            )
            s.add(row)
        else:
            row.event_ids = list(dict.fromkeys([*(row.event_ids or []), *event_ids]))
            row.rule_ids = list(dict.fromkeys([*(row.rule_ids or []), *rule_ids]))
            row.severity = _max_sev(row.severity, severity.value)
            row.updated_at = now
            row.detail = {**(row.detail or {}), **(detail or {}), "occurrences": len(row.event_ids)}
        await s.commit()
        return incident_from_row(row)
