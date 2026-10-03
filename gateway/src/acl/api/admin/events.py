"""Admin: events, live stream, incidents, audit chain/export, metrics. Owner: Phase 1A."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Literal

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sse_starlette.sse import EventSourceResponse

from acl.api.deps import ERROR_RESPONSES, Analyst, Viewer, not_implemented
from acl.audit import queries
from acl.audit.chain import verify_chain as verify_chain_file
from acl.audit.db_models import IncidentRow
from acl.audit.export import iter_export
from acl.audit.incidents import incident_from_row
from acl.contracts.admin import (
    ChainVerifyResult,
    EventSummary,
    GuardQualitySummary,
    Incident,
    IncidentNote,
    IncidentPatch,
    OverviewSummary,
    PerformanceSummary,
)
from acl.contracts.audit import AuditEvent, EventType
from acl.contracts.common import Action, InspectionPoint, Severity

router = APIRouter(tags=["events"], responses=ERROR_RESPONSES)


def _sessions(request: Request):  # type: ignore[no-untyped-def]
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        raise HTTPException(503, detail="database not ready")
    return sessions


def _utc(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=UTC) if dt.tzinfo is None else dt.astimezone(UTC)


@router.get("/events", response_model=list[EventSummary], operation_id="listEvents")
async def list_events(
    request: Request,
    p: Viewer,
    since: datetime | None = None,
    until: datetime | None = None,
    subject: str | None = None,
    group: str | None = None,
    agent: str | None = None,
    control: str | None = None,
    rule_id: str | None = None,
    action: Action | None = None,
    point: InspectionPoint | None = None,
    event_type: str | None = None,
    taxonomy: str | None = None,
    before_seq: int | None = None,
    limit: int = 100,
) -> list[EventSummary]:
    return await queries.list_events(
        _sessions(request),
        since=_utc(since),
        until=_utc(until),
        subject=subject,
        group=group,
        agent=agent,
        control=control,
        rule_id=rule_id,
        action=action.value if action else None,
        point=point.value if point else None,
        event_type=event_type,
        taxonomy=taxonomy,
        before_seq=before_seq,
        limit=limit,
    )


@router.get(
    "/events/stream",
    operation_id="streamEvents",
    responses={
        200: {
            "content": {"text/event-stream": {}},
            "description": "Server-sent events; each `data:` line is an EventSummary JSON object.",
        }
    },
)
async def stream_events(request: Request, p: Viewer, subject: str | None = None, action: Action | None = None) -> None:
    hub = request.app.state.event_stream

    async def events():  # type: ignore[no-untyped-def]
        with hub.subscribe() as sub:
            async for s in sub:
                if subject and subject not in (s.subject, s.username):
                    continue
                if action and s.action != action:
                    continue
                yield {"event": "event", "id": str(s.seq), "data": s.model_dump_json()}

    return EventSourceResponse(events(), ping=15)  # type: ignore[return-value]


@router.get("/events/{event_id}", response_model=AuditEvent, operation_id="getEvent")
async def get_event(request: Request, event_id: str, p: Viewer) -> AuditEvent:
    """Full decision trace (the audit record) for one event."""
    event = await queries.get_event(_sessions(request), event_id)
    if event is None:
        raise HTTPException(404, detail="event not found")
    return event


@router.get("/incidents", response_model=list[Incident], operation_id="listIncidents")
async def list_incidents(request: Request, p: Viewer, status: str | None = None, limit: int = 100) -> list[Incident]:
    stmt = select(IncidentRow).order_by(IncidentRow.updated_at.desc()).limit(max(1, min(limit, 1000)))
    if status:
        stmt = stmt.where(IncidentRow.status == status)
    async with _sessions(request)() as s:
        return [incident_from_row(r) for r in (await s.execute(stmt)).scalars()]


@router.get("/incidents/{incident_id}", response_model=Incident, operation_id="getIncident")
async def get_incident(request: Request, incident_id: str, p: Viewer) -> Incident:
    async with _sessions(request)() as s:
        row = await s.get(IncidentRow, incident_id)
    if row is None:
        raise HTTPException(404, detail="incident not found")
    return incident_from_row(row)


@router.patch("/incidents/{incident_id}", response_model=Incident, operation_id="updateIncident")
async def update_incident(request: Request, incident_id: str, body: IncidentPatch, p: Analyst) -> Incident:
    now = datetime.now(UTC)
    change: dict[str, str | None] = {}
    async with _sessions(request)() as s:
        row = await s.get(IncidentRow, incident_id)
        if row is None:
            raise HTTPException(404, detail="incident not found")
        if body.status is not None and body.status != row.status:
            change["status"] = f"{row.status} -> {body.status}"
            row.status = body.status
        if body.assignee is not None and body.assignee != row.assignee:
            change["assignee"] = body.assignee
            row.assignee = body.assignee
        if body.note:
            note = IncidentNote(author=p.username or p.subject, at=now, text=body.note)
            row.notes = [*(row.notes or []), note.model_dump(mode="json")]
            change["note"] = "added"
        row.updated_at = now
        await s.commit()
        result = incident_from_row(row)
    audit = getattr(request.app.state, "audit", None)
    if audit is not None and change:
        await audit.record_event(
            EventType.incident,
            severity=Severity.info,
            detail={"incident_id": incident_id, "change": change},  # no "category": not a new incident
            principal=p,
        )
    return result


@router.get("/audit/verify", response_model=ChainVerifyResult, operation_id="verifyAuditChain")
async def verify_chain(request: Request, p: Analyst) -> ChainVerifyResult:
    # Re-computes the hash chain and cross-checks the head against the DB index to expose tail truncation.
    # (A comment, not a docstring: docstrings would change the generated OpenAPI contract.)
    audit = request.app.state.audit
    path = audit.chain.path
    async with audit.chain.lock:  # snapshot a consistent (file size, index head) pair
        size = path.stat().st_size if path.exists() else 0
        index_head = await queries.head_of_index(audit.sessions) if audit.sessions else None
    result = await asyncio.to_thread(verify_chain_file, path, upto_bytes=size)
    if result.ok and index_head is not None:
        seq, digest = index_head
        if result.head_seq is None or result.head_seq < seq:
            return result.model_copy(
                update={
                    "ok": False,
                    "first_bad_seq": (result.head_seq + 1) if result.head_seq is not None else 0,
                    "message": f"audit file ends at seq {result.head_seq}, the index holds seq {seq}: tail truncated",
                }
            )
        if result.head_seq == seq and result.head_hash != digest:
            return result.model_copy(
                update={"ok": False, "first_bad_seq": seq, "message": "head record differs from the index copy"}
            )
    return result


@router.get(
    "/audit/export",
    operation_id="exportAudit",
    responses={
        200: {
            "content": {"application/x-ndjson": {}, "text/csv": {}},
            "description": "JSONL (raw records), OCSF JSONL, or CSV.",
        }
    },
)
async def export_audit(
    request: Request,
    p: Analyst,
    format: Literal["jsonl", "ocsf", "csv"] = "jsonl",
    since: datetime | None = None,
    until: datetime | None = None,
) -> None:
    path = request.app.state.audit.chain.path
    media = "text/csv" if format == "csv" else "application/x-ndjson"
    ext = "csv" if format == "csv" else "jsonl"
    return StreamingResponse(  # type: ignore[return-value]
        iter_export(path, format, _utc(since), _utc(until)),
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="audit-{format}.{ext}"'},
    )


@router.get("/metrics/overview", response_model=OverviewSummary, operation_id="getOverview")
async def overview(request: Request, p: Viewer, window: str = "24h") -> OverviewSummary:
    engine = request.app.state.engine
    ext_price = None
    if engine is not None:
        ext = engine.policy.model_by_id().get(engine.policy.routing.targets.ext_small)
        if ext is not None:
            ext_price = (ext.pricing.in_per_1k, ext.pricing.out_per_1k)
    return await queries.overview(_sessions(request), window, external_price_per_1k=ext_price)


@router.get("/metrics/guard-quality", response_model=GuardQualitySummary, operation_id="getGuardQuality")
async def guard_quality(p: Viewer) -> GuardQualitySummary:
    not_implemented("guard quality")  # computed from the self-test suite results (Phase 4C)


@router.get("/metrics/performance", response_model=PerformanceSummary, operation_id="getPerformance")
async def performance(request: Request, p: Viewer, window: str = "1h") -> PerformanceSummary:
    return await queries.performance(_sessions(request), window)
