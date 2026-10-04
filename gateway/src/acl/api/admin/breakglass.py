"""Admin: break-glass reveal of raw event content. See `acl.breakglass.service` for the rules."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request

from acl.api.deps import ERROR_RESPONSES, Analyst
from acl.audit import queries as audit_queries
from acl.breakglass import service
from acl.contracts.admin import BreakGlassRequest, BreakGlassResponse

router = APIRouter(tags=["access"], responses=ERROR_RESPONSES)


@router.post("/users/{user_id}/breakglass", response_model=BreakGlassResponse, operation_id="breakGlass")
async def break_glass(request: Request, user_id: str, body: BreakGlassRequest, p: Analyst) -> BreakGlassResponse:
    """View raw content of one event. Requires a reason; audited as its own `breakglass` event."""
    reason = service.clean_reason(body.reason)
    if reason is None:
        raise HTTPException(422, detail=f"a reason of at least {service.MIN_REASON_CHARS} characters is required")
    identity = getattr(request.app.state, "identity", None)
    sessions = getattr(request.app.state, "db", None)
    if identity is None or sessions is None:
        raise HTTPException(503, detail="identity services or the event store are not running")
    row = await identity.users.get(user_id)
    if row is None:
        raise HTTPException(404, detail="user not found")
    event = await audit_queries.get_event(sessions, body.event_id)
    if event is None or event.principal is None or event.principal.subject != row.subject:
        raise HTTPException(404, detail="event not found for this user")

    engine = getattr(request.app.state, "engine", None)
    raw = await service.fetch_raw(
        getattr(request.app.state, "raw_payloads", None),
        engine.policy if engine is not None else None,
        event,
        datetime.now(UTC),
    )
    try:
        audit_event_id = await service.record_access(
            getattr(request.app.state, "audit", None),
            actor=p,
            subject_ref=row.subject,
            subject_name=row.username or row.subject,
            event=event,
            reason=reason,
            available=raw is not None,
        )
    except service.BreakGlassUnavailable as exc:
        raise HTTPException(503, detail=f"{exc}; nothing was revealed") from exc
    return BreakGlassResponse(
        event_id=event.event_id, audit_event_id=audit_event_id, raw_payload=raw, available=raw is not None
    )
