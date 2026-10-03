"""Admin: events, live stream, incidents, audit chain/export, metrics. Owner: Phase 1A."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Analyst, Viewer, not_implemented
from acl.contracts.admin import (
    ChainVerifyResult,
    EventSummary,
    GuardQualitySummary,
    Incident,
    IncidentPatch,
    OverviewSummary,
    PerformanceSummary,
)
from acl.contracts.audit import AuditEvent
from acl.contracts.common import Action, InspectionPoint

router = APIRouter(tags=["events"], responses=ERROR_RESPONSES)


@router.get("/events", response_model=list[EventSummary], operation_id="listEvents")
async def list_events(
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
    not_implemented("events")


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
async def stream_events(p: Viewer, subject: str | None = None, action: Action | None = None) -> None:
    not_implemented("event stream")


@router.get("/events/{event_id}", response_model=AuditEvent, operation_id="getEvent")
async def get_event(event_id: str, p: Viewer) -> AuditEvent:
    """Full decision trace (the audit record) for one event."""
    not_implemented("events")


@router.get("/incidents", response_model=list[Incident], operation_id="listIncidents")
async def list_incidents(p: Viewer, status: str | None = None, limit: int = 100) -> list[Incident]:
    not_implemented("incidents")


@router.get("/incidents/{incident_id}", response_model=Incident, operation_id="getIncident")
async def get_incident(incident_id: str, p: Viewer) -> Incident:
    not_implemented("incidents")


@router.patch("/incidents/{incident_id}", response_model=Incident, operation_id="updateIncident")
async def update_incident(incident_id: str, body: IncidentPatch, p: Analyst) -> Incident:
    not_implemented("incidents")


@router.get("/audit/verify", response_model=ChainVerifyResult, operation_id="verifyAuditChain")
async def verify_chain(p: Analyst) -> ChainVerifyResult:
    not_implemented("audit verify")


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
    p: Analyst,
    format: Literal["jsonl", "ocsf", "csv"] = "jsonl",
    since: datetime | None = None,
    until: datetime | None = None,
) -> None:
    not_implemented("audit export")


@router.get("/metrics/overview", response_model=OverviewSummary, operation_id="getOverview")
async def overview(p: Viewer, window: str = "24h") -> OverviewSummary:
    not_implemented("overview")


@router.get("/metrics/guard-quality", response_model=GuardQualitySummary, operation_id="getGuardQuality")
async def guard_quality(p: Viewer) -> GuardQualitySummary:
    not_implemented("guard quality")


@router.get("/metrics/performance", response_model=PerformanceSummary, operation_id="getPerformance")
async def performance(p: Viewer, window: str = "1h") -> PerformanceSummary:
    not_implemented("performance")
