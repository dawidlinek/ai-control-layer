"""Audit sink interface (orchestrator-owned seam). Phase 1A implements the hash-chained sink.

Every module that needs to record something uses `app.state.audit` (an `AuditSink`). Tests may use
`RecordingSink`, which only records calls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from acl.contracts.admin import EventSummary
from acl.contracts.audit import AuditEvent, EventType, LatencyBreakdown, Usage
from acl.contracts.common import Severity
from acl.contracts.decision import Decision, RouteInfo
from acl.contracts.inspection import InspectionContext, Principal


class AuditSink(Protocol):
    async def record_decision(
        self,
        ctx: InspectionContext,
        decision: Decision,
        *,
        route: RouteInfo | None = None,
        usage: Usage | None = None,
        latency: LatencyBreakdown | None = None,
        redacted_payload: str | None = None,
        response_hash: str | None = None,
    ) -> AuditEvent:
        """Build, chain, persist and publish (SSE) the audit record for one decision."""
        ...

    async def record_event(
        self,
        event_type: EventType,
        *,
        severity: Severity = Severity.info,
        detail: dict[str, Any] | None = None,
        principal: Principal | None = None,
        trace_id: str | None = None,
        session_id: str | None = None,
    ) -> AuditEvent:
        """Non-decision events: policy_change, grant_change, feed_update, incident, system_alert, ..."""
        ...


@dataclass
class RecordingSink:
    """Test double: records calls, returns nothing meaningful. Not hash-chained."""

    decisions: list[tuple[InspectionContext, Decision, dict[str, Any]]] = field(default_factory=list)
    events: list[tuple[EventType, dict[str, Any]]] = field(default_factory=list)

    async def record_decision(self, ctx: InspectionContext, decision: Decision, **kw: Any) -> Any:
        self.decisions.append((ctx, decision, kw))

    async def record_event(self, event_type: EventType, **kw: Any) -> Any:
        self.events.append((event_type, kw))


class EventStream(Protocol):
    """Live fan-out for SSE (`/admin/v1/events/stream`)."""

    def subscribe(self) -> Any: ...

    async def publish(self, summary: EventSummary) -> None: ...
