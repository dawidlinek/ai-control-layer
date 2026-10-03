"""`AuditService`: the `acl.audit.sink.AuditSink` implementation at `app.state.audit`.

Every record goes through one path: build → chain (file, single writer) → DB index → SSE fan-out →
metrics. The JSONL file is the source of truth: a failed file write propagates (callers fail closed),
a failed index write is logged and the request continues.

Incidents: `record_event(EventType.incident, detail={"category": ..., "title": ..., "rule_ids": [...],
"related_event_ids": [...]})` also opens/updates an incident (grouped by category + subject within 10
minutes). Incident events without a `category` (e.g. a status change) are plain audit records.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.audit.builder import build_event, build_system_event
from acl.audit.chain import AuditChain
from acl.audit.db_models import AuditEventRow
from acl.audit.incidents import record_incident
from acl.audit.metrics import GatewayMetrics
from acl.audit.stream import EventStreamHub, event_summary
from acl.contracts.audit import AuditEvent, EventType, LatencyBreakdown, Usage
from acl.contracts.common import Action, Severity, Versions
from acl.contracts.decision import Decision, RouteInfo
from acl.contracts.inspection import InspectionContext, Principal

log = logging.getLogger(__name__)


def _bar(items: list[str]) -> str:
    return "|" + "|".join(dict.fromkeys(items)) + "|" if items else ""


def row_from_event(e: AuditEvent) -> AuditEventRow:
    d = e.decision
    rules = list(d.rule_ids) if d else []
    tags: list[str] = []
    for field in type(e.taxonomy).model_fields:
        tags.extend(getattr(e.taxonomy, field))
    controls = [v.control_id for v in e.verdicts if v.action not in (Action.allow, Action.monitor)]
    if d and d.decided_by:
        controls.insert(0, d.decided_by)
    u = e.usage
    return AuditEventRow(
        event_id=e.event_id,
        seq=e.seq,
        timestamp=e.timestamp,
        event_type=e.event_type.value,
        severity=e.severity.value,
        trace_id=e.trace_id,
        session_id=e.session_id,
        subject=e.principal.subject if e.principal else None,
        username=e.principal.username if e.principal else None,
        groups_text=_bar(e.principal.groups) if e.principal else "",
        agent_id=e.principal.agent_id if e.principal else None,
        point=e.point.value if e.point else None,
        model=e.model,
        connector=e.connector,
        tier=e.route.tier.value if e.route else None,
        degraded=bool(e.route and e.route.degraded),
        tool=e.tool,
        action=d.action.value if d else None,
        would_action=d.would_action.value if d and d.would_action else None,
        rules_text=_bar(rules),
        controls_text=_bar(controls),
        tags_text=_bar(tags),
        risk_score=d.risk_score if d else None,
        latency_ms=e.latency.total_ms if e.latency else None,
        input_tokens=u.input_tokens if u else 0,
        output_tokens=u.output_tokens if u else 0,
        usd=u.usd if u else 0.0,
        gpu_seconds=u.gpu_seconds if u else 0.0,
        data=e.model_dump(mode="json"),
    )


class AuditService:
    def __init__(
        self,
        *,
        chain: AuditChain,
        sessions: async_sessionmaker[AsyncSession] | None,
        salt: str,
        stream: EventStreamHub,
        metrics: GatewayMetrics,
        versions: Callable[[], Versions],
    ) -> None:
        self.chain = chain
        self.sessions = sessions
        self.salt = salt
        self.stream = stream
        self.metrics = metrics
        self._versions = versions
        self._incident_lock = asyncio.Lock()

    # ------------------------------------------------------------ AuditSink

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
        event = build_event(
            ctx,
            decision,
            salt=self.salt,
            route=route,
            usage=usage,
            latency=latency,
            redacted_payload=redacted_payload,
            response_hash=response_hash,
        )
        final = await self._commit(event)
        if decision.action == Action.block and decision.would_action is None:
            await self._block_incident(ctx, decision, final)
        return final

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
        event = build_system_event(
            event_type,
            versions=self._versions(),
            severity=severity,
            detail=detail,
            principal=principal,
            trace_id=trace_id,
            session_id=session_id,
        )
        final = await self._commit(event)
        category = (detail or {}).get("category")
        if event_type == EventType.incident and category:
            await self._open_incident(final, str(category), principal, detail or {})
        return final

    # ------------------------------------------------------------ internals

    async def _commit(self, event: AuditEvent) -> AuditEvent:
        async with self.chain.lock:
            final = self.chain.append_locked(event)  # file write failure propagates → fail closed
            await self._index(final)
            await self.stream.publish(event_summary(final))
        try:
            self.metrics.observe_event(final)
        except Exception:  # metrics must never break auditing
            log.exception("metrics update failed")
        return final

    async def _index(self, event: AuditEvent) -> None:
        if self.sessions is None:
            return
        try:
            async with self.sessions() as s:
                s.add(row_from_event(event))
                await s.commit()
        except Exception:
            log.exception("audit index write failed for seq %s (the JSONL file has the record)", event.seq)

    async def _open_incident(
        self, event: AuditEvent, category: str, principal: Principal | None, detail: dict[str, Any]
    ) -> None:
        if self.sessions is None:
            return
        subject = (principal.username or principal.subject) if principal else None
        related = [str(i) for i in detail.get("related_event_ids", [])]
        try:
            async with self._incident_lock:
                await record_incident(
                    self.sessions,
                    category=category,
                    title=str(detail.get("title") or category.replace("_", " ")),
                    severity=event.severity,
                    subject=subject,
                    event_ids=[event.event_id, *related],
                    rule_ids=[str(r) for r in detail.get("rule_ids", [])],
                    detail={k: v for k, v in detail.items() if k not in ("title", "related_event_ids", "rule_ids")},
                    now=event.timestamp,
                )
        except Exception:
            log.exception("incident creation failed")

    async def _block_incident(self, ctx: InspectionContext, decision: Decision, event: AuditEvent) -> None:
        """Enforced blocks open a (grouped) incident, unless the caller already opened a specific one."""
        if self.sessions is None:
            return
        forbidden = "SEC-MODEL-01" in decision.rule_ids or any(
            v.control_type == "model_access" and v.action == Action.block for v in decision.verdicts
        )
        if forbidden:
            category = "forbidden_model"
        else:
            category = "blocked_response" if decision.point.value == "egress" else "blocked_request"
        subject = ctx.principal.username or ctx.principal.subject
        title = f"{category.replace('_', ' ').capitalize()} for {subject}: {decision.reason or 'policy block'}"
        try:
            async with self._incident_lock:
                await record_incident(
                    self.sessions,
                    category=category,
                    title=title[:300],
                    severity=event.severity,
                    subject=subject,
                    event_ids=[event.event_id],
                    rule_ids=list(decision.rule_ids),
                    detail={"point": decision.point.value, "decided_by": decision.decided_by},
                    now=event.timestamp,
                )
        except Exception:
            log.exception("incident creation failed")
