"""Live fan-out of audit events to SSE subscribers (`acl.audit.sink.EventStream`)."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator

from acl.contracts.admin import EventSummary
from acl.contracts.audit import AuditEvent


def event_summary(event: AuditEvent) -> EventSummary:
    d = event.decision
    return EventSummary(
        event_id=event.event_id,
        seq=event.seq,
        timestamp=event.timestamp,
        event_type=event.event_type.value,
        severity=event.severity,
        trace_id=event.trace_id,
        session_id=event.session_id,
        subject=event.principal.subject if event.principal else None,
        username=event.principal.username if event.principal else None,
        groups=list(event.principal.groups) if event.principal else [],
        agent_id=event.principal.agent_id if event.principal else None,
        point=event.point,
        model=event.model,
        tool=event.tool,
        action=d.action if d else None,
        rule_ids=list(d.rule_ids) if d else [],
        risk_score=d.risk_score if d else None,
        latency_ms=event.latency.total_ms if event.latency else None,
    )


class Subscription:
    """One subscriber's bounded queue. Slow consumers lose the oldest events (`dropped` counts them)."""

    def __init__(self, stream: EventStreamHub, maxsize: int) -> None:
        self._stream = stream
        self.queue: asyncio.Queue[EventSummary] = asyncio.Queue(maxsize=maxsize)
        self.dropped = 0

    def push(self, summary: EventSummary) -> None:
        if self.queue.full():
            try:
                self.queue.get_nowait()
                self.dropped += 1
            except asyncio.QueueEmpty:  # pragma: no cover - raced with the consumer
                pass
        self.queue.put_nowait(summary)

    async def get(self) -> EventSummary:
        return await self.queue.get()

    def __aiter__(self) -> AsyncIterator[EventSummary]:
        return self._iter()

    async def _iter(self) -> AsyncIterator[EventSummary]:
        while True:
            yield await self.queue.get()

    def close(self) -> None:
        self._stream._subs.discard(self)

    def __enter__(self) -> Subscription:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class EventStreamHub:
    def __init__(self, maxsize: int = 1000) -> None:
        self._subs: set[Subscription] = set()
        self._maxsize = maxsize

    @property
    def subscribers(self) -> int:
        return len(self._subs)

    def subscribe(self) -> Subscription:
        sub = Subscription(self, self._maxsize)
        self._subs.add(sub)
        return sub

    async def publish(self, summary: EventSummary) -> None:
        for sub in list(self._subs):
            sub.push(summary)
