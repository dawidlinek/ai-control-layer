"""Live fan-out of audit events to SSE subscribers (`acl.audit.sink.EventStream`)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import AsyncIterator
from datetime import datetime
from typing import TYPE_CHECKING, Literal

from acl.audit import narrate
from acl.contracts.admin import ClientRef, EventSummary, SessionLabelInfo
from acl.contracts.audit import AuditEvent
from acl.contracts.common import DATA_CLASS_ORDER, Action, DataClass

if TYPE_CHECKING:
    from acl.policy.models import Policy

log = logging.getLogger(__name__)


def session_threshold(policy: Policy | None) -> DataClass | None:
    """SEC-SESSION-01's `threshold` in the given policy: confidential when no policy is at hand, None when the
    control is absent or disabled (no session is then pinned to local models)."""
    if policy is None:
        return DataClass.confidential
    for c in policy.controls:
        if c.type == "session_label" and c.enabled:
            try:
                return DataClass(str(c.params.get("threshold", DataClass.confidential.value)))
            except ValueError:
                return DataClass.confidential
    return None


def event_data_class(event: AuditEvent) -> DataClass | None:
    """Highest data class the event carries: session labels after it, or the class the router saw."""
    found: list[DataClass] = []
    if event.labels_after is not None:
        found.append(event.labels_after.confidentiality)
    if event.route is not None:
        with contextlib.suppress(ValueError):
            found.append(DataClass(str(event.route.factors.get("data_class"))))
    return max(found, key=lambda c: DATA_CLASS_ORDER[c]) if found else None


def label_info(
    data_class: DataClass, trust: str, since: datetime | None, threshold: DataClass | None
) -> SessionLabelInfo:
    return SessionLabelInfo(
        data_class=data_class,
        trust="untrusted" if trust == "untrusted" else "trusted",
        since=since,
        local_only=threshold is not None and DATA_CLASS_ORDER[data_class] >= DATA_CLASS_ORDER[threshold],
    )


def session_label_of(event: AuditEvent, threshold: DataClass | None) -> SessionLabelInfo | None:
    if event.labels_after is None:
        return None
    labels = event.labels_after
    level = event_data_class(event) or labels.confidentiality
    since = labels.since if level == labels.confidentiality else None
    return label_info(level, labels.integrity.value, since, threshold)


def _applied(event: AuditEvent) -> list[Action]:
    d = event.decision
    if d is None:
        return []
    out = [a for a in d.applied if a != Action.allow]
    if d.action != Action.allow and d.action not in out:
        out.insert(0, d.action)
    return out


def event_summary(
    event: AuditEvent,
    *,
    policy: Policy | None = None,
    threshold: DataClass | Literal["policy"] | None = "policy",
    client_ref: ClientRef | None = None,
) -> EventSummary:
    """The panel's list row for one audit record, with plain-language text and session context.

    `threshold` defaults to SEC-SESSION-01's setting in `policy` (confidential without a policy); pass a value
    (or None for "no local-only pinning") to avoid recomputing it per row.
    """
    d = event.decision
    th = session_threshold(policy) if threshold == "policy" else threshold
    try:  # narration must never break auditing: this runs inside the audit commit
        text, changed = narrate.summary(event, policy), narrate.changed_steps(event)
    except Exception:
        log.exception("narration failed for seq %s", event.seq)
        text, changed = "", {}
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
        applied=_applied(event),
        client_app=event.client.app if event.client else None,
        data_class=event_data_class(event),
        tier=event.route.tier if event.route else None,
        degraded=bool(event.route and event.route.degraded),
        tokens_in=event.usage.input_tokens if event.usage else 0,
        tokens_out=event.usage.output_tokens if event.usage else 0,
        summary=text,
        changed_steps=changed,
        session_label=session_label_of(event, th),
        client_ref=client_ref,
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
