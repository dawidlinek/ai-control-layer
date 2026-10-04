"""Break-glass reveal of raw content (concept §12): a reason, its own audit event, an incident, a short window.

* The gateway keeps only redacted / pseudonymised payloads by default. Raw content exists only when
  `reporting.audit_log.store_raw_payloads` is on AND something has registered a raw store at
  `app.state.raw_payloads` (an object with `async get(event_id) -> str | None`; encrypted, short retention).
  Nothing registers one yet, so today every request answers `available: false`. The access is audited anyway:
  the attempt is the signal.
* Break-glass reads data. It does not change enforcement: no org lock, locked control, grant or policy value is
  touched, and no decision depends on it.
* The audit event is written BEFORE any raw content is returned (fail closed: no audit, no reveal). It names who,
  whose event, why and for how long clients may show it (`VISIBLE_FOR_S`, enforced by the panel's watermark band
  and auto-hide), never the content. An `incident` (category `break_glass`) makes it visible in the panel's
  incident list and the posture view ("who looked at whose data").
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from acl.contracts.audit import AuditEvent, EventType
from acl.contracts.common import Severity
from acl.contracts.inspection import Principal
from acl.policy.models import Policy

log = logging.getLogger(__name__)

VISIBLE_FOR_S = 300  # "Visible for 5 minutes, this record only" (docs/ux/02-flows.md F9)
MIN_REASON_CHARS = 10
CATEGORY = "break_glass"


class RawStore(Protocol):
    async def get(self, event_id: str) -> str | None: ...


class BreakGlassUnavailable(RuntimeError):
    """The audit trail cannot take the record, so nothing may be revealed."""


def clean_reason(reason: str) -> str | None:
    """The reason with blanks normalised, or None if it is too short to explain anything."""
    text = " ".join(reason.split())
    return text if len(text) >= MIN_REASON_CHARS else None


def raw_retention(policy: Policy | None) -> timedelta | None:
    """How long raw payloads are kept (None: not at all)."""
    if policy is None:
        return None
    cfg = policy.reporting.audit_log
    if not cfg.store_raw_payloads or cfg.raw_retention_hours <= 0:
        return None
    return timedelta(hours=cfg.raw_retention_hours)


async def fetch_raw(store: RawStore | None, policy: Policy | None, event: AuditEvent, now: datetime) -> str | None:
    retention = raw_retention(policy)
    if store is None or retention is None:
        return None
    ts = event.timestamp if event.timestamp.tzinfo else event.timestamp.replace(tzinfo=UTC)
    if now - ts > retention:
        return None
    try:
        return await store.get(event.event_id)
    except Exception:
        log.exception("raw payload store failed for event %s", event.event_id)
        return None


async def record_access(
    sink: Any,
    *,
    actor: Principal,
    subject_ref: str,
    subject_name: str,
    event: AuditEvent,
    reason: str,
    available: bool,
) -> str:
    """Write the `breakglass` event, then raise the incident. Returns the break-glass audit event id."""
    if sink is None:
        raise BreakGlassUnavailable("audit sink is not running")
    detail = {
        "target_event_id": event.event_id,
        "subject": subject_ref,
        "subject_username": subject_name,
        "reason": reason,
        "available": available,
        "visible_for_s": VISIBLE_FOR_S,
    }
    try:
        audited = await sink.record_event(
            EventType.breakglass,
            severity=Severity.medium,
            detail=detail,
            principal=actor,
            trace_id=event.trace_id,
            session_id=event.session_id,
        )
    except Exception as exc:
        log.exception("break-glass audit record failed")
        raise BreakGlassUnavailable("audit record could not be written") from exc
    try:
        await sink.record_event(
            EventType.incident,
            severity=Severity.medium,
            detail={
                "category": CATEGORY,
                "title": f"Break-glass access by {actor.username or actor.subject} to data of {subject_name}",
                "related_event_ids": [event.event_id],
                **detail,
            },
            principal=actor,
            trace_id=event.trace_id,
            session_id=event.session_id,
        )
    except Exception:  # the access itself is already on the chain; a missing incident must not hide it
        log.exception("break-glass incident could not be opened")
    return str(audited.event_id)
