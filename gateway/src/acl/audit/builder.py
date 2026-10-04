"""Decision/Verdict → `AuditEvent` mapping. Raw values never enter an audit record.

Findings are reduced to `AuditFinding` (entity type, location, salted hash, rule id); verdict
`reason`s are controls' responsibility (they must not contain raw values, CLAUDE.md rule 2).
`seq`, `prev_hash` and `hash` are placeholders here: `AuditChain.append_locked` assigns them.
"""

from __future__ import annotations

import re
import uuid
from datetime import UTC, datetime
from typing import Any

from acl.contracts.audit import (
    GENESIS_HASH,
    AuditDecision,
    AuditEvent,
    AuditFinding,
    AuditPrincipal,
    AuditVerdict,
    EventType,
    LatencyBreakdown,
    Usage,
)
from acl.contracts.canonical import canonical_json, value_hash
from acl.contracts.common import Action, InspectionPoint, Severity, Versions
from acl.contracts.decision import Decision, Finding, RouteInfo, Verdict
from acl.contracts.inspection import ClientInfo, InspectionContext, Principal
from acl.engine.text import apply_replacements, iter_texts

MAX_REDACTED_CHARS = 16_000

_SEVERITY: dict[Action, Severity] = {
    Action.allow: Severity.info,
    Action.monitor: Severity.info,
    Action.redact: Severity.low,
    Action.pseudonymise: Severity.low,
    Action.sanitize: Severity.low,
    Action.route_local: Severity.low,
    Action.downgrade: Severity.medium,
    Action.require_approval: Severity.medium,
    Action.block: Severity.high,
}


def audit_principal(p: Principal) -> AuditPrincipal:
    return AuditPrincipal(
        subject=p.subject,
        kind=p.kind,
        username=p.username,
        groups=list(p.groups),
        agent_id=p.agent_id,
        client_id=p.client_id,
        auth_method=p.auth_method,
        api_key_id=p.api_key_id,
        delegation_chain=list(p.delegation_chain),
    )


def audit_finding(f: Finding) -> AuditFinding:
    return AuditFinding(
        entity_type=f.entity_type, field=f.field, start=f.start, end=f.end, value_hash=f.value_hash, rule_id=f.rule_id
    )


def audit_verdict(v: Verdict) -> AuditVerdict:
    return AuditVerdict(
        control_id=v.control_id,
        control_type=v.control_type,
        phase=v.phase,
        action=v.action,
        final=v.final,
        score=v.score,
        status=v.status,
        latency_ms=v.latency_ms,
        rule_ids=list(v.rule_ids),
        findings=[audit_finding(f) for f in v.findings],
        reason=v.reason,
    )


def severity_for(decision: Decision) -> Severity:
    sev = _SEVERITY[decision.action]
    if decision.action == Action.monitor and decision.would_action is not None:
        sev = max(sev, Severity.low, key=list(Severity).index)
    if decision.action == Action.block and decision.final:
        sev = Severity.critical if decision.risk_score >= 0.9 else Severity.high
    return sev


def payload_texts(ctx: InspectionContext) -> str:
    return "\n".join(t for _, t in iter_texts(ctx.payload))


def redacted_pairs(ctx: InspectionContext, verdicts: list[Verdict]) -> list[tuple[str, str]]:
    """(field path, text) pairs of the inspected payload with EVERY detected span masked (enforced or not).

    Spans without a control-provided replacement get `[REDACTED:<ENTITY>]`. Offsets refer to the
    payload as inspected (the normalised payload when a normaliser published one).
    """
    payload = ctx.attributes.get("payload", ctx.payload)
    if not hasattr(payload, "kind"):
        payload = ctx.payload
    spans = sorted(
        (
            f.model_copy(update={"replacement": f.replacement or f"[REDACTED:{f.entity_type}]"})
            for v in verdicts
            for f in v.findings
            if f.start is not None and f.end is not None and f.field
        ),
        key=lambda f: (f.field, f.start, -(f.end or 0)),
    )
    masks: list[Finding] = []
    for f in spans:  # union overlapping spans so no fragment of a skipped finding survives
        last = masks[-1] if masks else None
        if last is not None and last.field == f.field and (f.start or 0) < (last.end or 0):
            masks[-1] = last.model_copy(update={"end": max(last.end or 0, f.end or 0)})
        else:
            masks.append(f)
    masked, _ = apply_replacements(payload, masks)
    return iter_texts(masked)


def _capped(text: str) -> str:
    return text if len(text) <= MAX_REDACTED_CHARS else text[:MAX_REDACTED_CHARS] + "…[truncated]"


def redacted_text(ctx: InspectionContext, verdicts: list[Verdict]) -> str:
    """The inspected text with EVERY detected span masked (enforced or not), safe to store."""
    return _capped("\n".join(t for _, t in redacted_pairs(ctx, verdicts)))


_MESSAGE_TEXT = re.compile(r"^messages\[(\d+)\]\.content(?:\[\d+\]\.text)?$")


def last_message_text(pairs: list[tuple[str, str]]) -> str | None:
    """Masked text of the LAST chat message only (the new turn), from `redacted_pairs` of a chat payload."""
    last = -1
    texts: list[str] = []
    for field, text in pairs:
        m = _MESSAGE_TEXT.match(field)
        if m is None:
            continue
        idx = int(m.group(1))
        if idx > last:
            last, texts = idx, []
        if idx == last:
            texts.append(text)
    return _capped("\n".join(texts)) if last >= 0 else None


def build_event(
    ctx: InspectionContext,
    decision: Decision,
    *,
    salt: str,
    route: RouteInfo | None = None,
    usage: Usage | None = None,
    latency: LatencyBreakdown | None = None,
    redacted_payload: str | None = None,
    response_hash: str | None = None,
    now: datetime | None = None,
) -> AuditEvent:
    route = route or decision.route
    payload = ctx.payload
    tool = server = args_hash = None
    if payload.kind == "tool_call":
        tool, server = payload.tool, payload.server
        args_hash = value_hash(canonical_json(payload.arguments), salt, 64)
    elif payload.kind == "tool_result":
        tool, server = payload.tool, payload.server
    elif payload.kind == "mcp":
        server = payload.server
    texts = payload_texts(ctx)
    detail: dict[str, Any] = {}
    if redacted_payload is not None and payload.kind == "chat" and decision.point == InspectionPoint.ingress:
        # Only when redacted payload storage is on for this event: the masked text of the new user turn, for the
        # session transcript (the full `redacted_payload` repeats the whole history on every request).
        turn = last_message_text(redacted_pairs(ctx, decision.verdicts))
        if turn is not None:
            detail["turn_text"] = turn
    return AuditEvent(
        event_id=decision.decision_id or str(uuid.uuid4()),
        seq=0,
        timestamp=now or datetime.now(UTC),
        event_type=EventType.decision,
        severity=severity_for(decision),
        trace_id=ctx.trace_id,
        session_id=ctx.session_id,
        request_id=ctx.request_id,
        principal=audit_principal(ctx.principal),
        client=ctx.client,
        point=decision.point,
        tool=tool,
        server=server,
        model_requested=ctx.model_requested,
        model=route.model if route else None,
        connector=route.connector if route else None,
        args_hash=args_hash,
        payload_hash=value_hash(texts, salt, 64) if texts else None,
        response_hash=response_hash,
        decision=AuditDecision(
            action=decision.action,
            applied=list(decision.applied),
            would_action=decision.would_action,
            final=decision.final,
            decided_by=decision.decided_by,
            decided_phase=decision.decided_phase,
            rule_ids=list(decision.rule_ids),
            risk_score=decision.risk_score,
            reason=decision.reason,
        ),
        verdicts=[audit_verdict(v) for v in decision.verdicts],
        risk_factors=list(decision.risk_factors),
        route=route,
        approval=decision.approval,
        labels_after=decision.labels_after,
        versions=decision.versions,
        taxonomy=decision.taxonomy,
        usage=usage,
        latency=latency,
        seed=ctx.seed,
        redacted_payload=redacted_payload,
        detail=detail,
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )


def build_system_event(
    event_type: EventType,
    *,
    versions: Versions,
    severity: Severity = Severity.info,
    detail: dict[str, Any] | None = None,
    principal: Principal | None = None,
    client: ClientInfo | None = None,
    trace_id: str | None = None,
    session_id: str | None = None,
    point: InspectionPoint | None = None,
    now: datetime | None = None,
) -> AuditEvent:
    return AuditEvent(
        event_id=str(uuid.uuid4()),
        seq=0,
        timestamp=now or datetime.now(UTC),
        event_type=event_type,
        severity=severity,
        trace_id=trace_id,
        session_id=session_id,
        principal=audit_principal(principal) if principal else None,
        client=client,
        point=point,
        versions=versions,
        detail=detail or {},
        prev_hash=GENESIS_HASH,
        hash=GENESIS_HASH,
    )
