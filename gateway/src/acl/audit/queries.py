"""Read side of the audit index: event lists, incidents, overview and performance summaries."""

from __future__ import annotations

import re
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.audit.db_models import AuditEventRow, IncidentRow
from acl.audit.incidents import as_utc
from acl.contracts.admin import EventSummary, OverviewSummary, PerformanceSummary, StageLatency
from acl.contracts.audit import AuditEvent
from acl.contracts.common import Severity

_WINDOW = re.compile(r"^(\d+)\s*([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_NO_ACTION = ("allow", "monitor")


def parse_window(window: str, default_s: int = 86400) -> timedelta:
    m = _WINDOW.match(window.strip().lower())
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2)]) if m else timedelta(seconds=default_s)


def utc(dt: datetime) -> datetime:
    return as_utc(dt)


def _split(text: str) -> list[str]:
    return [p for p in text.split("|") if p]


def summary_from_row(r: AuditEventRow) -> EventSummary:
    return EventSummary(
        event_id=r.event_id,
        seq=r.seq,
        timestamp=utc(r.timestamp),
        event_type=r.event_type,
        severity=Severity(r.severity),
        trace_id=r.trace_id,
        session_id=r.session_id,
        subject=r.subject,
        username=r.username,
        groups=_split(r.groups_text),
        agent_id=r.agent_id,
        point=r.point,  # type: ignore[arg-type]
        model=r.model,
        tool=r.tool,
        action=r.action,  # type: ignore[arg-type]
        rule_ids=_split(r.rules_text),
        risk_score=r.risk_score,
        latency_ms=r.latency_ms,
    )


async def list_events(
    sessions: async_sessionmaker[AsyncSession],
    *,
    since: datetime | None = None,
    until: datetime | None = None,
    subject: str | None = None,
    group: str | None = None,
    agent: str | None = None,
    control: str | None = None,
    rule_id: str | None = None,
    action: str | None = None,
    point: str | None = None,
    event_type: str | None = None,
    taxonomy: str | None = None,
    before_seq: int | None = None,
    limit: int = 100,
) -> list[EventSummary]:
    stmt = select(AuditEventRow)
    if since:
        stmt = stmt.where(AuditEventRow.timestamp >= utc(since))
    if until:
        stmt = stmt.where(AuditEventRow.timestamp <= utc(until))
    if subject:
        stmt = stmt.where(or_(AuditEventRow.subject == subject, AuditEventRow.username == subject))
    if group:
        stmt = stmt.where(AuditEventRow.groups_text.contains(f"|{group}|", autoescape=True))
    if agent:
        stmt = stmt.where(AuditEventRow.agent_id == agent)
    if control:
        stmt = stmt.where(AuditEventRow.controls_text.contains(f"|{control}|", autoescape=True))
    if rule_id:
        stmt = stmt.where(AuditEventRow.rules_text.contains(f"|{rule_id}|", autoescape=True))
    if action:
        stmt = stmt.where(AuditEventRow.action == action)
    if point:
        stmt = stmt.where(AuditEventRow.point == point)
    if event_type:
        stmt = stmt.where(AuditEventRow.event_type == event_type)
    if taxonomy:
        stmt = stmt.where(AuditEventRow.tags_text.contains(f"|{taxonomy}|", autoescape=True))
    if before_seq is not None:
        stmt = stmt.where(AuditEventRow.seq < before_seq)
    stmt = stmt.order_by(AuditEventRow.seq.desc()).limit(max(1, min(limit, 1000)))
    async with sessions() as s:
        return [summary_from_row(r) for r in (await s.execute(stmt)).scalars()]


async def get_event(sessions: async_sessionmaker[AsyncSession], event_id: str) -> AuditEvent | None:
    async with sessions() as s:
        row = await s.get(AuditEventRow, event_id)
    return AuditEvent.model_validate(row.data) if row else None


async def head_of_index(sessions: async_sessionmaker[AsyncSession]) -> tuple[int, str] | None:
    """(max seq, hash of that record) as recorded in the index, for truncation / tail-edit detection."""
    async with sessions() as s:
        row = (await s.execute(select(AuditEventRow).order_by(AuditEventRow.seq.desc()).limit(1))).scalar_one_or_none()
    return (row.seq, str(row.data.get("hash"))) if row else None


async def spend_by_connector(sessions: async_sessionmaker[AsyncSession], since: datetime) -> dict[str, float]:
    stmt = (
        select(AuditEventRow.connector, func.sum(AuditEventRow.usd))
        .where(AuditEventRow.timestamp >= utc(since), AuditEventRow.connector.is_not(None))
        .group_by(AuditEventRow.connector)
    )
    async with sessions() as s:
        return {c: float(v or 0.0) for c, v in (await s.execute(stmt)).all()}


def posture_score(open_by_severity: Counter[str], enforcement_gap: float) -> float:
    """100 minus weighted open incidents and the share of would-have-blocked traffic running in monitor mode."""
    penalty = (
        20 * open_by_severity.get("critical", 0)
        + 10 * open_by_severity.get("high", 0)
        + 4 * open_by_severity.get("medium", 0)
        + 1 * open_by_severity.get("low", 0)
        + 25 * enforcement_gap
    )
    return round(max(0.0, min(100.0, 100.0 - penalty)), 1)


async def overview(
    sessions: async_sessionmaker[AsyncSession],
    window: str,
    *,
    external_price_per_1k: tuple[float, float] | None = None,
    pending_approvals: int = 0,
) -> OverviewSummary:
    now = datetime.now(UTC)
    since = now - parse_window(window)
    base = (AuditEventRow.timestamp >= since, AuditEventRow.event_type == "decision")
    async with sessions() as s:
        by_action = {
            a: int(n)
            for a, n in (
                await s.execute(select(AuditEventRow.action, func.count()).where(*base).group_by(AuditEventRow.action))
            ).all()
            if a
        }
        routed = (
            await s.execute(
                select(AuditEventRow.tier, func.count())
                .where(*base, AuditEventRow.tier.is_not(None), AuditEventRow.point.in_(("ingress", "embeddings")))
                .group_by(AuditEventRow.tier)
            )
        ).all()
        spend = float(
            (
                await s.execute(
                    select(func.coalesce(func.sum(AuditEventRow.usd), 0.0)).where(AuditEventRow.timestamp >= since)
                )
            ).scalar()
            or 0.0
        )
        local_tokens = (
            await s.execute(
                select(
                    func.coalesce(func.sum(AuditEventRow.input_tokens), 0),
                    func.coalesce(func.sum(AuditEventRow.output_tokens), 0),
                    func.coalesce(func.sum(AuditEventRow.usd), 0.0),
                ).where(*base, AuditEventRow.tier == "local")
            )
        ).one()
        flagged = (
            await s.execute(
                select(AuditEventRow.rules_text, AuditEventRow.tags_text, AuditEventRow.would_action)
                .where(*base, or_(AuditEventRow.action.not_in(_NO_ACTION), AuditEventRow.would_action.is_not(None)))
                .order_by(AuditEventRow.seq.desc())
                .limit(20000)
            )
        ).all()
        open_rows = (
            await s.execute(
                select(IncidentRow.severity, func.count())
                .where(IncidentRow.status.in_(("open", "triaged")))
                .group_by(IncidentRow.severity)
            )
        ).all()
    rules: Counter[str] = Counter()
    tags: Counter[str] = Counter()
    for rules_text, tags_text, _ in flagged:
        rules.update(_split(rules_text))
        tags.update(_split(tags_text))
    routed_by_tier = {t: int(n) for t, n in routed}
    total_routed = sum(routed_by_tier.values())
    open_by_sev: Counter[str] = Counter({sev: int(n) for sev, n in open_rows})
    total_decisions = sum(by_action.values())
    would = sum(1 for _, _, w in flagged if w)
    savings = 0.0
    if external_price_per_1k is not None:
        in_p, out_p = external_price_per_1k
        savings = max(0.0, local_tokens[0] / 1000 * in_p + local_tokens[1] / 1000 * out_p - float(local_tokens[2]))
    return OverviewSummary(
        generated_at=now,
        window=window,
        posture_score=posture_score(open_by_sev, would / total_decisions if total_decisions else 0.0),
        decisions_by_action=by_action,
        top_rules=dict(rules.most_common(10)),
        top_taxonomy=dict(tags.most_common(10)),
        external_routing_rate=routed_by_tier.get("cloud", 0) / total_routed if total_routed else 0.0,
        spend_usd=round(spend, 6),
        savings_usd_vs_external=round(savings, 6),
        open_incidents=sum(open_by_sev.values()),
        pending_approvals=pending_approvals,
    )


def _pct(sorted_values: list[float], q: float) -> float:
    if not sorted_values:
        return 0.0
    idx = min(len(sorted_values) - 1, max(0, round(q * (len(sorted_values) - 1))))
    return sorted_values[idx]


async def performance(sessions: async_sessionmaker[AsyncSession], window: str) -> PerformanceSummary:
    now = datetime.now(UTC)
    since = now - parse_window(window, 3600)
    stmt = (
        select(AuditEventRow.data)
        .where(AuditEventRow.timestamp >= since, AuditEventRow.event_type == "decision")
        .order_by(AuditEventRow.seq.desc())
        .limit(5000)
    )
    async with sessions() as s:
        datas: list[dict[str, Any]] = list((await s.execute(stmt)).scalars())
    lat: dict[tuple[str, str], list[float]] = {}
    verdicts = cached = fail_open = escalated = 0
    for d in datas:
        l2 = False
        for v in d.get("verdicts", []):
            verdicts += 1
            if v.get("status") == "cached":
                cached += 1
                continue
            if v.get("status") in ("timeout", "error") and v.get("action") == "allow":
                fail_open += 1
            l2 = l2 or v.get("phase") == "semantic_l2"
            lat.setdefault((v.get("phase", ""), v.get("control_id", "")), []).append(float(v.get("latency_ms") or 0.0))
        escalated += int(l2)
    stages = []
    for (phase, control), values in sorted(lat.items()):
        values.sort()
        stages.append(
            StageLatency(
                phase=phase,
                control_id=control,
                count=len(values),
                p50_ms=_pct(values, 0.5),
                p95_ms=_pct(values, 0.95),
                p99_ms=_pct(values, 0.99),
            )
        )
    return PerformanceSummary(
        generated_at=now,
        stages=stages,
        cache_hit_rate=cached / verdicts if verdicts else 0.0,
        judge_escalation_rate=escalated / len(datas) if datas else 0.0,
        fail_open_count=fail_open,
    )
