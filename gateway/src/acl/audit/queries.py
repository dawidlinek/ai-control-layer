"""Read side of the audit index: event lists, incidents, overview and performance summaries."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal

from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.audit.db_models import AuditEventRow, IncidentRow
from acl.audit.incidents import as_utc
from acl.audit.stream import event_summary, session_threshold
from acl.contracts.admin import (
    ClientRef,
    DecisionBucket,
    EventSummary,
    ModelCost,
    OverviewSummary,
    PerformanceSummary,
    StageLatency,
    UsageStats,
)
from acl.contracts.audit import AuditEvent
from acl.contracts.common import ConnectorTier, DataClass

if TYPE_CHECKING:
    from acl.policy.models import Policy

_WINDOW = re.compile(r"^(\d+)\s*([smhdw])$")
_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_NO_ACTION = ("allow", "monitor")


async def open_incident_count(sessions: async_sessionmaker[AsyncSession]) -> int:
    stmt = select(func.count()).select_from(IncidentRow).where(IncidentRow.status.in_(("open", "triaged")))
    async with sessions() as s:
        return int((await s.execute(stmt)).scalar_one())


def parse_window(window: str, default_s: int = 86400) -> timedelta:
    m = _WINDOW.match(window.strip().lower())
    return timedelta(seconds=int(m.group(1)) * _UNITS[m.group(2)]) if m else timedelta(seconds=default_s)


def utc(dt: datetime) -> datetime:
    return as_utc(dt)


def _split(text: str) -> list[str]:
    return [p for p in text.split("|") if p]


_GENERIC_APPS = frozenset({"", "unknown", "agent", "sdk"})
# Decision points that start something (a model request, a tool call); answers and tool results are replies.
_REPLY_POINTS = ("egress", "tool_result")
Threshold = DataClass | None | Literal["policy"]


def summary_from_row(
    r: AuditEventRow,
    *,
    policy: Policy | None = None,
    threshold: Threshold = "policy",
    client_ref: ClientRef | None = None,
) -> EventSummary:
    return event_summary(AuditEvent.model_validate(r.data), policy=policy, threshold=threshold, client_ref=client_ref)


def build_client_ref(event: AuditEvent, stats: dict[str, tuple[int, datetime]]) -> ClientRef | None:
    """The client conversation / session an event belongs to, from `session_stats`."""
    if not event.session_id or event.session_id not in stats:
        return None
    count, started = stats[event.session_id]
    app = (event.client.app if event.client else "").strip().lower()
    agent = event.principal.agent_id if event.principal else None
    client = agent if agent and app in _GENERIC_APPS else (app or agent or "unknown")
    return ClientRef(
        kind="conversation" if app == "librechat" else "session",
        id=event.session_id,
        client=client,
        message_count=count,
        started_at=started,
    )


async def session_stats(
    sessions: async_sessionmaker[AsyncSession], session_ids: Iterable[str]
) -> dict[str, tuple[int, datetime]]:
    """session id -> (ingress decision events, first decision timestamp), one grouped query."""
    ids = sorted({i for i in session_ids if i})
    if not ids:
        return {}
    stmt = (
        select(
            AuditEventRow.session_id,
            func.sum(case((AuditEventRow.point == "ingress", 1), else_=0)),
            func.min(AuditEventRow.timestamp),
        )
        .where(AuditEventRow.session_id.in_(ids), AuditEventRow.event_type == "decision")
        .group_by(AuditEventRow.session_id)
    )
    async with sessions() as s:
        return {sid: (int(n or 0), utc(first)) for sid, n, first in (await s.execute(stmt)).all()}


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
    policy: Policy | None = None,
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
        rows = list((await s.execute(stmt)).scalars())
    events = [AuditEvent.model_validate(r.data) for r in rows]
    stats = await session_stats(sessions, (e.session_id for e in events if e.session_id))
    threshold = session_threshold(policy)
    return [event_summary(e, policy=policy, threshold=threshold, client_ref=build_client_ref(e, stats)) for e in events]


async def rule_hits(
    sessions: async_sessionmaker[AsyncSession], rule_ids: Iterable[str], since: datetime
) -> dict[str, tuple[int, datetime | None]]:
    """rule id -> (decisions citing it since `since`, latest such timestamp); one aggregate query per 40 ids."""
    ids = sorted({r for r in rule_ids if r})
    out: dict[str, tuple[int, datetime | None]] = {}
    for start in range(0, len(ids), 40):
        chunk = ids[start : start + 40]
        hit = {r: AuditEventRow.rules_text.contains(f"|{r}|", autoescape=True) for r in chunk}
        cols = []
        for r in chunk:
            cols.append(func.sum(case((hit[r], 1), else_=0)))
            cols.append(func.max(case((hit[r], AuditEventRow.timestamp), else_=None)))
        stmt = select(*cols).where(
            AuditEventRow.event_type == "decision",
            AuditEventRow.timestamp >= utc(since),
            AuditEventRow.rules_text != "",
        )
        async with sessions() as s:
            row = (await s.execute(stmt)).one()
        for i, r in enumerate(chunk):
            n, last = row[2 * i], row[2 * i + 1]
            out[r] = (int(n or 0), utc(last) if last else None)
    return out


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


async def user_stats(
    sessions: async_sessionmaker[AsyncSession], subjects: Iterable[str], *, window: str = "7d"
) -> dict[str, UsageStats]:
    """Traffic per subject over `window` from decision events, one grouped query.

    `requests` counts what a client starts (prompts, embeddings, tool calls); answers and tool results are
    replies to those and would double-count.
    """
    ids = sorted({x for x in subjects if x})
    if not ids:
        return {}
    since = datetime.now(UTC) - parse_window(window, 7 * 86400)
    stmt = (
        select(
            AuditEventRow.subject,
            func.sum(case((AuditEventRow.point.in_(_REPLY_POINTS), 0), else_=1)),
            func.coalesce(func.sum(AuditEventRow.input_tokens), 0),
            func.coalesce(func.sum(AuditEventRow.output_tokens), 0),
            func.sum(case((AuditEventRow.action == "block", 1), else_=0)),
            func.coalesce(func.sum(AuditEventRow.usd), 0.0),
            func.coalesce(func.sum(AuditEventRow.gpu_seconds), 0.0),
            func.max(AuditEventRow.timestamp),
        )
        .where(
            AuditEventRow.subject.in_(ids),
            AuditEventRow.event_type == "decision",
            AuditEventRow.timestamp >= since,
        )
        .group_by(AuditEventRow.subject)
    )
    async with sessions() as s:
        rows = (await s.execute(stmt)).all()
    out = {
        subject: UsageStats(
            window=window,
            requests=int(req or 0),
            tokens_in=int(tin or 0),
            tokens_out=int(tout or 0),
            blocks=int(blocks or 0),
            usd=round(float(usd or 0.0), 6),
            gpu_seconds=round(float(gpu or 0.0), 3),
            last_active=utc(last) if last else None,
        )
        for subject, req, tin, tout, blocks, usd, gpu, last in rows
    }
    return {sid: out.get(sid, UsageStats(window=window)) for sid in ids}


async def usage_by_model(sessions: async_sessionmaker[AsyncSession], since: datetime) -> dict[str, dict[str, float]]:
    """model id -> requests, tokens in / out, usd, gpu seconds since `since`, one grouped query."""
    stmt = (
        select(
            AuditEventRow.model,
            func.sum(case((AuditEventRow.point.in_(("ingress", "embeddings")), 1), else_=0)),
            func.coalesce(func.sum(AuditEventRow.input_tokens), 0),
            func.coalesce(func.sum(AuditEventRow.output_tokens), 0),
            func.coalesce(func.sum(AuditEventRow.usd), 0.0),
            func.coalesce(func.sum(AuditEventRow.gpu_seconds), 0.0),
        )
        .where(AuditEventRow.timestamp >= utc(since), AuditEventRow.model.is_not(None))
        .group_by(AuditEventRow.model)
    )
    async with sessions() as s:
        rows = (await s.execute(stmt)).all()
    return {
        model: {
            "requests": int(req or 0),
            "tokens_in": int(tin or 0),
            "tokens_out": int(tout or 0),
            "usd": float(usd or 0.0),
            "gpu_seconds": float(gpu or 0.0),
        }
        for model, req, tin, tout, usd, gpu in rows
    }


async def session_events(
    sessions: async_sessionmaker[AsyncSession], session_id: str, limit: int
) -> tuple[list[AuditEvent], bool]:
    """The audit events of one session ordered by seq (at most `limit`), and whether more exist."""
    limit = max(1, min(limit, 5000))
    stmt = (
        select(AuditEventRow.data)
        .where(AuditEventRow.session_id == session_id)
        .order_by(AuditEventRow.seq.asc())
        .limit(limit + 1)
    )
    async with sessions() as s:
        datas = list((await s.execute(stmt)).scalars())
    return [AuditEvent.model_validate(d) for d in datas[:limit]], len(datas) > limit


def bucket_seconds(window: timedelta) -> int:
    """Timeline bucket for a window: 15m → 1 min, 1h → 5 min, 24h → 1 h, 7d → 1 day."""
    s = window.total_seconds()
    return 60 if s <= 900 else 300 if s <= 3600 else 3600 if s <= 86400 else 86400


def decision_timeline(
    rows: Iterable[tuple[datetime, str | None]], since: datetime, now: datetime, step: int
) -> list[DecisionBucket]:
    """Contiguous buckets from `since` to `now` with decisions per action."""
    first = int(since.timestamp()) // step * step
    last = int(now.timestamp()) // step * step
    counts: dict[int, Counter[str]] = {t: Counter() for t in range(first, last + 1, step)}
    for ts, action in rows:
        if action:
            counts.setdefault(int(utc(ts).timestamp()) // step * step, Counter())[action] += 1
    return [DecisionBucket(start=datetime.fromtimestamp(t, UTC), counts=dict(c)) for t, c in sorted(counts.items())]


def cost_by_model(rows: Iterable[tuple[Any, ...]], policy: Policy | None) -> list[ModelCost]:
    """Spend per model (tokens, USD for cloud, GPU-seconds for local) with its share of all tokens."""
    merged: dict[str, dict[str, Any]] = {}
    for model, tier, tin, tout, usd, gpu in rows:
        m = merged.setdefault(model, {"tier": None, "in": 0, "out": 0, "usd": 0.0, "gpu": 0.0})
        m["tier"] = m["tier"] or tier
        m["in"] += int(tin or 0)
        m["out"] += int(tout or 0)
        m["usd"] += float(usd or 0.0)
        m["gpu"] += float(gpu or 0.0)
    by_id = policy.model_by_id() if policy is not None else {}
    total = sum(m["in"] + m["out"] for m in merged.values())
    out: list[ModelCost] = []
    for model, m in merged.items():
        if not (m["in"] or m["out"] or m["usd"] or m["gpu"]):
            continue  # routed but never answered (e.g. blocked requests)
        entry = by_id.get(model)
        tier = policy.connectors[entry.connector].tier if policy is not None and entry is not None else m["tier"]
        if not tier:
            tier = ConnectorTier.local if m["gpu"] and not m["usd"] else ConnectorTier.cloud
        out.append(
            ModelCost(
                model=model,
                tier=ConnectorTier(tier),
                tokens_in=m["in"],
                tokens_out=m["out"],
                usd=round(m["usd"], 6),
                gpu_seconds=round(m["gpu"], 3),
                share=round((m["in"] + m["out"]) / total, 6) if total else 0.0,
            )
        )
    return sorted(out, key=lambda c: (-(c.tokens_in + c.tokens_out), c.model))


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
    policy: Policy | None = None,
) -> OverviewSummary:
    now = datetime.now(UTC)
    span = parse_window(window)
    since = now - span
    midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
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
        timeline_rows = (await s.execute(select(AuditEventRow.timestamp, AuditEventRow.action).where(*base))).all()
        cost_rows = (
            await s.execute(
                select(
                    AuditEventRow.model,
                    AuditEventRow.tier,
                    func.coalesce(func.sum(AuditEventRow.input_tokens), 0),
                    func.coalesce(func.sum(AuditEventRow.output_tokens), 0),
                    func.coalesce(func.sum(AuditEventRow.usd), 0.0),
                    func.coalesce(func.sum(AuditEventRow.gpu_seconds), 0.0),
                )
                .where(AuditEventRow.timestamp >= since, AuditEventRow.model.is_not(None))
                .group_by(AuditEventRow.model, AuditEventRow.tier)
            )
        ).all()
        today = (
            await s.execute(
                select(
                    func.coalesce(func.sum(AuditEventRow.usd), 0.0),
                    func.coalesce(func.sum(AuditEventRow.gpu_seconds), 0.0),
                ).where(AuditEventRow.timestamp >= midnight)
            )
        ).one()
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
    usd_today, gpu_today = float(today[0] or 0.0), float(today[1] or 0.0)
    org = policy.budgets.org if policy is not None else None
    usd_limit = None
    if org is not None:
        usd_limit = org.usd_day if org.usd_day is not None else (org.usd_month / 30 if org.usd_month else None)
    elapsed = max((now - midnight).total_seconds(), 3600.0)  # under an hour of data would explode the forecast
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
        decisions_total=total_decisions,
        timeline=decision_timeline(timeline_rows, since, now, bucket_seconds(span)),
        incidents_by_severity=dict(open_by_sev),
        cost_by_model=cost_by_model(cost_rows, policy),
        usd_today=round(usd_today, 6),
        usd_limit_day=usd_limit,
        usd_forecast_day=round(max(usd_today, usd_today * 86400 / elapsed), 6),
        gpu_seconds_today=round(gpu_today, 3),
        gpu_seconds_limit_day=org.gpu_seconds_day if org is not None else None,
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
