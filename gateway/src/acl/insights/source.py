"""Pipeline input: redacted prompts from the audit index, plus the optional demo seed history.

Audit index: ingress `decision` rows that were forwarded (not blocked / held) and have a `redacted_payload` (the
masked text the gateway stores; rows where a span could not be masked have none and are skipped). Tokens, USD,
GPU-seconds and latency come from the egress row of the same trace. Requests to skills are not mined again.

Seed (`deploy/seed/insights/*.jsonl`, `ACL_INSIGHTS_SEED_DIR`): synthetic, already-redacted history for the demo.
It is read directly by the miner and never written to the audit log (the hash chain stays a record of real
traffic). Dates are relative (`workdays_ago` / `days_ago`) so the history is always recent; models are roles
(`@local`, `@cloud`, `@large`) resolved against the current policy and priced with its model pricing.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from datetime import UTC, datetime, time, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.audit.db_models import AuditEventRow
from acl.contracts.common import DATA_CLASS_ORDER, DataClass
from acl.insights.records import PromptRecord
from acl.policy.models import Policy
from acl.routing.connectors.base import UpstreamUsage
from acl.routing.metering import compute_usage

log = logging.getLogger(__name__)

FORWARDED = ("allow", "monitor", "redact", "pseudonymise", "route_local", "downgrade", "sanitize")
_CHUNK = 400


def _max_class(classes: Iterable[Any]) -> DataClass:
    out = DataClass.public
    for c in classes:
        try:
            dc = DataClass(c)
        except ValueError:
            continue
        if DATA_CLASS_ORDER[dc] > DATA_CLASS_ORDER[out]:
            out = dc
    return out


def _groups(text: str) -> tuple[str, ...]:
    return tuple(p for p in (text or "").split("|") if p)


def _utc(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


async def audit_records(
    sessions: async_sessionmaker[AsyncSession], since: datetime, groups: set[str], limit: int
) -> list[PromptRecord]:
    if not groups:
        return []
    async with sessions() as s:
        rows = (
            (
                await s.execute(
                    select(AuditEventRow)
                    .where(
                        AuditEventRow.event_type == "decision",
                        AuditEventRow.point == "ingress",
                        AuditEventRow.timestamp >= since,
                        AuditEventRow.action.in_(FORWARDED),
                    )
                    .order_by(AuditEventRow.timestamp.desc())
                    .limit(limit)
                )
            )
            .scalars()
            .all()
        )
        ingress = []
        for r in rows:
            data = r.data or {}
            text = data.get("redacted_payload")
            requested = str(data.get("model_requested") or "")
            if not text or requested.startswith("skill/") or not r.subject or not r.trace_id:
                continue
            if not set(_groups(r.groups_text)) & groups:
                continue
            ingress.append(r)
        egress: dict[str, AuditEventRow] = {}
        traces = [r.trace_id for r in ingress]
        for i in range(0, len(traces), _CHUNK):
            for e in (
                await s.execute(
                    select(AuditEventRow).where(
                        AuditEventRow.trace_id.in_(traces[i : i + _CHUNK]),
                        AuditEventRow.event_type == "decision",
                        AuditEventRow.point == "egress",
                    )
                )
            ).scalars():
                egress.setdefault(e.trace_id or "", e)
    out = []
    for r in ingress:
        data = r.data or {}
        e = egress.get(r.trace_id or "")
        route = data.get("route") or {}
        labels = data.get("labels_after") or {}
        out.append(
            PromptRecord(
                key=r.event_id,
                subject=r.subject or "",
                groups=_groups(r.groups_text),
                timestamp=_utc(r.timestamp),
                session_id=r.session_id,
                text=str(data["redacted_payload"]),
                model=(e.model if e is not None else None) or r.model,
                tokens_in=e.input_tokens if e is not None else 0,
                tokens_out=e.output_tokens if e is not None else 0,
                usd=e.usd if e is not None else 0.0,
                gpu_seconds=e.gpu_seconds if e is not None else 0.0,
                latency_ms=(e.latency_ms or 0.0) if e is not None else (r.latency_ms or 0.0),
                data_class=_max_class(
                    [(route.get("factors") or {}).get("data_class"), labels.get("confidentiality"), "internal"]
                ),
                source="audit",
            )
        )
    return out


# ---------------------------------------------------------------- seed


def _workdays_back(today: datetime, n: int) -> datetime:
    d = today
    while d.weekday() >= 5:
        d -= timedelta(days=1)
    while n > 0:
        d -= timedelta(days=1)
        if d.weekday() < 5:
            n -= 1
    return d


def _seed_model(policy: Policy, ref: str) -> str:
    targets = policy.routing.targets
    role = {"@local": targets.local, "@cloud": targets.ext_small, "@large": targets.ext_large}.get(ref, ref)
    models = policy.model_by_id()
    if role in models:
        return role
    owner = next((m.id for m in policy.models if role in m.aliases), None)
    return owner or targets.local


def seed_records(seed_dir: Path, policy: Policy, now: datetime) -> list[PromptRecord]:
    """Parse every `*.jsonl` in `seed_dir`. Bad lines are skipped with a warning (the demo must still start)."""
    if not seed_dir.is_dir():
        log.warning("insights seed dir %s does not exist", seed_dir)
        return []
    models = policy.model_by_id()
    today = datetime(now.year, now.month, now.day, tzinfo=UTC)
    out: list[PromptRecord] = []
    for path in sorted(seed_dir.glob("*.jsonl")):
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                d = json.loads(line)
                base = (
                    _workdays_back(today, int(d["workdays_ago"]))
                    if "workdays_ago" in d
                    else today - timedelta(days=int(d.get("days_ago", 0)))
                )
                hh, mm = (int(x) for x in str(d.get("time", "09:00")).split(":"))
                ts = datetime.combine(base.date(), time(hh, mm), tzinfo=UTC)
                if ts > now:
                    ts -= timedelta(days=7)
                model_id = _seed_model(policy, str(d.get("model", "@local")))
                tin, tout = int(d.get("tokens_in", 0)), int(d.get("tokens_out", 0))
                usage = compute_usage(models.get(model_id), UpstreamUsage(input_tokens=tin, output_tokens=tout))
                user = str(d["user"])
                out.append(
                    PromptRecord(
                        key=str(d["id"]),
                        subject=f"seed:{user}",
                        groups=tuple(d.get("groups") or []),
                        timestamp=ts,
                        session_id=str(d.get("session") or f"{user}-{base.date().isoformat()}"),
                        text=str(d["text"]),
                        model=model_id,
                        tokens_in=tin,
                        tokens_out=tout,
                        usd=usage.usd,
                        gpu_seconds=usage.gpu_seconds,
                        latency_ms=float(d.get("latency_ms", 0.0)),
                        data_class=DataClass(d.get("data_class", "internal")),
                        source="seed",
                    )
                )
            except (KeyError, ValueError, TypeError) as exc:
                log.warning("insights seed %s:%d skipped (%s)", path.name, n, type(exc).__name__)
    return out


# ---------------------------------------------------------------- skill runs


async def skill_runs(
    sessions: async_sessionmaker[AsyncSession], since: datetime, skills: dict[str, str], limit: int = 20000
) -> dict[str, tuple[int, float, float]]:
    """skill id → (runs, mean USD per run, mean GPU-seconds per run) from forwarded skill requests in the window.

    `skills` maps skill id → its model id (the index has no `model_requested` column; filter by model first)."""
    if not skills:
        return {}
    async with sessions() as s:
        rows = (
            await s.execute(
                select(AuditEventRow.trace_id, AuditEventRow.data)
                .where(
                    AuditEventRow.event_type == "decision",
                    AuditEventRow.point == "ingress",
                    AuditEventRow.timestamp >= since,
                    AuditEventRow.action.in_(FORWARDED),
                    AuditEventRow.model.in_(sorted(set(skills.values()))),
                )
                .limit(limit)
            )
        ).all()
        by_skill: dict[str, list[str]] = {}
        for trace, data in rows:
            sid = (data or {}).get("model_requested")
            if sid in skills and trace:
                by_skill.setdefault(sid, []).append(trace)
        traces = [t for ts in by_skill.values() for t in ts]
        cost: dict[str, tuple[float, float]] = {}
        for i in range(0, len(traces), _CHUNK):
            for trace, usd, gpu in (
                await s.execute(
                    select(AuditEventRow.trace_id, AuditEventRow.usd, AuditEventRow.gpu_seconds).where(
                        AuditEventRow.trace_id.in_(traces[i : i + _CHUNK]),
                        AuditEventRow.event_type == "decision",
                        AuditEventRow.point == "egress",
                    )
                )
            ).all():
                cost.setdefault(trace or "", (usd or 0.0, gpu or 0.0))
    out = {}
    for sid, ts in by_skill.items():
        priced = [cost[t] for t in ts if t in cost]
        n = len(priced) or 1
        out[sid] = (len(ts), sum(c[0] for c in priced) / n, sum(c[1] for c in priced) / n)
    return out
