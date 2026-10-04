"""Recurrence of one cluster: runs and retries, periodicity (daily / weekly / ad hoc), time spent, similarity.

A **run** is one person doing the task once: a cluster member plus the retries that follow it in the same session
(a near-identical prompt within `retry_window_s`). Time spent on a run is the span from its first request to the
last answer, plus the time to read that answer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Literal

from acl.insights.embed import centroid, cosine
from acl.insights.records import PromptRecord

READ_TOKENS_PER_MINUTE = 250.0
DAILY_MIN_RATIO = 0.6
WEEKLY_MIN_RATIO = 0.75


@dataclass
class Run:
    subject: str
    members: list[int] = field(default_factory=list)  # indices into the cluster's records, time-ordered

    def records(self, recs: list[PromptRecord]) -> list[PromptRecord]:
        return [recs[i] for i in self.members]


@dataclass(frozen=True)
class Recurrence:
    kind: Literal["daily", "weekly", "adhoc"]
    periodicity: float
    first_seen: datetime
    last_seen: datetime
    active_days: int
    runs: int
    retries: int
    distinct_users: int
    minutes_total: float
    minutes_per_active_day: float
    runs_per_active_day: float
    structural_similarity: float


def build_runs(
    records: list[PromptRecord], vectors: list[list[float]], *, retry_window_s: float, retry_similarity: float
) -> list[Run]:
    order = sorted(range(len(records)), key=lambda i: (records[i].timestamp, records[i].key))
    runs: list[Run] = []
    open_run: dict[tuple[str, str], tuple[Run, int]] = {}  # (subject, session) → (run, last member)
    for i in order:
        r = records[i]
        sk = (r.subject, r.session_id or f"day:{r.timestamp.date().isoformat()}")
        prev = open_run.get(sk)
        if prev is not None:
            run, last = prev
            gap = (r.timestamp - records[last].timestamp).total_seconds()
            if gap <= retry_window_s and cosine(vectors[i], vectors[last]) >= retry_similarity:
                run.members.append(i)
                open_run[sk] = (run, i)
                continue
        run = Run(subject=r.subject, members=[i])
        runs.append(run)
        open_run[sk] = (run, i)
    return runs


def run_minutes(run: Run, records: list[PromptRecord]) -> float:
    recs = run.records(records)
    span = (recs[-1].timestamp - recs[0].timestamp).total_seconds() / 60.0
    return span + recs[-1].latency_ms / 60000.0 + recs[-1].tokens_out / READ_TOKENS_PER_MINUTE


def _workdays(start: date, end: date) -> list[date]:
    days, d = [], start
    while d <= end:
        if d.weekday() < 5:
            days.append(d)
        d += timedelta(days=1)
    return days


def classify(run_starts: list[datetime]) -> tuple[Literal["daily", "weekly", "adhoc"], float]:
    """Daily if runs happen on most workdays of the observed span, weekly if in most weeks, else ad hoc."""
    if not run_starts:
        return "adhoc", 0.0
    days = {t.date() for t in run_starts}
    first, last = min(days), max(days)
    span = (last - first).days + 1
    workdays = _workdays(first, last)
    daily = len([d for d in days if d.weekday() < 5]) / len(workdays) if workdays else 0.0
    weeks_all = {(first + timedelta(days=i)).isocalendar()[:2] for i in range(span)}
    weekly = len({d.isocalendar()[:2] for d in days}) / len(weeks_all)
    if span >= 5 and len(workdays) >= 3 and daily >= DAILY_MIN_RATIO:
        return "daily", round(min(daily, 1.0), 3)
    if span >= 14 and weekly >= WEEKLY_MIN_RATIO:
        return "weekly", round(min(weekly, 1.0), 3)
    return "adhoc", round(min(daily, 1.0), 3)


def recurrence(records: list[PromptRecord], vectors: list[list[float]], runs: list[Run]) -> Recurrence:
    starts = [records[run.members[0]].timestamp for run in runs]
    kind, periodicity = classify(starts)
    active_days = len({t.date() for t in starts}) or 1
    minutes = sum(run_minutes(run, records) for run in runs)
    c = centroid(vectors)
    similarity = sum(cosine(v, c) for v in vectors) / len(vectors) if vectors else 0.0
    return Recurrence(
        kind=kind,
        periodicity=periodicity,
        first_seen=min(r.timestamp for r in records),
        last_seen=max(r.timestamp for r in records),
        active_days=active_days,
        runs=len(runs),
        retries=sum(len(run.members) - 1 for run in runs),
        distinct_users=len({r.subject for r in records}),
        minutes_total=round(minutes, 2),
        minutes_per_active_day=round(minutes / active_days, 1),
        runs_per_active_day=round(len(runs) / active_days, 2),
        structural_similarity=round(similarity, 3),
    )
