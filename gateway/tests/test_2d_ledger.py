"""2D: budget ledger, token bucket, windows, circuit-breaker state machine, persistence."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from acl.budgets.breaker import BreakerBook
from acl.budgets.estimate import ZERO, Estimate
from acl.budgets.ledger import Ledger, window_id
from acl.budgets.nodes import NodeSpec
from acl.budgets.store import BudgetStore
from acl.db import create_all, make_engine, make_sessionmaker


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:  # a mid-month, mid-day UTC instant
        self.t = t

    def __call__(self) -> float:
        return self.t


def specs(limits_user: dict[str, float] | None = None, limits_org: dict[str, float] | None = None) -> list[NodeSpec]:
    return [
        NodeSpec("org", "org", None, limits_org or {}),
        NodeSpec("user:jan", "user", "org", limits_user or {}),
        NodeSpec("session:s1", "session", "user:jan", {}),
    ]


def test_window_ids_are_calendar_aligned() -> None:
    t = datetime(2026, 3, 9, 13, 45, 10, tzinfo=UTC).timestamp()
    assert window_id("day", t) == "2026-03-09"
    assert window_id("month", t) == "2026-03"
    assert window_id("minute", t) == str(int(t // 60))
    assert window_id("session", t) == "s"


def test_under_the_cap_is_clean_and_overrun_is_hard() -> None:
    clock = Clock()
    ledger = Ledger(clock)
    sp = specs({"tokens_day": 1000})
    assert ledger.check(sp, Estimate(input_tokens=100, output_tokens=100), soft_pct=80) == []
    ledger.charge(sp, input_tokens=600, output_tokens=200, usd=0.0, gpu_seconds=0.0)
    [b] = ledger.check(sp, Estimate(input_tokens=100, output_tokens=100), soft_pct=80)
    assert not b.hard and b.level == "soft" and b.projected == 1000  # exactly at the limit is still allowed
    [b] = ledger.check(sp, Estimate(input_tokens=100, output_tokens=101), soft_pct=80)
    assert b.hard and not b.exhausted  # the request is too large; the budget itself is not spent
    ledger.charge(sp, input_tokens=200, output_tokens=0, usd=0.0, gpu_seconds=0.0)
    [b] = ledger.check(sp, ZERO, soft_pct=80)
    assert b.exhausted and not b.hard  # used == limit: spent, but not over


def test_soft_threshold_is_reported_without_hard() -> None:
    ledger = Ledger(Clock())
    sp = specs({"tokens_day": 1000})
    ledger.charge(sp, input_tokens=700, output_tokens=100, usd=0, gpu_seconds=0)
    [b] = ledger.check(sp, ZERO, soft_pct=80)
    assert not b.hard and b.level == "soft" and b.used == 800


def test_windows_roll_over() -> None:
    clock = Clock()
    ledger = Ledger(clock)
    sp = specs({"tokens_minute": 100, "tokens_day": 1000})
    ledger.charge(sp, input_tokens=100, output_tokens=0, usd=0, gpu_seconds=0)
    assert {b.meter for b in ledger.check(sp, Estimate(input_tokens=1), soft_pct=80)} == {"tokens_minute"}
    clock.t += 61  # next minute: the minute window restarts, the day window keeps counting
    assert ledger.check(sp, Estimate(input_tokens=1), soft_pct=80) == []
    assert ledger.value("user:jan", "tokens_day") == 100
    clock.t += 86_400  # next day
    assert ledger.value("user:jan", "tokens_day") == 0


def test_session_limits_count_on_the_session_node_and_floors_apply() -> None:
    ledger = Ledger(Clock())
    sp = [
        NodeSpec("org", "org", None, {}),
        NodeSpec("agent:bot", "agent", "org", {"tokens_session": 100, "tool_calls_session": 2}),
        NodeSpec("session:s1", "session", "agent:bot", {}),
    ]
    ledger.charge(sp, input_tokens=60, output_tokens=0, usd=0, gpu_seconds=0)
    [b] = ledger.check(sp, Estimate(input_tokens=60), soft_pct=80)
    assert b.hard and b.owner == "agent:bot" and b.scope == "session:s1"  # a session breach trips the session
    ledger.count_tool_call(sp)
    ledger.count_tool_call(sp)
    [b] = ledger.check(sp, Estimate(tool_calls=1), soft_pct=80, tools_only=True)
    assert b.meter == "tool_calls_session" and b.hard and b.exhausted
    # the session store's tool_depth is a floor (cases and /v1/decide sessions carry it)
    fresh = Ledger(Clock())
    [b] = fresh.check(sp, Estimate(tool_calls=1), soft_pct=80, tools_only=True, floors={"tool_calls": 2})
    assert b.hard


def test_requests_per_minute_is_a_token_bucket() -> None:
    clock = Clock()
    ledger = Ledger(clock)
    sp = specs({"requests_per_minute": 6})
    for _ in range(6):
        assert not [b for b in ledger.check(sp, ZERO, soft_pct=100) if b.hard]
        ledger.count_request(sp)
    [b] = [b for b in ledger.check(sp, ZERO, soft_pct=100) if b.hard]
    assert b.meter == "requests_per_minute"
    clock.t += 10  # 6/min refills one request every 10 s
    assert not [b for b in ledger.check(sp, ZERO, soft_pct=100) if b.hard]
    ledger.count_request(sp)
    assert [b for b in ledger.check(sp, ZERO, soft_pct=100) if b.hard]


def test_check_is_read_only_and_guard_spend_is_a_separate_line() -> None:
    ledger = Ledger(Clock())
    sp = specs({"tokens_day": 100})
    for _ in range(5):
        ledger.check(sp, Estimate(input_tokens=50), soft_pct=80)
    assert ledger.usage_of("user:jan") == {}
    ledger.charge_guard(sp, tokens=5000, gpu_seconds=2.5)
    usage = ledger.usage_of("user:jan")
    assert usage["guard_tokens_day"] == 5000 and usage["guard_gpu_seconds_day"] == 2.5
    assert "tokens_day" not in usage  # never counted against the user's own budget
    assert ledger.check(sp, ZERO, soft_pct=80) == []


def test_mark_notified_once_per_window() -> None:
    clock = Clock()
    ledger = Ledger(clock)
    sp = specs({"tokens_day": 100})
    ledger.charge(sp, input_tokens=90, output_tokens=0, usd=0, gpu_seconds=0)
    assert ledger.mark_notified("user:jan", "tokens_day", "soft") is True
    assert ledger.mark_notified("user:jan", "tokens_day", "soft") is False
    assert ledger.mark_notified("user:jan", "tokens_day", "hard") is True
    clock.t += 86_400
    ledger.charge(sp, input_tokens=90, output_tokens=0, usd=0, gpu_seconds=0)
    assert ledger.mark_notified("user:jan", "tokens_day", "soft") is True


def test_session_spend_rate_tracks_the_trailing_average() -> None:
    clock = Clock()
    ledger = Ledger(clock)
    sp = specs()
    for _ in range(4):  # 4 quiet minutes of ~100 tokens
        ledger.charge(sp, input_tokens=100, output_tokens=0, usd=0, gpu_seconds=0)
        clock.t += 60
    rate = ledger.session_rate("s1", extra_tokens=900)
    assert rate.span_minutes == 4 and rate.trailing_avg == pytest.approx(100.0) and rate.current == 900


def test_sessions_are_evicted_by_ttl() -> None:
    clock = Clock()
    ledger = Ledger(clock, session_ttl_s=100)
    ledger.charge(specs(), input_tokens=1, output_tokens=0, usd=0, gpu_seconds=0)
    clock.t += 500
    ledger.charge([NodeSpec("session:s2", "session", None, {})], input_tokens=1, output_tokens=0, usd=0, gpu_seconds=0)
    ids = {n["id"] for n in ledger.nodes()}
    assert "session:s2" in ids and "session:s1" not in ids and "user:jan" in ids


# ---------------------------------------------------------------- circuit breaker


def test_breaker_closed_open_half_open_closed() -> None:
    clock = Clock()
    book = BreakerBook(clock)
    assert book.view("user:jan") is None
    assert book.trip("user:jan", "tokens_day", cooldown_s=300, half_open_probes=1) is True
    assert book.trip("user:jan", "again", cooldown_s=300, half_open_probes=1) is False  # already open
    assert book.view("user:jan").state == "open"  # type: ignore[union-attr]
    clock.t += 299
    assert book.view("user:jan").state == "open"  # type: ignore[union-attr]
    clock.t += 2  # cooldown elapsed: half-open, computed from the clock
    v = book.view("user:jan")
    assert v is not None and v.state == "half_open" and v.probe_available
    assert book.begin_probe("user:jan") is True
    v = book.view("user:jan")
    assert v is not None and v.state == "half_open" and not v.probe_available  # one probe at a time
    assert book.begin_probe("user:jan") is False
    assert book.probe_succeeded("user:jan") is True
    assert book.view("user:jan").state == "closed"  # type: ignore[union-attr]


def test_failed_probe_reopens_with_a_fresh_cooldown() -> None:
    clock = Clock()
    book = BreakerBook(clock)
    book.trip("n", "x", cooldown_s=60, half_open_probes=1)
    clock.t += 61
    assert book.begin_probe("n")
    assert book.trip("n", "still over", cooldown_s=60, half_open_probes=1) is True
    assert book.view("n").state == "open"  # type: ignore[union-attr]
    clock.t += 30
    assert book.view("n").state == "open"  # type: ignore[union-attr]
    clock.t += 31
    assert book.view("n").state == "half_open"  # type: ignore[union-attr]


def test_probe_slot_that_never_reports_back_frees_itself() -> None:
    clock = Clock()
    book = BreakerBook(clock)
    book.trip("n", "x", cooldown_s=60, half_open_probes=1)
    clock.t += 61
    assert book.begin_probe("n")
    assert not book.view("n").probe_available  # type: ignore[union-attr]
    clock.t += 61
    assert book.view("n").probe_available  # type: ignore[union-attr]


def test_admin_reset_closes() -> None:
    book = BreakerBook(Clock())
    book.trip("n", "x", cooldown_s=60, half_open_probes=1)
    assert book.reset("n").state == "closed"  # type: ignore[union-attr]
    assert book.reset("missing") is None


# ---------------------------------------------------------------- persistence


@pytest.mark.asyncio
async def test_flush_and_reload_roundtrip(tmp_path: Path) -> None:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'b.db'}")
    await create_all(engine)
    sessions = make_sessionmaker(engine)
    clock = Clock()
    ledger, book = Ledger(clock), BreakerBook(clock)
    store = BudgetStore(sessions, ledger, book)
    sp = specs({"tokens_day": 1000, "tokens_minute": 500})
    ledger.charge(sp, input_tokens=300, output_tokens=100, usd=0.5, gpu_seconds=2.0)
    ledger.mark_notified("user:jan", "tokens_day", "soft")
    book.trip("user:jan", "tokens_day", cooldown_s=300, half_open_probes=1)
    assert await store.flush() > 0
    assert await store.flush() == 0  # nothing dirty any more

    clock.t += 120  # restart two minutes later: the minute window is gone, day / session state survives
    ledger2, book2 = Ledger(clock), BreakerBook(clock)
    counters, breakers = await BudgetStore(sessions, ledger2, book2).load()
    assert counters > 0 and breakers == 1
    assert ledger2.value("user:jan", "tokens_day") == 400
    assert ledger2.value("user:jan", "tokens_minute") == 0
    assert ledger2.value("session:s1", "usd_session") == pytest.approx(0.5)
    assert ledger2.mark_notified("user:jan", "tokens_day", "soft") is False  # the notification flag survived
    assert book2.view("user:jan").state == "open"  # type: ignore[union-attr]
    await engine.dispose()


def test_retry_after_follows_the_window_that_resets() -> None:
    from acl.budgets.retry import breaker_retry_after_s, retry_after_s

    t = datetime(2026, 3, 9, 13, 45, 10, tzinfo=UTC).timestamp()
    ledger = Ledger(Clock(t))
    sp = specs({"tokens_day": 100, "tokens_session": 100, "usd_month": 5})
    ledger.charge(sp, input_tokens=0, output_tokens=100, usd=0, gpu_seconds=0)
    by_meter = {b.meter: b for b in ledger.check(sp, Estimate(input_tokens=1), soft_pct=80) if b.hard}
    assert set(by_meter) == {"tokens_day", "tokens_session"}
    midnight = datetime(2026, 3, 10, tzinfo=UTC).timestamp()
    assert retry_after_s([by_meter["tokens_day"]], t) == int(midnight - t)
    assert retry_after_s([by_meter["tokens_session"]], t) is None  # a session budget never refills
    assert retry_after_s(by_meter.values(), t) is None  # one unknown reset makes the answer unknown
    assert retry_after_s([], t) is None
    assert breaker_retry_after_s(t + 90.2, t) == 91 and breaker_retry_after_s(None, t) is None
    assert breaker_retry_after_s(t - 5, t) == 1


def test_retry_after_month_and_oversized_request() -> None:
    from acl.budgets.retry import retry_after_s, seconds_until_window_end

    t = datetime(2026, 12, 31, 23, 0, 0, tzinfo=UTC).timestamp()
    assert seconds_until_window_end("month", t) == 3600 and seconds_until_window_end("day", t) == 3600
    ledger = Ledger(Clock(t))
    sp = specs({"tokens_day": 100})
    [big] = [b for b in ledger.check(sp, Estimate(input_tokens=500), soft_pct=80) if b.hard]
    assert retry_after_s([big], t) is None  # one request larger than the whole daily limit: waiting never fits it
