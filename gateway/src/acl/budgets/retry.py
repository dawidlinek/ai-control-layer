"""When will a blocked client be able to retry? (`Retry-After` on the HTTP 429 of a budget block)

Only reset times that are actually known are reported:

* an open circuit breaker       → its cooldown end;
* a per-minute request limit    → the next full minute (conservative upper bound of the token-bucket refill);
* a `*_day` / `*_month` limit   → the next UTC day / month boundary;
* a `*_session` limit, or a single request larger than the whole limit → never (no retry will help).

With several hard breaches all of them must clear, so the answer is the latest reset, and one unknown reset
makes the whole answer unknown (None). Seconds are whole and at least 1.
"""

from __future__ import annotations

import math
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from acl.budgets.ledger import Breach
from acl.budgets.nodes import RPM, split_meter


def seconds_until_window_end(window: str, now: float) -> float | None:
    """Seconds until the counter window of `meter` rolls over (None: it never does, or is not time based)."""
    dt = datetime.fromtimestamp(now, UTC)
    if window == "minute":
        return 60.0 - (now % 60.0)
    if window == "day":
        end = dt.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        return (end - dt).total_seconds()
    if window == "month":
        end = dt.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        end = end.replace(year=end.year + 1, month=1) if end.month == 12 else end.replace(month=end.month + 1)
        return (end - dt).total_seconds()
    return None


def retry_after_for_breach(b: Breach, now: float) -> float | None:
    if b.meter == RPM:
        return seconds_until_window_end("minute", now)
    if b.projected - b.used > b.limit + 1e-9:  # this one request is larger than the whole limit: waiting never fits it
        return None
    return seconds_until_window_end(split_meter(b.meter)[1], now)


def retry_after_s(breaches: Iterable[Breach], now: float) -> int | None:
    waits: list[float] = []
    for b in breaches:
        wait = retry_after_for_breach(b, now)
        if wait is None:
            return None
        waits.append(wait)
    return max(1, math.ceil(max(waits))) if waits else None


def breaker_retry_after_s(cooldown_until: float | None, now: float) -> int | None:
    if cooldown_until is None:
        return None
    return max(1, math.ceil(cooldown_until - now))
