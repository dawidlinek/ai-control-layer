"""Budget ledger (concept §8): hierarchical counters with minute / day / month / session windows.

    org → group(s) → user → agent → session

* Hot path is in memory behind one lock (thread and task safe, nothing awaits inside it). `BudgetStore`
  flushes dirty rows periodically and reloads them on startup (`export_dirty` / `load`).
* Windows: `minute` (fixed bucket), `day` / `month` (UTC calendar), `session` (lifetime of the session node).
  A counter whose stored window id differs from the current one reads as 0 and restarts on the next write.
* Requests per minute is a real token bucket per node (capacity = limit, refill = limit / 60 per second).
* `check()` is read-only (dry-run safe). Counters change only through `charge()`, `count_request()`,
  `count_tool_call()` and `charge_guard()`, which the flow hooks call after a decision was enforced.
* Guard spend (judges, Phase 3) is its own line: `guard_tokens_*` / `guard_gpu_seconds_*`, never counted
  against the user's token or GPU budgets.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from acl.budgets.estimate import Estimate
from acl.budgets.nodes import RPM, NodeSpec, split_meter

Clock = Callable[[], float]
EPS = 1e-9
RPM_COUNTER = "requests_minute"
MINUTE_BUCKETS = 90  # per-session tokens-per-minute history kept for the spend derivative


def window_id(window: str, now: float) -> str:
    if window == "minute":
        return str(int(now // 60))
    if window == "session":
        return "s"
    dt = datetime.fromtimestamp(now, UTC)
    return dt.strftime("%Y-%m-%d") if window == "day" else dt.strftime("%Y-%m")


@dataclass
class Counter:
    window: str = ""
    value: float = 0.0
    soft_notified: bool = False
    hard_notified: bool = False


@dataclass
class NodeState:
    id: str
    level: str
    parent: str | None
    first_seen: float
    last_seen: float
    counters: dict[str, Counter] = field(default_factory=dict)
    bucket: float | None = None
    bucket_ts: float = 0.0
    minutes: OrderedDict[str, float] = field(default_factory=OrderedDict)  # session nodes only


@dataclass(frozen=True)
class Breach:
    """One limit the request (or the ledger as it stands) violates or approaches."""

    owner: str  # node that defines the limit
    scope: str  # node whose counter is compared (the session node for *_session limits)
    meter: str  # policy name, e.g. `tokens_day`, `requests_per_minute`
    counter: str  # ledger counter holding the usage and the notification flags
    limit: float
    used: float
    projected: float
    hard: bool
    exhausted: bool  # used >= limit: the budget is already spent, not just too small for this request

    @property
    def level(self) -> str:
        return "hard" if self.hard else "soft"

    @property
    def base(self) -> str:
        return split_meter(self.meter)[0]

    def describe(self) -> str:
        who = self.owner if self.scope == self.owner else f"{self.owner} (session)"
        return f"{self.meter} {_fmt(self.projected)}/{_fmt(self.limit)} on {who}"


def _fmt(v: float) -> str:
    return f"{v:.0f}" if abs(v - round(v)) < 1e-9 else f"{v:.3f}".rstrip("0").rstrip(".")


@dataclass(frozen=True)
class SpendRate:
    current: float  # tokens in the current minute
    trailing_avg: float  # tokens per minute over the earlier minutes of the session
    span_minutes: int  # how many earlier minutes the average covers


@dataclass
class DirtyBatch:
    nodes: list[dict[str, Any]] = field(default_factory=list)
    counters: list[dict[str, Any]] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.nodes or self.counters)


class Ledger:
    def __init__(
        self, clock: Clock = time.time, *, session_ttl_s: float = 8 * 3600, max_sessions: int = 20_000
    ) -> None:
        self.clock = clock
        self.session_ttl_s = session_ttl_s
        self.max_sessions = max_sessions
        self._lock = threading.RLock()
        self._nodes: dict[str, NodeState] = {}
        self._sessions: OrderedDict[str, None] = OrderedDict()
        self._dirty_counters: set[tuple[str, str]] = set()
        self._dirty_nodes: set[str] = set()

    # ------------------------------------------------------------ internals (lock held)

    def _touch(self, spec: NodeSpec, now: float) -> NodeState:
        st = self._nodes.get(spec.id)
        if st is None:
            st = NodeState(spec.id, spec.level, spec.parent, now, now)
            self._nodes[spec.id] = st
            self._dirty_nodes.add(spec.id)
            if spec.level == "session":
                self._evict(now)
        else:
            if st.parent != spec.parent:
                st.parent = spec.parent
                self._dirty_nodes.add(spec.id)
            if now - st.last_seen >= 30:
                self._dirty_nodes.add(spec.id)
            st.last_seen = now
        if spec.level == "session":
            self._sessions[spec.id] = None
            self._sessions.move_to_end(spec.id)
        return st

    def _evict(self, now: float) -> None:
        while self._sessions:
            oldest = next(iter(self._sessions))
            st = self._nodes.get(oldest)
            expired = st is None or now - st.last_seen > self.session_ttl_s
            if not expired and len(self._sessions) <= self.max_sessions:
                break
            self._sessions.popitem(last=False)
            self._nodes.pop(oldest, None)

    def _value(self, node_id: str, counter: str, now: float) -> float:
        st = self._nodes.get(node_id)
        c = st.counters.get(counter) if st else None
        if c is None or c.window != window_id(split_meter(counter)[1], now):
            return 0.0
        return c.value

    def _counter(self, st: NodeState, counter: str, now: float) -> Counter:
        wid = window_id(split_meter(counter)[1], now)
        c = st.counters.get(counter)
        if c is None:
            c = st.counters[counter] = Counter(window=wid)
        elif c.window != wid:
            c.window, c.value, c.soft_notified, c.hard_notified = wid, 0.0, False, False
        return c

    def _add(self, st: NodeState, counter: str, amount: float, now: float) -> None:
        if amount == 0:
            return
        self._counter(st, counter, now).value += amount
        self._dirty_counters.add((st.id, counter))

    def _bucket_avail(self, st: NodeState | None, cap: float, now: float) -> float:
        if st is None or st.bucket is None:
            return cap
        return min(cap, st.bucket + max(0.0, now - st.bucket_ts) * cap / 60.0)

    # ------------------------------------------------------------ read side

    def check(
        self,
        specs: Iterable[NodeSpec],
        est: Estimate,
        *,
        soft_pct: int,
        tools_only: bool = False,
        floors: Mapping[str, float] | None = None,
    ) -> list[Breach]:
        """Every limit of every node that `est` would push past soft / hard. Read-only."""
        specs = list(specs)
        session_id = next((s.id for s in specs if s.level == "session"), None)
        add_by_base = {
            "tokens": est.tokens,
            "usd": est.usd,
            "gpu_seconds": est.gpu_seconds,
            "tool_calls": est.tool_calls,
        }
        out: list[Breach] = []
        with self._lock:
            now = self.clock()
            for spec in specs:
                for meter, limit in spec.limits.items():
                    if meter == RPM:
                        if tools_only:
                            continue
                        avail = self._bucket_avail(self._nodes.get(spec.id), limit, now)
                        used = max(0.0, limit - avail)
                        projected = used + 1.0
                        hard = avail < 1.0 - EPS
                        counter, scope = RPM_COUNTER, spec.id
                        exhausted = hard
                    else:
                        base, window = split_meter(meter)
                        if tools_only and base != "tool_calls":
                            continue
                        scope = session_id if window == "session" and session_id else spec.id
                        counter = meter
                        used = self._value(scope, meter, now)
                        if window == "session" and floors:
                            used = max(used, float(floors.get(base, 0.0)))
                        projected = used + float(add_by_base.get(base, 0.0))
                        hard = projected > limit + EPS
                        exhausted = used >= limit - EPS
                    soft = not hard and limit > 0 and projected >= limit * soft_pct / 100.0 - EPS
                    if hard or soft:
                        out.append(Breach(spec.id, scope, meter, counter, limit, used, projected, hard, exhausted))
        return out

    def overruns(self, specs: Iterable[NodeSpec], *, floors: Mapping[str, float] | None = None) -> list[Breach]:
        """Limits whose recorded usage is already strictly above the limit (after reconciliation)."""
        return [b for b in self.check(specs, Estimate(), soft_pct=100, floors=floors) if b.used > b.limit + EPS]

    def value(self, node_id: str, counter: str) -> float:
        with self._lock:
            return self._value(node_id, counter, self.clock())

    def usage_of(self, node_id: str) -> dict[str, float]:
        with self._lock:
            now = self.clock()
            st = self._nodes.get(node_id)
            if st is None:
                return {}
            out = {
                m: round(c.value, 6) for m, c in st.counters.items() if c.window == window_id(split_meter(m)[1], now)
            }
            if st.level == "session":
                out["wall_seconds_session"] = round(max(0.0, st.last_seen - st.first_seen), 3)
            return out

    def session_rate(self, session_id: str, *, extra_tokens: float = 0.0) -> SpendRate:
        """Tokens in the current minute (+ `extra_tokens` about to be spent) vs the session's earlier average."""
        with self._lock:
            now = self.clock()
            st = self._nodes.get(f"session:{session_id}")
            cur_id = int(now // 60)
            if st is None:
                return SpendRate(extra_tokens, 0.0, 0)
            current = st.minutes.get(str(cur_id), 0.0) + extra_tokens
            earlier = [(int(k), v) for k, v in st.minutes.items() if int(k) < cur_id]
            if not earlier:
                return SpendRate(current, 0.0, 0)
            span = cur_id - min(m for m, _ in earlier)
            return SpendRate(current, sum(v for _, v in earlier) / max(1, span), span)

    def nodes(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": st.id,
                    "level": st.level,
                    "parent": st.parent,
                    "first_seen": st.first_seen,
                    "last_seen": st.last_seen,
                    "usage": self.usage_of(st.id),
                }
                for st in self._nodes.values()
            ]

    # ------------------------------------------------------------ write side (called from flow hooks)

    def charge(
        self,
        specs: Iterable[NodeSpec],
        *,
        input_tokens: int,
        output_tokens: int,
        usd: float,
        gpu_seconds: float,
    ) -> None:
        """Reconcile one metered upstream call into every node (post-response)."""
        tokens = input_tokens + output_tokens
        with self._lock:
            now = self.clock()
            for spec in specs:
                st = self._touch(spec, now)
                if spec.level == "session":
                    self._add(st, "tokens_session", tokens, now)
                    self._add(st, "input_tokens_session", input_tokens, now)
                    self._add(st, "output_tokens_session", output_tokens, now)
                    self._add(st, "usd_session", usd, now)
                    self._add(st, "gpu_seconds_session", gpu_seconds, now)
                    mid = str(int(now // 60))
                    st.minutes[mid] = st.minutes.get(mid, 0.0) + tokens
                    while len(st.minutes) > MINUTE_BUCKETS:
                        st.minutes.popitem(last=False)
                    continue
                for w in ("minute", "day", "month"):
                    self._add(st, f"tokens_{w}", tokens, now)
                self._add(st, "input_tokens_day", input_tokens, now)
                self._add(st, "output_tokens_day", output_tokens, now)
                for w in ("day", "month"):
                    self._add(st, f"usd_{w}", usd, now)
                    self._add(st, f"gpu_seconds_{w}", gpu_seconds, now)

    def count_request(self, specs: Iterable[NodeSpec]) -> None:
        """Consume one request from every rate-limited node's token bucket."""
        with self._lock:
            now = self.clock()
            for spec in specs:
                st = self._touch(spec, now)
                if spec.level == "session":
                    continue
                self._add(st, RPM_COUNTER, 1, now)
                cap = spec.limits.get(RPM)
                if cap is not None:
                    st.bucket = max(0.0, self._bucket_avail(st, cap, now) - 1.0)
                    st.bucket_ts = now
                else:
                    st.bucket = None

    def count_tool_call(self, specs: Iterable[NodeSpec]) -> None:
        with self._lock:
            now = self.clock()
            for spec in specs:
                st = self._touch(spec, now)
                if spec.level == "session":
                    self._add(st, "tool_calls_session", 1, now)

    def charge_guard(self, specs: Iterable[NodeSpec], *, tokens: int, gpu_seconds: float) -> None:
        """Guard / judge spend: a separate line, never counted against the user's token or GPU budgets."""
        with self._lock:
            now = self.clock()
            for spec in specs:
                st = self._touch(spec, now)
                w = "session" if spec.level == "session" else "day"
                self._add(st, f"guard_tokens_{w}", tokens, now)
                self._add(st, f"guard_gpu_seconds_{w}", gpu_seconds, now)

    def mark_notified(self, scope: str, counter: str, level: str) -> bool:
        """True the first time a soft / hard notification is claimed for this counter's current window."""
        with self._lock:
            now = self.clock()
            st = self._nodes.get(scope)
            if st is None:
                st = self._touch(NodeSpec(scope, scope.partition(":")[0], None, {}), now)
            c = self._counter(st, counter, now)
            attr = "hard_notified" if level == "hard" else "soft_notified"
            if getattr(c, attr):
                return False
            setattr(c, attr, True)
            self._dirty_counters.add((scope, counter))
            return True

    # ------------------------------------------------------------ persistence

    def export_dirty(self) -> DirtyBatch:
        with self._lock:
            now = self.clock()
            batch = DirtyBatch()
            for nid in self._dirty_nodes:
                st = self._nodes.get(nid)
                if st is not None:
                    batch.nodes.append(
                        {
                            "node_id": st.id,
                            "level": st.level,
                            "parent": st.parent,
                            "first_seen": st.first_seen,
                            "last_seen": st.last_seen,
                        }
                    )
            for nid, meter in self._dirty_counters:
                st = self._nodes.get(nid)
                c = st.counters.get(meter) if st else None
                if c is not None:
                    batch.counters.append(
                        {
                            "node_id": nid,
                            "meter": meter,
                            "window": c.window,
                            "value": c.value,
                            "soft_notified": c.soft_notified,
                            "hard_notified": c.hard_notified,
                            "updated_at": now,
                        }
                    )
            self._dirty_nodes.clear()
            self._dirty_counters.clear()
            return batch

    def requeue(self, batch: DirtyBatch) -> None:
        """A flush failed: mark its rows dirty again."""
        with self._lock:
            self._dirty_nodes.update(n["node_id"] for n in batch.nodes)
            self._dirty_counters.update((c["node_id"], c["meter"]) for c in batch.counters)

    def load(self, nodes: Iterable[Mapping[str, Any]], counters: Iterable[Mapping[str, Any]]) -> int:
        """Restore persisted state at startup. Counters from an earlier window are dropped; sessions that
        outlived their TTL are not restored. Returns the number of counters restored."""
        restored = 0
        with self._lock:
            now = self.clock()
            for n in nodes:
                if n["level"] == "session" and now - float(n["last_seen"]) > self.session_ttl_s:
                    continue
                st = NodeState(n["node_id"], n["level"], n.get("parent"), float(n["first_seen"]), float(n["last_seen"]))
                self._nodes[st.id] = st
                if st.level == "session":
                    self._sessions[st.id] = None
            for c in counters:
                st = self._nodes.get(c["node_id"])
                meter = c["meter"]
                if st is None or c["window"] != window_id(split_meter(meter)[1], now):
                    continue
                st.counters[meter] = Counter(
                    c["window"], float(c["value"]), bool(c["soft_notified"]), bool(c["hard_notified"])
                )
                restored += 1
        return restored
