"""Circuit breakers per budget node (concept §8): closed → open → half_open → closed.

* A hard breach of cumulative spend opens the node's breaker for `cooldown_s`; while open, SEC-BUDGET-01 blocks
  every request of that node with rule `SEC-BUDGET-01.BREAKER`.
* After the cooldown the *effective* state is `half_open` (computed from the injected clock, no timer): up to
  `half_open_probes` requests pass as probes. A probe that completes within budget closes the breaker; a probe
  that breaches again re-opens it for a fresh cooldown.
* `begin_probe()` is the only way a probe slot is taken, and it is called from the commit hook, never from
  `inspect()` (dry-run safety). A probe slot that never reports back frees itself after another cooldown.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

Clock = Callable[[], float]


@dataclass
class Breaker:
    node_id: str
    state: str = "closed"  # stored state: closed | open | half_open
    opened_at: float | None = None
    cooldown_until: float | None = None
    reason: str | None = None
    probes_used: int = 0
    last_probe_at: float | None = None
    cooldown_s: int = 300
    half_open_probes: int = 1


@dataclass(frozen=True)
class BreakerView:
    node_id: str
    state: str  # effective: closed | open | half_open
    opened_at: float | None
    cooldown_until: float | None
    reason: str | None
    probe_available: bool  # half_open with a free probe slot


class BreakerBook:
    def __init__(self, clock: Clock = time.time) -> None:
        self.clock = clock
        self._lock = threading.RLock()
        self._breakers: dict[str, Breaker] = {}
        self._dirty: set[str] = set()

    # ------------------------------------------------------------ internals (lock held)

    @staticmethod
    def _effective(b: Breaker, now: float) -> str:
        if b.state == "open" and b.cooldown_until is not None and now >= b.cooldown_until:
            return "half_open"
        return b.state

    @staticmethod
    def _probes_used(b: Breaker, now: float) -> int:
        if (
            b.probes_used >= b.half_open_probes
            and b.last_probe_at is not None
            and now - b.last_probe_at >= b.cooldown_s
        ):
            return 0  # the probes never reported back: allow new ones
        return b.probes_used

    def _view(self, b: Breaker, now: float) -> BreakerView:
        state = self._effective(b, now)
        free = state == "half_open" and self._probes_used(b, now) < b.half_open_probes
        return BreakerView(b.node_id, state, b.opened_at, b.cooldown_until, b.reason, free)

    # ------------------------------------------------------------ queries

    def view(self, node_id: str) -> BreakerView | None:
        with self._lock:
            b = self._breakers.get(node_id)
            return self._view(b, self.clock()) if b else None

    def views(self, node_ids: Iterable[str]) -> list[BreakerView]:
        with self._lock:
            now = self.clock()
            return [self._view(b, now) for nid in node_ids if (b := self._breakers.get(nid)) is not None]

    def all(self) -> list[BreakerView]:
        with self._lock:
            now = self.clock()
            return [self._view(b, now) for b in self._breakers.values()]

    # ------------------------------------------------------------ transitions

    def trip(self, node_id: str, reason: str, *, cooldown_s: int, half_open_probes: int) -> bool:
        """Open the breaker (also re-opens a half-open one). False if it is already open."""
        with self._lock:
            now = self.clock()
            b = self._breakers.get(node_id)
            if b is not None and self._effective(b, now) == "open":
                return False
            b = self._breakers[node_id] = Breaker(
                node_id,
                state="open",
                opened_at=now,
                cooldown_until=now + cooldown_s,
                reason=reason,
                cooldown_s=cooldown_s,
                half_open_probes=half_open_probes,
            )
            self._dirty.add(node_id)
            return True

    def begin_probe(self, node_id: str) -> bool:
        """Take a probe slot of a half-open breaker. False if closed, open, or no slot is free."""
        with self._lock:
            now = self.clock()
            b = self._breakers.get(node_id)
            if b is None or self._effective(b, now) != "half_open":
                return False
            used = self._probes_used(b, now)
            if used >= b.half_open_probes:
                return False
            b.state, b.probes_used, b.last_probe_at = "half_open", used + 1, now
            self._dirty.add(node_id)
            return True

    def probe_succeeded(self, node_id: str) -> bool:
        """A probe completed within budget: half_open → closed."""
        with self._lock:
            b = self._breakers.get(node_id)
            if b is None or self._effective(b, self.clock()) != "half_open":
                return False
            b.state, b.probes_used, b.last_probe_at, b.cooldown_until = "closed", 0, None, None
            self._dirty.add(node_id)
            return True

    def reset(self, node_id: str) -> BreakerView | None:
        """Admin reset: force closed. None if the node never had a breaker."""
        with self._lock:
            b = self._breakers.get(node_id)
            if b is None:
                return None
            b.state, b.probes_used, b.last_probe_at, b.cooldown_until, b.reason = "closed", 0, None, None, None
            self._dirty.add(node_id)
            return self._view(b, self.clock())

    # ------------------------------------------------------------ persistence

    def export_dirty(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = [
                {
                    "node_id": b.node_id,
                    "state": b.state,
                    "opened_at": b.opened_at,
                    "cooldown_until": b.cooldown_until,
                    "reason": b.reason,
                    "probes_used": b.probes_used,
                    "last_probe_at": b.last_probe_at,
                    "cooldown_s": b.cooldown_s,
                    "half_open_probes": b.half_open_probes,
                }
                for nid in self._dirty
                if (b := self._breakers.get(nid)) is not None
            ]
            self._dirty.clear()
            return rows

    def requeue(self, rows: Iterable[Mapping[str, Any]]) -> None:
        with self._lock:
            self._dirty.update(r["node_id"] for r in rows)

    def load(self, rows: Iterable[Mapping[str, Any]]) -> int:
        n = 0
        with self._lock:
            for r in rows:
                self._breakers[r["node_id"]] = Breaker(
                    r["node_id"],
                    r["state"],
                    r["opened_at"],
                    r["cooldown_until"],
                    r["reason"],
                    int(r["probes_used"]),
                    r["last_probe_at"],
                    int(r["cooldown_s"]),
                    int(r["half_open_probes"]),
                )
                n += 1
        return n
