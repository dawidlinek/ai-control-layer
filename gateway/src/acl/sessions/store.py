"""Session store seam (orchestrator-owned).

Session ids are already namespaced by principal (`api.chat_flow.session_key`), so a store keyed by the
session id never mixes principals. Labels only ever rise here (monotonic): `merge_labels` is the single
place that combines them. Phase 2 uses the in-memory store; a Postgres/Redis store can implement the same
protocol for multi-replica deployments.
"""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable
from typing import Protocol

from acl.contracts.common import DATA_CLASS_ORDER, Integrity
from acl.contracts.inspection import SessionLabels, SessionState


def merge_labels(a: SessionLabels, b: SessionLabels) -> SessionLabels:
    """Monotonic join: untrusted wins, the higher data class wins, taint flags and sources accumulate."""
    integrity = Integrity.untrusted if Integrity.untrusted in (a.integrity, b.integrity) else Integrity.trusted
    conf = max(a.confidentiality, b.confidentiality, key=lambda c: DATA_CLASS_ORDER[c])
    taint = list(dict.fromkeys([*a.taint, *b.taint]))
    sources = list(dict.fromkeys([*a.sources, *b.sources]))[-50:]
    return SessionLabels(integrity=integrity, confidentiality=conf, taint=taint, sources=sources)


class SessionStore(Protocol):
    async def load(self, session_id: str) -> SessionState: ...

    async def update(self, session_id: str, fn: Callable[[SessionState], SessionState]) -> SessionState:
        """Atomically read-modify-write one session (serialised per session id)."""
        ...


class InMemorySessionStore:
    def __init__(self, ttl_s: float = 8 * 3600, max_sessions: int = 50_000) -> None:
        self.ttl_s = ttl_s
        self.max_sessions = max_sessions
        self._data: OrderedDict[str, tuple[float, SessionState]] = OrderedDict()
        self._locks: dict[str, asyncio.Lock] = {}

    def _get(self, session_id: str) -> SessionState:
        item = self._data.get(session_id)
        if item is None or item[0] < time.monotonic():
            return SessionState(session_id=session_id)
        return item[1].model_copy(deep=True)

    async def load(self, session_id: str) -> SessionState:
        return self._get(session_id)

    async def update(self, session_id: str, fn: Callable[[SessionState], SessionState]) -> SessionState:
        lock = self._locks.setdefault(session_id, asyncio.Lock())
        async with lock:
            new = fn(self._get(session_id))
            self._data[session_id] = (time.monotonic() + self.ttl_s, new.model_copy(deep=True))
            self._data.move_to_end(session_id)
            while len(self._data) > self.max_sessions:
                old, _ = self._data.popitem(last=False)
                self._locks.pop(old, None)
            return new
