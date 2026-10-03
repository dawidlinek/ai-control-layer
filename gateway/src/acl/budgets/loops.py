"""Loop / runaway bookkeeping for SEC-LOOP-01 (concept §8).

In memory, per session (the session id is already principal-namespaced). Mutated only from the flow hooks
(`on_commit`), read by the control's `inspect()`.

* repeated (tool, args-hash) calls with their result hashes → "same call N times" and the coding-agent
  "same failing test, same fix" pattern (identical call, identical result, repeated);
* input tokens per ingress step → context-growth signal.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from acl.contracts.canonical import canonical_json

Clock = Callable[[], float]
MAX_CALLS = 400
MAX_INPUTS = 32


def args_key(tool: str, arguments: dict[str, Any]) -> str:
    """Stable (tool, args) fingerprint. Arguments are hashed, never stored."""
    return hashlib.sha256(canonical_json({"t": tool, "a": arguments}).encode("utf-8")).hexdigest()[:24]


def result_hash(content: str) -> str:
    return hashlib.sha256(content.encode("utf-8", "replace")).hexdigest()[:24]


@dataclass
class CallRecord:
    ts: float
    key: str
    tool: str
    call_id: str | None
    result: str | None = None


@dataclass
class _Session:
    calls: deque[CallRecord] = field(default_factory=lambda: deque(maxlen=MAX_CALLS))
    inputs: deque[int] = field(default_factory=lambda: deque(maxlen=MAX_INPUTS))
    last_seen: float = 0.0


@dataclass(frozen=True)
class RepeatInfo:
    count: int  # earlier identical calls inside the window
    results: list[str | None]  # their result hashes (oldest first), None = not reported yet


class LoopTracker:
    def __init__(self, clock: Clock = time.time, *, max_sessions: int = 20_000, ttl_s: float = 8 * 3600) -> None:
        self.clock = clock
        self.max_sessions = max_sessions
        self.ttl_s = ttl_s
        self._lock = threading.RLock()
        self._sessions: OrderedDict[str, _Session] = OrderedDict()

    def _get(self, session_id: str, create: bool) -> _Session | None:
        s = self._sessions.get(session_id)
        if s is None and create:
            s = self._sessions[session_id] = _Session()
            while len(self._sessions) > self.max_sessions:
                self._sessions.popitem(last=False)
        if s is not None:
            s.last_seen = self.clock()
            self._sessions.move_to_end(session_id)
        return s

    # ------------------------------------------------------------ writes (hooks only)

    def record_call(self, session_id: str, key: str, tool: str, call_id: str | None) -> None:
        with self._lock:
            s = self._get(session_id, True)
            assert s is not None
            s.calls.append(CallRecord(self.clock(), key, tool, call_id))

    def record_result(self, session_id: str, tool: str, call_id: str | None, content: str) -> None:
        """Attach a tool result to its call (by tool_call_id, else the latest call of that tool without one)."""
        with self._lock:
            s = self._get(session_id, False)
            if s is None:
                return
            for rec in reversed(s.calls):
                if rec.result is None and ((call_id and rec.call_id == call_id) or (not call_id and rec.tool == tool)):
                    rec.result = result_hash(content)
                    return

    def record_input(self, session_id: str, tokens: int) -> None:
        with self._lock:
            s = self._get(session_id, True)
            assert s is not None
            s.inputs.append(tokens)

    # ------------------------------------------------------------ reads

    def repeats(self, session_id: str, key: str, window_s: float) -> RepeatInfo:
        with self._lock:
            s = self._sessions.get(session_id)
            if s is None:
                return RepeatInfo(0, [])
            cutoff = self.clock() - window_s
            hits = [r for r in s.calls if r.key == key and r.ts >= cutoff]
            return RepeatInfo(len(hits), [r.result for r in hits])

    def inputs(self, session_id: str) -> list[int]:
        with self._lock:
            s = self._sessions.get(session_id)
            return list(s.inputs) if s else []
