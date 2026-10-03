"""Session-scoped pseudonymisation vault (concept §6.3).

Placeholders look like `<PESEL_1>`. The vault maps placeholder → original value *per session* and lives
in memory only (TTL + size bound). It is never logged; `repr()` shows counts only.

Side-effect-free inspection: `PiiControl.inspect()` calls `plan()`, which is a pure function of the
vault's current state and the values found in the payload (existing values keep their placeholder, new
values get the next free number in order of appearance). Nothing is stored until the request flow
calls `Control.commit()` after the decision was enforced, which calls `register()`. Dry-run/replay
therefore never touches the vault. `placeholder_for()` is the mutating convenience (plan + register)
for callers outside the inspect/commit flow.

Two concurrent requests of one session may plan the same number for different values; at `register()`
the later value gets a fresh number and the contested placeholder is marked ambiguous, which `restore()`
leaves untouched (it never guesses).
"""

from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z0-9]*(?:_[A-Z][A-Z0-9]*)*)_(\d{1,6})>")
_AMBIGUOUS = object()


@dataclass
class _Session:
    expires: float
    by_key: dict[tuple[str, str], str] = field(default_factory=dict)  # (type, canonical) -> placeholder
    by_placeholder: dict[str, object] = field(default_factory=dict)  # placeholder -> original text | _AMBIGUOUS
    counts: dict[str, int] = field(default_factory=dict)  # type -> highest number issued


@dataclass(frozen=True, slots=True)
class Planned:
    entity_type: str
    key: str  # canonical identity of the value
    original: str  # the text as it appeared (restored verbatim)
    placeholder: str


def placeholder_name(entity_type: str, n: int) -> str:
    return f"<{entity_type}_{n}>"


class PseudonymVault:
    def __init__(
        self,
        ttl_s: float = 3600.0,
        max_sessions: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.ttl_s = ttl_s
        self.max_sessions = max_sessions
        self._clock = clock
        self._sessions: OrderedDict[str, _Session] = OrderedDict()
        self._lock = threading.Lock()

    def __repr__(self) -> str:  # never expose contents
        return f"PseudonymVault(sessions={len(self._sessions)}, ttl_s={self.ttl_s})"

    # ------------------------------------------------------------------ internals

    def _purge(self, now: float) -> None:
        expired = [sid for sid, s in self._sessions.items() if s.expires <= now]
        for sid in expired:
            del self._sessions[sid]
        while len(self._sessions) > self.max_sessions:
            self._sessions.popitem(last=False)

    def _get(self, session_id: str, *, create: bool) -> _Session | None:
        now = self._clock()
        self._purge(now)
        s = self._sessions.get(session_id)
        if s is None:
            if not create:
                return None
            s = _Session(expires=now + self.ttl_s)
            self._sessions[session_id] = s
        else:
            s.expires = now + self.ttl_s
            self._sessions.move_to_end(session_id)
        return s

    # ------------------------------------------------------------------ pure planning (no mutation)

    def plan(self, session_id: str, items: Iterable[tuple[str, str, str]]) -> list[Planned]:
        """Placeholders for (entity_type, canonical_key, original) triples, without storing anything."""
        with self._lock:
            s = self._sessions.get(session_id)
            if s is not None and s.expires <= self._clock():
                s = None
            counts = dict(s.counts) if s else {}
            known = dict(s.by_key) if s else {}
        out: list[Planned] = []
        for etype, key, original in items:
            ph = known.get((etype, key))
            if ph is None:
                counts[etype] = counts.get(etype, 0) + 1
                ph = placeholder_name(etype, counts[etype])
                known[(etype, key)] = ph
            out.append(Planned(etype, key, original, ph))
        return out

    # ------------------------------------------------------------------ mutation

    def register(self, session_id: str, planned: Iterable[Planned]) -> None:
        """Store planned placeholders (called from `commit` after the decision was enforced)."""
        with self._lock:
            s = self._get(session_id, create=True)
            assert s is not None
            for p in planned:
                existing = s.by_key.get((p.entity_type, p.key))
                if existing is not None:
                    continue
                ph = p.placeholder
                owner = s.by_placeholder.get(ph)
                if owner is not None and owner != p.original:
                    # contested number (concurrent requests): never restore it, give this value a new one
                    s.by_placeholder[ph] = _AMBIGUOUS
                    n = s.counts.get(p.entity_type, 0) + 1
                    ph = placeholder_name(p.entity_type, n)
                s.by_key[(p.entity_type, p.key)] = ph
                s.by_placeholder.setdefault(ph, p.original)
                m = PLACEHOLDER_RE.fullmatch(ph)
                if m:
                    s.counts[p.entity_type] = max(s.counts.get(p.entity_type, 0), int(m.group(2)))

    def placeholder_for(self, session_id: str, entity_type: str, value: str, key: str | None = None) -> str:
        """Consistent placeholder for `value` in this session (registers it)."""
        planned = self.plan(session_id, [(entity_type, key or value, value)])
        self.register(session_id, planned)
        with self._lock:
            s = self._sessions.get(session_id)
            return s.by_key[(entity_type, key or value)] if s else planned[0].placeholder

    def restore(self, session_id: str, text: str, *, allowed_entity_types: set[str]) -> str:
        """Replace this session's placeholders of allow-listed types by their original values.

        Unknown, foreign-session, ambiguous or non-allow-listed placeholders are left untouched.
        """
        if not allowed_entity_types or "<" not in text:
            return text
        with self._lock:
            s = self._get(session_id, create=False)
            if s is None:
                return text
            mapping = dict(s.by_placeholder)

        def repl(m: re.Match[str]) -> str:
            if m.group(1) not in allowed_entity_types:
                return m.group(0)
            val = mapping.get(m.group(0))
            return val if isinstance(val, str) else m.group(0)

        return PLACEHOLDER_RE.sub(repl, text)

    def placeholders(self, session_id: str) -> set[str]:
        with self._lock:
            s = self._get(session_id, create=False)
            return set(s.by_placeholder) if s else set()

    def forget(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
