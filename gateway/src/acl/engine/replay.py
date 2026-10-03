"""In-memory replay buffer of real traffic for policy dry-run (Phase 1B consumes it).

Real requests only, bounded, never persisted: contexts carry raw content. Stored contexts are
deep copies with `attributes` reset so a replay starts from a clean slate.
"""

from __future__ import annotations

from collections import deque

from acl.contracts.common import InspectionPoint
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext


class ReplayBuffer:
    def __init__(self, maxlen: int = 2000) -> None:
        self._items: deque[tuple[InspectionContext, Decision]] = deque(maxlen=maxlen)

    def __len__(self) -> int:
        return len(self._items)

    def add(self, ctx: InspectionContext, decision: Decision) -> None:
        self._items.append((ctx.model_copy(update={"attributes": {}}, deep=True), decision))

    def recent(self, n: int, point: InspectionPoint | None = None) -> list[tuple[InspectionContext, Decision]]:
        """Most recent `n` (context, original decision) pairs, newest first, optionally of one point."""
        out: list[tuple[InspectionContext, Decision]] = []
        for ctx, decision in reversed(self._items):
            if point is None or ctx.point == point:
                out.append((ctx, decision))
                if len(out) >= n:
                    break
        return out

    def clear(self) -> None:
        self._items.clear()
