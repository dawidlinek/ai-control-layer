"""Periodic flush of the in-memory ledger / breakers to the database and reload on startup."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from acl.budgets.breaker import BreakerBook
from acl.budgets.db_models import BudgetBreakerRow, BudgetCounterRow, BudgetNodeRow
from acl.budgets.ledger import DirtyBatch, Ledger

log = logging.getLogger(__name__)

SESSION_ROW_TTL_S = 24 * 3600


class BudgetStore:
    def __init__(self, sessions: async_sessionmaker[AsyncSession], ledger: Ledger, breakers: BreakerBook) -> None:
        self.sessions = sessions
        self.ledger = ledger
        self.breakers = breakers
        self._task: asyncio.Task[None] | None = None
        self._flush_lock = asyncio.Lock()

    async def load(self) -> tuple[int, int]:
        """Restore counters (current windows only) and breakers. Returns (counters, breakers)."""
        async with self.sessions() as s:
            nodes = [
                {
                    "node_id": r.node_id,
                    "level": r.level,
                    "parent": r.parent,
                    "first_seen": r.first_seen,
                    "last_seen": r.last_seen,
                }
                for r in (await s.execute(select(BudgetNodeRow))).scalars()
            ]
            counters = [
                {
                    "node_id": r.node_id,
                    "meter": r.meter,
                    "window": r.window,
                    "value": r.value,
                    "soft_notified": r.soft_notified,
                    "hard_notified": r.hard_notified,
                }
                for r in (await s.execute(select(BudgetCounterRow))).scalars()
            ]
            breakers = [
                {
                    "node_id": r.node_id,
                    "state": r.state,
                    "opened_at": r.opened_at,
                    "cooldown_until": r.cooldown_until,
                    "reason": r.reason,
                    "probes_used": r.probes_used,
                    "last_probe_at": r.last_probe_at,
                    "cooldown_s": r.cooldown_s,
                    "half_open_probes": r.half_open_probes,
                }
                for r in (await s.execute(select(BudgetBreakerRow))).scalars()
            ]
        return self.ledger.load(nodes, counters), self.breakers.load(breakers)

    async def flush(self) -> int:
        """Write dirty rows. A failure re-queues them (the ledger keeps counting in memory)."""
        async with self._flush_lock:
            batch: DirtyBatch = self.ledger.export_dirty()
            breaker_rows: list[dict[str, Any]] = self.breakers.export_dirty()
            if not batch and not breaker_rows:
                return 0
            try:
                async with self.sessions() as s:
                    for n in batch.nodes:
                        await s.merge(BudgetNodeRow(**n))
                    for c in batch.counters:
                        await s.merge(BudgetCounterRow(**c))
                    for b in breaker_rows:
                        await s.merge(BudgetBreakerRow(**b))
                    await s.commit()
            except Exception:
                log.exception("budget ledger flush failed; will retry")
                self.ledger.requeue(batch)
                self.breakers.requeue(breaker_rows)
                return 0
            return len(batch.nodes) + len(batch.counters) + len(breaker_rows)

    async def prune(self, now: float) -> None:
        """Drop persisted session rows that outlived their TTL (the ledger evicts them in memory too)."""
        cutoff = now - SESSION_ROW_TTL_S
        try:
            async with self.sessions() as s:
                stale = (
                    await s.execute(
                        select(BudgetNodeRow.node_id).where(
                            BudgetNodeRow.level == "session", BudgetNodeRow.last_seen < cutoff
                        )
                    )
                ).scalars()
                ids = list(stale)
                if ids:
                    await s.execute(delete(BudgetCounterRow).where(BudgetCounterRow.node_id.in_(ids)))
                    await s.execute(delete(BudgetNodeRow).where(BudgetNodeRow.node_id.in_(ids)))
                    await s.commit()
        except Exception:
            log.exception("budget ledger prune failed")

    def start(self, interval_s: float = 5.0) -> None:
        async def loop() -> None:
            ticks = 0
            while True:
                await asyncio.sleep(interval_s)
                await self.flush()
                ticks += 1
                if ticks % 720 == 0:
                    await self.prune(self.ledger.clock())

        self._task = asyncio.get_running_loop().create_task(loop(), name="budget-flush")

    async def stop(self) -> None:
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task
            self._task = None
        await self.flush()
