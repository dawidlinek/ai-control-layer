"""Installs the budget service: ledger + breakers + loop tracker, flow hooks, control service `"budgets"`.

app.state.budgets                 BudgetService (ledger, breakers, loops, `charge_guard()` for Phase 3 judges)
app.state.flow_hooks              += the service (`on_commit`, `on_usage`)
control service "budgets"         read by SEC-BUDGET-01 / SEC-LOOP-01
startup / shutdown                reload counters + breakers from the DB, flush every few seconds
"""

from __future__ import annotations

import logging

from fastapi import FastAPI

from acl.budgets.service import BudgetService
from acl.budgets.store import BudgetStore
from acl.settings import Settings

log = logging.getLogger(__name__)

FLUSH_INTERVAL_S = 5.0


def install(app: FastAPI, settings: Settings) -> None:
    service = BudgetService(
        lambda: app.state.engine.policy if getattr(app.state, "engine", None) is not None else None,
        audit_provider=lambda: getattr(app.state, "audit", None),
    )
    app.state.budgets = service
    app.state.control_deps.register("budgets", service)
    if not hasattr(app.state, "flow_hooks"):
        app.state.flow_hooks = []
    app.state.flow_hooks.append(service)

    async def start(app: FastAPI) -> None:
        store = BudgetStore(app.state.db, service.ledger, service.breakers)
        try:
            counters, breakers = await store.load()
            log.info("budget ledger restored: %d counters, %d breakers", counters, breakers)
        except Exception:
            log.exception("could not reload the budget ledger; starting empty")
        service.store = store
        store.start(FLUSH_INTERVAL_S)

    async def stop(app: FastAPI) -> None:
        if service.store is not None:
            await service.store.stop()

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
