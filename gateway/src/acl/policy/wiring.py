"""Installer: `PolicyService` at `app.state.policy_service`, started/stopped with the app (concept §11.1).

The admin routes live in `acl.api.admin.policy` (already mounted); this only provides the service behind them.
Startup loads `settings.policy_dir` and sets `app.state.engine`; the watcher then keeps it current.
"""

from __future__ import annotations

from fastapi import FastAPI

from acl.policy.config import PolicyOptions
from acl.policy.errors import PolicyServiceError, handle_policy_error
from acl.policy.service import PolicyService
from acl.policy.source import FileSource
from acl.policy.writer import PolicyWriter
from acl.settings import Settings


def install(app: FastAPI, settings: Settings) -> None:
    options = PolicyOptions()
    source = FileSource(
        settings.policy_dir,
        force_polling=options.effective_force_polling(),
        poll_delay_ms=options.poll_delay_ms,
        debounce_ms=options.debounce_ms,
        step_ms=options.step_ms,
        rescan_interval_s=options.rescan_interval_s,
    )
    service = PolicyService(app, source, options)
    app.state.policy_service = service
    app.state.policy_writer = PolicyWriter(service)
    app.add_exception_handler(PolicyServiceError, handle_policy_error)

    async def start(app: FastAPI) -> None:
        await service.start()

    async def stop(app: FastAPI) -> None:
        await service.stop()

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
