"""ASGI app factory. `uvicorn acl.main:app`.

Integration seam (orchestrator-owned). Packages plug in through installers:

    # acl/<pkg>/wiring.py
    def install(app: FastAPI, settings: Settings) -> None:
        app.include_router(...)                       # routes
        app.state.on_startup.append(start_fn)         # async def start_fn(app) -> None
        app.state.on_shutdown.append(stop_fn)         # async def stop_fn(app) -> None
        app.state.control_deps.register("vault", ...) # services for controls

Startup order: DB → startup hooks in INSTALLERS order → initial engine build (only if no hook set
`app.state.engine`, e.g. the policy service). Rebuild the engine anywhere with
`app.state.build_engine(policy, version)`; swap by assigning `app.state.engine`.
"""

from __future__ import annotations

import importlib
import logging
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager

from fastapi import FastAPI

from acl import __version__
from acl.api import admin, decide, health
from acl.controls.base import ControlDeps
from acl.db import create_all, make_engine, make_sessionmaker
from acl.engine.engine import Engine
from acl.policy.loader import PolicyLoadError, load_policy_dir
from acl.policy.models import Policy
from acl.settings import Settings, get_settings

log = logging.getLogger("acl")

Hook = Callable[[FastAPI], Awaitable[None]]

# "module:function" installers, applied in order. Each phase adds its own line here.
INSTALLERS: list[str] = [
    "acl.audit.wiring:install",  # 1A: audit chain + index + SSE + /metrics (app.state.audit)
    "acl.api.wiring:install",  # 1A: connectors, replay buffer, /v1 chat/embeddings/models
    "acl.identity.wiring:install",  # 1C: authenticator, access resolver (control service "access")
    "acl.sessions.wiring:install",  # orchestrator: session store (labels, steps) + flow hooks list
    "acl.controls.pii.wiring:install",  # 1D: pseudonymisation vault (control service "vault")
    "acl.feed.wiring:install",  # 1D: signature store + feed sync (control service "signatures")
    "acl.budgets.wiring:install",  # 2D: budget ledger, breakers, loop tracker, flow hooks (service "budgets")
    "acl.mcp_proxy.wiring:install",  # 2A: MCP proxy `/mcp/{server_id}` + pinned tool manifests
    "acl.approvals.wiring:install",  # 2B: approvals queue + elevations (control service "approvals"), bypass detection
    "acl.insights.wiring:install",  # 4B: automation insights service + recompute worker (app.state.insights)
    "acl.policy.wiring:install",  # 1B: policy service builds/swaps the engine; keep last
]


def _load(spec: str) -> Callable[[FastAPI, Settings], None]:
    module, _, attr = spec.partition(":")
    return getattr(importlib.import_module(module), attr or "install")


def create_app(
    settings: Settings | None = None,
    *,
    allow_anonymous_dev: bool = False,
    installers: list[str] | None = None,
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=settings.log_level)
        db_engine = make_engine(settings.database_url)
        if settings.database_url.startswith("sqlite"):
            await create_all(db_engine)  # dev/tests; Postgres uses `python -m acl.migrate`
        app.state.db_engine = db_engine
        app.state.db = make_sessionmaker(db_engine)
        for hook in app.state.on_startup:
            await hook(app)
        if app.state.engine is None:
            try:
                loaded = load_policy_dir(settings.policy_dir)
                app.state.engine = app.state.build_engine(loaded.policy, loaded.version)
                log.info("policy %s loaded from %s", loaded.version, settings.policy_dir)
            except PolicyLoadError as exc:
                # No last-good version exists at startup: stay up but not ready (readyz = down).
                log.error("policy load failed: %s", exc)
        try:
            yield
        finally:
            for hook in reversed(app.state.on_shutdown):
                try:
                    await hook(app)
                except Exception:
                    log.exception("shutdown hook failed")
            if app.state.engine is not None:
                await app.state.engine.aclose()
            await db_engine.dispose()

    app = FastAPI(
        title="AI Control Layer Gateway",
        version=__version__,
        lifespan=lifespan,
        description="OpenAI-compatible AI gateway with policy enforcement, plus decide and admin APIs.",
    )
    app.state.settings = settings
    app.state.allow_anonymous_dev = allow_anonymous_dev
    app.state.engine = None
    app.state.control_deps = ControlDeps()
    app.state.on_startup = []
    app.state.on_shutdown = []

    def build_engine(policy: Policy, version: str) -> Engine:
        return Engine.build(policy, version, deps=app.state.control_deps)

    app.state.build_engine = build_engine
    app.include_router(health.router)
    app.include_router(decide.router)
    app.include_router(admin.router)
    for spec in INSTALLERS if installers is None else installers:
        _load(spec)(app, settings)
    return app


app = create_app()
