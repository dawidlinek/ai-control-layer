"""ASGI app factory. `uvicorn acl.main:app`."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from acl import __version__
from acl.api import admin, decide, health
from acl.engine.engine import Engine
from acl.policy.loader import PolicyLoadError, load_policy_dir
from acl.settings import Settings, get_settings

log = logging.getLogger("acl")


def create_app(settings: Settings | None = None, *, allow_anonymous_dev: bool = False) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(level=settings.log_level)
        try:
            loaded = load_policy_dir(settings.policy_dir)
            app.state.engine = Engine.build(loaded.policy, loaded.version)
            log.info("policy %s loaded from %s", loaded.version, settings.policy_dir)
        except PolicyLoadError as exc:
            # No last-good version exists at startup: stay up but not ready (readyz = down).
            log.error("policy load failed: %s", exc)
            app.state.engine = None
        yield
        if app.state.engine is not None:
            await app.state.engine.aclose()

    app = FastAPI(
        title="AI Control Layer Gateway",
        version=__version__,
        lifespan=lifespan,
        description="OpenAI-compatible AI gateway with policy enforcement, plus decide and admin APIs.",
    )
    app.state.settings = settings
    app.state.allow_anonymous_dev = allow_anonymous_dev
    app.state.engine = None
    app.include_router(health.router)
    app.include_router(decide.router)
    app.include_router(admin.router)
    return app


app = create_app()
