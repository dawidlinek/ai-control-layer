"""Installs the gateway request path: connector registry, replay buffer, `/v1` routes, error handlers.

State exposed on the app:
    app.state.connectors      ConnectorRegistry (kill switch, health, per-policy routing tables)
    app.state.replay_buffer   ReplayBuffer (real traffic for policy dry-run, in memory only)
"""

from __future__ import annotations

from fastapi import FastAPI

from acl.api.errors import install_error_handlers
from acl.api.openai import router as openai_router
from acl.engine.replay import ReplayBuffer
from acl.routing.registry import ConnectorRegistry
from acl.settings import Settings


def install(app: FastAPI, settings: Settings) -> None:
    app.state.replay_buffer = ReplayBuffer(maxlen=2000)
    app.state.connectors = ConnectorRegistry(deterministic=settings.deterministic)
    install_error_handlers(app)
    app.include_router(openai_router)

    async def stop(app: FastAPI) -> None:
        await app.state.connectors.aclose()

    app.state.on_shutdown.append(stop)
