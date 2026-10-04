"""Installer: `InsightsService` at `app.state.insights` plus the background recompute worker (concept §14).

Deterministic mode (tests, demo without a model server) embeds with `HashingEmbedder` and drafts deterministically;
otherwise embeddings and drafts go to the policy's local models through the gateway connectors.
Admin routes live in `acl.api.admin.insights`.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from acl.contracts.admin import ErrorResponse
from acl.insights.config import InsightsOptions
from acl.insights.draft import ConnectorCompleter
from acl.insights.embed import ConnectorEmbedder, Embedder, HashingEmbedder
from acl.insights.service import InsightsApiError, InsightsService
from acl.settings import Settings

log = logging.getLogger(__name__)


async def _handle(_: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, InsightsApiError)
    body = ErrorResponse(error=exc.code, message=exc.message, details=exc.details)
    return JSONResponse(body.model_dump(mode="json"), status_code=exc.status_code)


def install(app: FastAPI, settings: Settings) -> None:
    options = InsightsOptions()
    embedder: Embedder = HashingEmbedder() if settings.deterministic else ConnectorEmbedder(app)
    complete = None if settings.deterministic or not options.draft_with_llm else ConnectorCompleter(app)
    service = InsightsService(app, options, embedder, complete)
    app.state.insights = service
    app.add_exception_handler(InsightsApiError, _handle)
    task: asyncio.Task[None] | None = None

    async def loop() -> None:
        await asyncio.sleep(options.initial_delay_s)
        trigger = "startup"
        while True:
            if getattr(app.state, "engine", None) is not None:
                await service.recompute(trigger)  # type: ignore[arg-type]
                trigger = "interval"
            await asyncio.sleep(options.interval_s if trigger == "interval" else 5.0)

    async def start(app: FastAPI) -> None:
        nonlocal task
        if options.worker:
            task = asyncio.create_task(loop(), name="insights-worker")

    async def stop(app: FastAPI) -> None:
        if task is not None:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
