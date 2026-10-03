"""Installs the audit service: `app.state.audit`, `app.state.event_stream`, `app.state.metrics`, `/metrics`."""

from __future__ import annotations

import logging

from fastapi import APIRouter, FastAPI, Request, Response
from prometheus_client import CONTENT_TYPE_LATEST

from acl import __version__
from acl.audit.chain import AuditChain
from acl.audit.metrics import GatewayMetrics
from acl.audit.service import AuditService
from acl.audit.stream import EventStreamHub
from acl.contracts.common import Versions
from acl.settings import Settings

log = logging.getLogger(__name__)

metrics_router = APIRouter(tags=["metrics"], include_in_schema=False)


@metrics_router.get("/metrics")
async def prometheus_metrics(request: Request) -> Response:
    """Prometheus exposition (decisions, per-control latency, upstream latency, tokens, spend)."""
    metrics: GatewayMetrics = request.app.state.metrics
    return Response(metrics.render(), media_type=CONTENT_TYPE_LATEST)


def install(app: FastAPI, settings: Settings) -> None:
    app.state.event_stream = EventStreamHub()
    app.state.metrics = GatewayMetrics()
    app.include_router(metrics_router)

    async def start(app: FastAPI) -> None:
        if getattr(app.state, "audit", None) is not None:  # a test double (RecordingSink) was injected: keep it
            return
        chain = AuditChain(settings.audit_path)
        chain.resume()

        def versions() -> Versions:
            engine = app.state.engine
            return Versions(policy=engine.policy_version if engine is not None else "unknown", gateway=__version__)

        app.state.audit = AuditService(
            chain=chain,
            sessions=app.state.db,
            salt=settings.value_hash_salt.get_secret_value(),
            stream=app.state.event_stream,
            metrics=app.state.metrics,
            versions=versions,
        )
        head_seq, _ = chain.head
        log.info("audit log %s ready (head seq %s)", settings.audit_path, head_seq)
        app.state.audit_chain = chain

    async def stop(app: FastAPI) -> None:
        chain = getattr(app.state, "audit_chain", None)
        if chain is not None:
            chain.close()

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
