from __future__ import annotations

from fastapi import APIRouter, Request

from acl import __version__
from acl.contracts.admin import Health

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=Health, operation_id="healthz")
async def healthz() -> Health:
    """Liveness: the process is up."""
    return Health(status="ok", version=__version__)


@router.get("/readyz", response_model=Health, operation_id="readyz")
async def readyz(request: Request) -> Health:
    """Readiness: a policy is loaded and the engine is built."""
    engine = getattr(request.app.state, "engine", None)
    checks = {"policy": f"v{engine.policy_version}" if engine else "not loaded"}
    return Health(status="ok" if engine else "down", version=__version__, checks=checks)
