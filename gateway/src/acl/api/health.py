from __future__ import annotations

from fastapi import APIRouter, Request

from acl import __version__
from acl.contracts.admin import Health

router = APIRouter(tags=["health"])


@router.get("/healthz", response_model=Health, operation_id="healthz")
async def healthz() -> Health:
    """Liveness: the process is up."""
    return Health(status="ok", version=__version__)


# Control types whose security depends on an app-wired service: a missing service would silently weaken them.
_REQUIRED_SERVICES = {"model_access": "access", "pii": "vault", "signatures": "signatures"}


@router.get("/readyz", response_model=Health, operation_id="readyz")
async def readyz(request: Request) -> Health:
    """Readiness: a policy is loaded, the engine is built and every service its controls rely on is wired."""
    engine = getattr(request.app.state, "engine", None)
    checks = {"policy": f"v{engine.policy_version}" if engine else "not loaded"}
    ok = engine is not None
    if engine is not None:
        deps = request.app.state.control_deps
        for control in engine.policy.controls:
            service = _REQUIRED_SERVICES.get(control.type)
            if control.enabled and service is not None:
                present = deps.get(service) is not None
                checks[f"service:{service}"] = "ok" if present else f"missing (needed by {control.id})"
                ok = ok and present
        checks["audit"] = "ok" if getattr(request.app.state, "audit", None) is not None else "missing"
        ok = ok and checks["audit"] == "ok"
    return Health(status="ok" if ok else "down", version=__version__, checks=checks)
