"""Admin: budgets (owner: Phase 2D). Route signatures are the contract."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, status

from acl.api.deps import ERROR_RESPONSES, Admin, Viewer
from acl.budgets.service import BudgetService
from acl.contracts.admin import (
    BreakerState,
    BudgetTree,
)
from acl.contracts.audit import EventType
from acl.contracts.common import Severity

router = APIRouter(responses=ERROR_RESPONSES)


def _service(request: Request) -> BudgetService:
    service = getattr(request.app.state, "budgets", None)
    if service is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="the budget service is not running")
    return service


# ---------------------------------------------------------------- budgets (2D)


@router.get("/budgets", response_model=BudgetTree, tags=["budgets"], operation_id="getBudgets")
async def budgets(request: Request, p: Viewer) -> BudgetTree:
    # budget tree (org → group → user → agent → session) with limits, live usage and breaker state
    return _service(request).tree()


@router.get("/budgets/breakers", response_model=list[BreakerState], tags=["budgets"], operation_id="listBreakers")
async def breakers(request: Request, p: Viewer) -> list[BreakerState]:
    return _service(request).list_breakers()


@router.post(
    "/budgets/breakers/{breaker_id}/reset", response_model=BreakerState, tags=["budgets"], operation_id="resetBreaker"
)
async def reset_breaker(breaker_id: str, request: Request, p: Admin) -> BreakerState:
    state = _service(request).reset_breaker(breaker_id)
    if state is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail=f"no circuit breaker for {breaker_id!r}")
    audit = getattr(request.app.state, "audit", None)
    if audit is not None:
        await audit.record_event(
            EventType.system_alert,
            severity=Severity.low,
            detail={"event": "breaker_reset", "breaker": breaker_id, "by": p.username or p.subject},
            principal=p,
        )
    return state
