"""Admin: budgets (owner: Phase 2D). Route signatures are the contract."""

from __future__ import annotations

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Admin, Viewer, not_implemented
from acl.contracts.admin import (
    BreakerState,
    BudgetTree,
)

router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- budgets (2D)


@router.get("/budgets", response_model=BudgetTree, tags=["budgets"], operation_id="getBudgets")
async def budgets(p: Viewer) -> BudgetTree:
    not_implemented("budgets")


@router.get("/budgets/breakers", response_model=list[BreakerState], tags=["budgets"], operation_id="listBreakers")
async def breakers(p: Viewer) -> list[BreakerState]:
    not_implemented("breakers")


@router.post(
    "/budgets/breakers/{breaker_id}/reset", response_model=BreakerState, tags=["budgets"], operation_id="resetBreaker"
)
async def reset_breaker(breaker_id: str, p: Admin) -> BreakerState:
    not_implemented("breakers")
