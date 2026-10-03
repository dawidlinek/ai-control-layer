"""Admin: approvals (owner: Phase 2B). Route signatures are the contract."""

from __future__ import annotations

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Analyst, Viewer, not_implemented
from acl.contracts.admin import (
    Approval,
)
from acl.contracts.common import ApprovalStatus
from acl.contracts.decide import ApprovalDecisionRequest

router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- approvals (2B)


@router.get("/approvals", response_model=list[Approval], tags=["approvals"], operation_id="listApprovals")
async def list_approvals(p: Viewer, status: ApprovalStatus | None = ApprovalStatus.pending) -> list[Approval]:
    not_implemented("approvals")


@router.get("/approvals/{approval_id}", response_model=Approval, tags=["approvals"], operation_id="getApprovalAdmin")
async def get_approval(approval_id: str, p: Viewer) -> Approval:
    not_implemented("approvals")


@router.post(
    "/approvals/{approval_id}/decision", response_model=Approval, tags=["approvals"], operation_id="decideApproval"
)
async def decide_approval(approval_id: str, body: ApprovalDecisionRequest, p: Analyst) -> Approval:
    """Approve (optionally with time-boxed elevation) or deny. Audited."""
    not_implemented("approvals")
