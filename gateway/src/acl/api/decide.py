"""`/v1/decide` + client-side approvals. Owner: Phase 2B (orchestrator reviews closely)."""

from __future__ import annotations

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, PrincipalDep, not_implemented
from acl.contracts.decide import ApprovalDecisionRequest, ApprovalStatusResponse, DecideRequest, DecideResponse

router = APIRouter(prefix="/v1", tags=["decide"], responses=ERROR_RESPONSES)


@router.post("/decide", response_model=DecideResponse, operation_id="decide")
async def decide(body: DecideRequest, principal: PrincipalDep) -> DecideResponse:
    """Ask whether a client-local action (tool call) may run. Fail closed on any error."""
    not_implemented("decide")


@router.get("/approvals/{approval_id}", response_model=ApprovalStatusResponse, operation_id="getApproval")
async def get_approval(approval_id: str, principal: PrincipalDep) -> ApprovalStatusResponse:
    """Poll an approval created by a `require_approval` decision (only the requester or an admin)."""
    not_implemented("approvals")


@router.post(
    "/approvals/{approval_id}/decision", response_model=ApprovalStatusResponse, operation_id="decideApprovalAsUser"
)
async def decide_as_user(
    approval_id: str, body: ApprovalDecisionRequest, principal: PrincipalDep
) -> ApprovalStatusResponse:
    """User-level approval (approver_scope=user only). Admin-scope approvals require the admin API."""
    not_implemented("approvals")
