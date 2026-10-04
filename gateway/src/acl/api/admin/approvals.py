"""Admin: approvals (owner: Phase 2B). Route signatures are the contract.

The queue holds every `require_approval` decision of `/v1/decide` and the MCP proxy. Viewers may read it, analysts
and admins decide (`user`- and `admin`-scope alike); a decision can carry a time-boxed elevation for the call's tool
in that session (SEC-TOOL-01 stops asking while it lasts; it never lifts a block or the Rule of Two). Every decision
is written to the audit log by the approval service. (Docstrings are part of the OpenAPI contract: keep them as is.)
"""

from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi import status as http_status

from acl.api.admin.paging import TOTAL_COUNT_RESPONSES, set_total
from acl.api.deps import ERROR_RESPONSES, Analyst, Viewer
from acl.approvals.service import ApprovalError, ApprovalService
from acl.contracts.admin import (
    Approval,
)
from acl.contracts.common import ApprovalStatus
from acl.contracts.decide import ApprovalDecisionRequest

router = APIRouter(responses=ERROR_RESPONSES)

# ---------------------------------------------------------------- approvals (2B)


def _service(request: Request) -> ApprovalService:
    svc = getattr(request.app.state, "approvals", None)
    if svc is None:
        raise HTTPException(http_status.HTTP_503_SERVICE_UNAVAILABLE, detail="approvals are not available")
    return svc


@router.get(
    "/approvals",
    response_model=list[Approval],
    tags=["approvals"],
    operation_id="listApprovals",
    responses=TOTAL_COUNT_RESPONSES,
)
async def list_approvals(
    request: Request, response: Response, p: Viewer, status: ApprovalStatus | None = ApprovalStatus.pending
) -> list[Approval]:
    rows, total = await _service(request).list_page(status)
    set_total(response, total)
    return rows


@router.get("/approvals/{approval_id}", response_model=Approval, tags=["approvals"], operation_id="getApprovalAdmin")
async def get_approval(approval_id: str, request: Request, p: Viewer) -> Approval:
    try:
        return await _service(request).get(approval_id)
    except ApprovalError as exc:
        raise HTTPException(exc.status_code, detail=str(exc)) from exc


@router.post(
    "/approvals/{approval_id}/decision", response_model=Approval, tags=["approvals"], operation_id="decideApproval"
)
async def decide_approval(approval_id: str, body: ApprovalDecisionRequest, request: Request, p: Analyst) -> Approval:
    """Approve (optionally with time-boxed elevation) or deny. Audited."""
    try:
        return await _service(request).decide(
            approval_id,
            approve=body.decision == "approve",
            actor=p,
            elevation_minutes=body.elevation_minutes,
            note=body.note,
        )
    except ApprovalError as exc:
        raise HTTPException(exc.status_code, detail=str(exc)) from exc
