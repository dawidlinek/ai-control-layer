"""`/v1/decide` + client-side approvals. Owner: Phase 2B (orchestrator reviews closely).

`/v1/decide` evaluates a client-local tool call through the same engine path as chat and MCP traffic
(`acl.engine.actions.evaluate_point`): session labels, SEC-TOOL-01, SEC-FLOW-01, signatures, secrets, PII, audit and
commit hooks. The response maps the decision onto what the plugin can enforce:

    allow / monitor            run the tool
    redact                     run the tool with `modified_arguments` (a redact/pseudonymise verdict rewrote them)
    require_approval           do not run; poll `GET /v1/approvals/{id}` (user scope) or wait for an administrator
    block / anything else      do not run

Fail closed: any internal error (engine, audit, approvals, redaction) answers `block` with rule `SEC-DECIDE-01`.
Only `allow`, `monitor` and `redact` mean "run"; the contract tells clients to treat every other action as not allowed.
(Route docstrings are part of the generated OpenAPI contract: keep them byte-identical, document here instead.)
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from fastapi import APIRouter, HTTPException, Request, status

from acl.api.deps import ERROR_RESPONSES, PrincipalDep
from acl.approvals.preview import build_preview
from acl.approvals.service import ApprovalError, ApprovalService, approver_scope_for, is_privileged
from acl.contracts.audit import EventType
from acl.contracts.common import Action, ApprovalStatus, InspectionPoint, Severity
from acl.contracts.decide import (
    ApprovalDecisionRequest,
    ApprovalStatusResponse,
    DecideRequest,
    DecideResponse,
    Elevation,
)
from acl.contracts.decision import Decision
from acl.contracts.inspection import InspectionContext, Principal, SessionLabels, ToolCallPayload
from acl.controls.tools.catalogue import downgrade_safe
from acl.engine.actions import evaluate_point
from acl.engine.text import apply_replacements
from acl.engine.transforms import transform_findings, unaddressable_fields

log = logging.getLogger(__name__)

router = APIRouter(prefix="/v1", tags=["decide"], responses=ERROR_RESPONSES)

RULE_DECIDE = "SEC-DECIDE-01"
RULE_REDACT = "ENG-REDACT-01"
RULE_CONFINED = "SEC-TOOL-01.CONFINED"
_RUN = {Action.allow, Action.monitor}
_TRANSFORMS = {Action.redact, Action.pseudonymise, Action.sanitize}


# ---------------------------------------------------------------- helpers


def _blocked(
    trace_id: str, policy_version: str, reason: str, rules: list[str] | None = None, decision: Decision | None = None
) -> DecideResponse:
    return DecideResponse(
        decision_id=decision.decision_id if decision else str(uuid.uuid4()),
        trace_id=trace_id,
        action=Action.block,
        rule_ids=rules or [RULE_DECIDE],
        reason=reason,
        risk_score=1.0,
        labels=decision.labels_after if decision else SessionLabels(),
        policy_version=policy_version,
    )


async def _alert(request: Request, principal: Principal, trace_id: str, exc: Exception) -> None:
    sink = getattr(request.app.state, "audit", None)
    if sink is None:
        return
    try:
        await sink.record_event(
            EventType.system_alert,
            severity=Severity.high,
            detail={"event": "decide_internal_error", "error": type(exc).__name__, "rule_id": RULE_DECIDE},
            principal=principal,
            trace_id=trace_id,
        )
    except Exception:
        log.exception("could not record decide system_alert")


def _modified_arguments(app: Any, ctx: InspectionContext, decision: Decision) -> dict[str, Any] | None:
    findings = transform_findings(app.state.engine, decision)
    if not findings:
        return None
    base = ctx.attributes.get("payload")
    if not isinstance(base, ToolCallPayload):
        base = ctx.payload
    unsafe = unaddressable_fields(base)
    if unsafe and any(f.field in unsafe for f in findings):
        raise ValueError("a sensitive span could not be located for redaction")
    out, skipped = apply_replacements(base, findings)
    if skipped:
        raise ValueError("overlapping sensitive spans could not be redacted safely")
    assert isinstance(out, ToolCallPayload)
    return out.arguments


async def _respond(request: Request, ctx: InspectionContext, decision: Decision) -> DecideResponse:
    app = request.app
    base = dict(
        decision_id=decision.decision_id,
        trace_id=decision.trace_id,
        rule_ids=list(decision.rule_ids),
        reason=decision.reason,
        risk_score=decision.risk_score,
        labels=decision.labels_after,
        policy_version=ctx.versions.policy,
    )
    action = decision.action
    applied = set(decision.applied)

    if action == Action.block:
        return DecideResponse(action=Action.block, **base)

    if action == Action.require_approval:
        svc = getattr(app.state, "approvals", None)
        if svc is None:
            raise RuntimeError("approval service is not available")
        payload = ctx.attributes.get("payload")
        if not isinstance(payload, ToolCallPayload):
            payload = ctx.payload
        assert isinstance(payload, ToolCallPayload)
        ref = await svc.create(
            ctx,
            decision,
            approver_scope=approver_scope_for(app.state.engine, decision),
            preview=build_preview(payload, why=decision.reason),
        )
        return DecideResponse(action=Action.require_approval, approval=ref, **base)

    if action not in _RUN | _TRANSFORMS | {Action.downgrade}:
        # route_local / anything the plugin cannot enforce at a tool call: not allowed (fail closed)
        return _blocked(
            decision.trace_id, ctx.versions.policy, f"action {action.value} cannot be enforced here", decision=decision
        )

    if action == Action.downgrade or Action.downgrade in applied:
        tool = app.state.engine.policy.tools.get(ctx.payload.tool) if isinstance(ctx.payload, ToolCallPayload) else None  # type: ignore[call-overload]
        if tool is None or not downgrade_safe(tool):
            return _blocked(
                decision.trace_id,
                ctx.versions.policy,
                "session is downgraded: irreversible, exec and external-egress tools are not available",
                [*decision.rule_ids, RULE_CONFINED],
                decision,
            )

    modified = None
    if action in _TRANSFORMS or applied & _TRANSFORMS:
        modified = _modified_arguments(app, ctx, decision)
    if modified is not None:
        return DecideResponse(action=Action.redact, modified_arguments=modified, **base)
    if action in _TRANSFORMS:  # a transform without addressable findings changed nothing: nothing to run safely
        return _blocked(
            decision.trace_id, ctx.versions.policy, "redaction produced no usable arguments", [RULE_REDACT], decision
        )
    return DecideResponse(action=Action.monitor if action == Action.monitor else Action.allow, **base)


def _service(request: Request) -> ApprovalService:
    svc = getattr(request.app.state, "approvals", None)
    if svc is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="approvals are not available")
    return svc


def _http(exc: ApprovalError) -> HTTPException:
    return HTTPException(exc.status_code, detail=str(exc))


def _status_response(svc: ApprovalService, row: Any) -> ApprovalStatusResponse:
    approval = svc.to_contract(row)
    return ApprovalStatusResponse(
        approval_id=row.id,
        status=ApprovalStatus(row.status),
        tool=row.tool,
        rule_ids=list(row.rule_ids or []),
        reason=row.reason,
        decided_by=row.decided_by,
        decided_at=row.decided_at,
        expires_at=row.expires_at,
        elevation=Elevation(scope=approval.elevation.scope, until=approval.elevation.until)
        if approval.elevation
        else None,
        note=row.note,
    )


# ---------------------------------------------------------------- routes


@router.post("/decide", response_model=DecideResponse, operation_id="decide")
async def decide(body: DecideRequest, principal: PrincipalDep, request: Request) -> DecideResponse:
    """Ask whether a client-local action (tool call) may run. Fail closed on any error."""
    trace_id = uuid.uuid4().hex
    app = request.app
    engine = getattr(app.state, "engine", None)
    policy_version = engine.policy_version if engine is not None else "unavailable"
    try:
        a = body.action
        payload = ToolCallPayload(
            tool=a.tool,
            server=a.server,
            tool_call_id=a.tool_call_id,
            arguments=a.arguments,
            cwd=a.cwd,
            workspace_root=a.workspace_root,
        )
        ctx, decision = await evaluate_point(
            app,
            principal,
            point=InspectionPoint.tool_call,
            payload=payload,
            client_session=body.session_id,
            client=body.client,
            user_request=body.user_request,
            trace_id=trace_id,
        )
        return await _respond(request, ctx, decision)
    except Exception as exc:
        log.exception("decide failed (trace %s)", trace_id)
        await _alert(request, principal, trace_id, exc)
        return _blocked(trace_id, policy_version, "the decision could not be made; failing closed")


@router.get("/approvals/{approval_id}", response_model=ApprovalStatusResponse, operation_id="getApproval")
async def get_approval(approval_id: str, principal: PrincipalDep, request: Request) -> ApprovalStatusResponse:
    """Poll an approval created by a `require_approval` decision (only the requester or an admin)."""
    svc = _service(request)
    try:
        row = await svc.get_row(approval_id)
    except ApprovalError as exc:
        raise _http(exc) from exc
    if row.requester_subject != principal.subject and not is_privileged(principal):
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="not your approval")
    return _status_response(svc, row)


@router.post(
    "/approvals/{approval_id}/decision", response_model=ApprovalStatusResponse, operation_id="decideApprovalAsUser"
)
async def decide_as_user(
    approval_id: str, body: ApprovalDecisionRequest, principal: PrincipalDep, request: Request
) -> ApprovalStatusResponse:
    """User-level approval (approver_scope=user only). Admin-scope approvals require the admin API."""
    svc = _service(request)
    try:
        row = await svc.get_row(approval_id)
        if row.approver_scope != "user":
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="admin-scope approvals require the admin API")
        if row.requester_subject != principal.subject:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail="only the requesting user can decide here")
        await svc.decide(
            approval_id,
            approve=body.decision == "approve",
            actor=principal,
            elevation_minutes=body.elevation_minutes,
            note=body.note,
        )
        return _status_response(svc, await svc.get_row(approval_id))
    except ApprovalError as exc:
        raise _http(exc) from exc
