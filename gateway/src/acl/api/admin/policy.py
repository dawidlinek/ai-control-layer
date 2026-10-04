"""Admin: policy files, validation, dry-run, versions. Owner: Phase 1B.

Thin HTTP layer over `acl.policy.service.PolicyService` (read side, validate, dry-run, versions) and
`acl.policy.writer.PolicyWriter` (the only code path that changes policy files).
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer
from acl.contracts.admin import (
    DryRunRequest,
    DryRunResponse,
    ErrorResponse,
    PolicyFileContent,
    PolicyFileInfo,
    PolicyFileWrite,
    PolicyRollbackRequest,
    PolicyStatus,
    PolicyVersion,
    PolicyVersionDetail,
    ValidateRequest,
    ValidateResponse,
)
from acl.policy.models import PolicyDocument
from acl.policy.service import PolicyService
from acl.policy.writer import PolicyWriter


def _service(request: Request) -> PolicyService:
    service = getattr(request.app.state, "policy_service", None)
    if service is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="policy service is not running")
    return service


def _writer(request: Request) -> PolicyWriter:
    writer = getattr(request.app.state, "policy_writer", None)
    if writer is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, detail="policy service is not running")
    return writer


Service = Annotated[PolicyService, Depends(_service)]
Writer = Annotated[PolicyWriter, Depends(_writer)]


router = APIRouter(prefix="/policy", tags=["policy"], responses=ERROR_RESPONSES)


@router.get("", response_model=PolicyStatus, operation_id="getPolicyStatus")
async def get_status(p: Viewer, service: Service) -> PolicyStatus:
    return await service.status()


@router.get("/schema", operation_id="getPolicySchema")
async def get_schema(p: Viewer) -> dict[str, Any]:
    """JSON Schema for policy files (same as contracts/policy.schema.json)."""
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://acl.local/contracts/policy.schema.json",
        **PolicyDocument.model_json_schema(by_alias=True, ref_template="#/$defs/{model}"),
    }


@router.get("/files", response_model=list[PolicyFileInfo], operation_id="listPolicyFiles")
async def list_files(p: Viewer, service: Service) -> list[PolicyFileInfo]:
    return service.list_files()


@router.get("/files/{name}", response_model=PolicyFileContent, operation_id="getPolicyFile")
async def get_file(name: str, p: Viewer, service: Service) -> PolicyFileContent:
    return service.get_file(name)


@router.put(
    "/files/{name}",
    response_model=PolicyStatus,
    operation_id="writePolicyFile",
    responses={
        409: {"model": ErrorResponse, "description": "Stale base_version"},
        422: {"model": ErrorResponse, "description": "Validation failed or locked control edited"},
    },
)
async def write_file(name: str, body: PolicyFileWrite, p: Admin, writer: Writer) -> PolicyStatus:
    """Single-writer update: validate → round-trip write (comments preserved) → reload → snapshot."""
    return await writer.write_file(name, body.content, body.base_version, p, body.message)


@router.post("/validate", response_model=ValidateResponse, operation_id="validatePolicy")
async def validate(body: ValidateRequest, p: Analyst, service: Service) -> ValidateResponse:
    return await service.validate(body.files)


@router.post("/dry-run", response_model=DryRunResponse, operation_id="dryRunPolicy")
async def dry_run(body: DryRunRequest, p: Analyst, service: Service) -> DryRunResponse:
    """Replay the last N stored requests against the candidate policy."""
    return await service.dry_run(body)


@router.get("/versions", response_model=list[PolicyVersion], operation_id="listPolicyVersions")
async def list_versions(p: Viewer, service: Service, limit: int = 50) -> list[PolicyVersion]:
    return await service.list_versions(limit)


@router.get("/versions/{version_id}", response_model=PolicyVersionDetail, operation_id="getPolicyVersion")
async def get_version(version_id: int, p: Viewer, service: Service) -> PolicyVersionDetail:
    return await service.get_version(version_id)


@router.post("/versions/{version_id}/rollback", response_model=PolicyStatus, operation_id="rollbackPolicy")
async def rollback(
    version_id: int, p: Admin, writer: Writer, body: PolicyRollbackRequest | None = None
) -> PolicyStatus:
    """Restore a stored version as a new one. The JSON body is optional; when given, `reason` is stored with the new
    version (history `reason`, the `policy_change` audit event)."""
    return await writer.rollback(version_id, p, reason=body.reason if body is not None else None)
