"""Admin: policy files, validation, dry-run, versions. Owner: Phase 1B."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, Viewer, not_implemented
from acl.contracts.admin import (
    DryRunRequest,
    DryRunResponse,
    ErrorResponse,
    PolicyFileContent,
    PolicyFileInfo,
    PolicyFileWrite,
    PolicyStatus,
    PolicyVersion,
    PolicyVersionDetail,
    ValidateRequest,
    ValidateResponse,
)

router = APIRouter(prefix="/policy", tags=["policy"], responses=ERROR_RESPONSES)


@router.get("", response_model=PolicyStatus, operation_id="getPolicyStatus")
async def get_status(p: Viewer) -> PolicyStatus:
    not_implemented("policy status")


@router.get("/schema", operation_id="getPolicySchema")
async def get_schema(p: Viewer) -> dict[str, Any]:
    """JSON Schema for policy files (same as contracts/policy.schema.json)."""
    not_implemented("policy schema")


@router.get("/files", response_model=list[PolicyFileInfo], operation_id="listPolicyFiles")
async def list_files(p: Viewer) -> list[PolicyFileInfo]:
    not_implemented("policy files")


@router.get("/files/{name}", response_model=PolicyFileContent, operation_id="getPolicyFile")
async def get_file(name: str, p: Viewer) -> PolicyFileContent:
    not_implemented("policy files")


@router.put(
    "/files/{name}",
    response_model=PolicyStatus,
    operation_id="writePolicyFile",
    responses={
        409: {"model": ErrorResponse, "description": "Stale base_version"},
        422: {"model": ErrorResponse, "description": "Validation failed or locked control edited"},
    },
)
async def write_file(name: str, body: PolicyFileWrite, p: Admin) -> PolicyStatus:
    """Single-writer update: validate → round-trip write (comments preserved) → reload → snapshot."""
    not_implemented("policy write")


@router.post("/validate", response_model=ValidateResponse, operation_id="validatePolicy")
async def validate(body: ValidateRequest, p: Analyst) -> ValidateResponse:
    not_implemented("policy validate")


@router.post("/dry-run", response_model=DryRunResponse, operation_id="dryRunPolicy")
async def dry_run(body: DryRunRequest, p: Analyst) -> DryRunResponse:
    """Replay the last N stored requests against the candidate policy."""
    not_implemented("policy dry-run")


@router.get("/versions", response_model=list[PolicyVersion], operation_id="listPolicyVersions")
async def list_versions(p: Viewer, limit: int = 50) -> list[PolicyVersion]:
    not_implemented("policy versions")


@router.get("/versions/{version_id}", response_model=PolicyVersionDetail, operation_id="getPolicyVersion")
async def get_version(version_id: int, p: Viewer) -> PolicyVersionDetail:
    not_implemented("policy versions")


@router.post("/versions/{version_id}/rollback", response_model=PolicyStatus, operation_id="rollbackPolicy")
async def rollback(version_id: int, p: Admin) -> PolicyStatus:
    not_implemented("policy rollback")
