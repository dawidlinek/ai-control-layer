"""Admin: users, groups, grants, effective access, API keys, break-glass. Owner: Phase 1C."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, PrincipalDep, Viewer, not_implemented
from acl.contracts.admin import (
    ApiKey,
    ApiKeyCreate,
    ApiKeyCreated,
    BreakGlassRequest,
    BreakGlassResponse,
    EffectiveAccess,
    EventSummary,
    Grant,
    GrantChange,
    GrantCreate,
    Group,
    User,
)
from acl.contracts.common import GrantResourceType

router = APIRouter(tags=["access"], responses=ERROR_RESPONSES)


@router.get("/users", response_model=list[User], operation_id="listUsers")
async def list_users(p: Viewer, q: str | None = None, group: str | None = None, limit: int = 100) -> list[User]:
    not_implemented("users")


@router.get("/users/{user_id}", response_model=User, operation_id="getUser")
async def get_user(user_id: str, p: Viewer) -> User:
    not_implemented("users")


@router.get("/users/{user_id}/effective-access", response_model=EffectiveAccess, operation_id="getEffectiveAccess")
async def effective_access(user_id: str, p: Viewer) -> EffectiveAccess:
    """Resolved access with sources: org locks → group grants → user grants (with expiry)."""
    not_implemented("effective access")


@router.get("/users/{user_id}/activity", response_model=list[EventSummary], operation_id="getUserActivity")
async def activity(user_id: str, p: Analyst, since: datetime | None = None, limit: int = 100) -> list[EventSummary]:
    not_implemented("user activity")


@router.post("/users/{user_id}/breakglass", response_model=BreakGlassResponse, operation_id="breakGlass")
async def break_glass(user_id: str, body: BreakGlassRequest, p: Admin) -> BreakGlassResponse:
    """View raw content of one event. Requires a reason; audited as its own `breakglass` event."""
    not_implemented("break-glass")


@router.get("/groups", response_model=list[Group], operation_id="listGroups")
async def list_groups(p: Viewer) -> list[Group]:
    not_implemented("groups")


@router.get("/grants", response_model=list[Grant], operation_id="listGrants")
async def list_grants(
    p: Viewer,
    subject: str | None = None,
    resource_type: GrantResourceType | None = None,
    resource: str | None = None,
    active: bool | None = True,
) -> list[Grant]:
    not_implemented("grants")


@router.post("/grants", response_model=Grant, status_code=201, operation_id="createGrant")
async def create_grant(body: GrantCreate, p: Admin) -> Grant:
    """Create a per-user/group grant. Rejected (422) if an org lock forbids it outright."""
    not_implemented("grants")


@router.delete("/grants/{grant_id}", response_model=Grant, operation_id="revokeGrant")
async def revoke_grant(grant_id: str, p: Admin, reason: str) -> Grant:
    not_implemented("grants")


@router.get("/grants/changes", response_model=list[GrantChange], operation_id="listGrantChanges")
async def grant_changes(p: Viewer, subject: str | None = None, limit: int = 100) -> list[GrantChange]:
    not_implemented("grant changes")


@router.get("/users/{user_id}/api-keys", response_model=list[ApiKey], operation_id="listApiKeys")
async def list_keys(user_id: str, p: Viewer) -> list[ApiKey]:
    not_implemented("api keys")


@router.post("/users/{user_id}/api-keys", response_model=ApiKeyCreated, status_code=201, operation_id="createApiKey")
async def create_key(user_id: str, body: ApiKeyCreate, p: Admin) -> ApiKeyCreated:
    not_implemented("api keys")


@router.delete("/api-keys/{key_id}", response_model=ApiKey, operation_id="revokeApiKey")
async def revoke_key(key_id: str, p: Admin) -> ApiKey:
    not_implemented("api keys")


@router.get("/me", response_model=EffectiveAccess, operation_id="getMyAccess")
async def me(p: PrincipalDep) -> EffectiveAccess:
    """Employee self-service: the caller's own effective access."""
    not_implemented("self-service")
