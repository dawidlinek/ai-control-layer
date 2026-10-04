"""Admin: users, groups, grants, effective access, API keys (break-glass: `breakglass.py`). Owner: Phase 1C."""

from __future__ import annotations

import asyncio
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, HTTPException, Request, Response

from acl.api.admin.paging import TOTAL_COUNT_RESPONSES, set_total
from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, PrincipalDep, Viewer
from acl.audit import queries as audit_queries
from acl.contracts.admin import (
    ApiKey,
    ApiKeyCreate,
    ApiKeyCreated,
    EffectiveAccess,
    EventSummary,
    Grant,
    GrantChange,
    GrantCreate,
    Group,
    GroupSettingsPreview,
    GroupSettingsUpdate,
    PolicyStatus,
    UsageStats,
    User,
)
from acl.contracts.audit import EventType
from acl.contracts.common import GrantResourceType, Preset, Severity
from acl.contracts.inspection import Principal
from acl.identity.access import AccessUnavailable, preset_rank
from acl.identity.apikeys import key_from_row
from acl.identity.db_models import UserRow
from acl.identity.grants import GrantAlreadyRevoked, GrantNotFound
from acl.identity.users import principal_from_row, user_from_row
from acl.identity.wiring import IdentityServices
from acl.policy import groups_edit
from acl.policy.errors import ValidationFailed
from acl.policy.service import PolicyService
from acl.policy.writer import PolicyWriter

log = logging.getLogger(__name__)

router = APIRouter(tags=["access"], responses=ERROR_RESPONSES)


def _svc(request: Request) -> IdentityServices:
    svc = getattr(request.app.state, "identity", None)
    if svc is None:
        raise HTTPException(503, detail="identity services are not installed")
    return svc


async def _user_or_404(svc: IdentityServices, ref: str) -> UserRow:
    row = await svc.users.get(ref)
    if row is None:
        raise HTTPException(404, detail="user not found")
    return row


async def _effective(svc: IdentityServices, principal: Principal) -> EffectiveAccess:
    try:
        return await svc.access.effective_access(principal)
    except AccessUnavailable as exc:
        raise HTTPException(503, detail="policy not loaded yet") from exc


async def _audit_key_event(request: Request, actor: Principal, what: str, key: ApiKey) -> None:
    sink = getattr(request.app.state, "audit", None)
    if sink is None:
        return
    try:
        await sink.record_event(
            EventType.grant_change,
            severity=Severity.info,
            detail={"change": what, "resource_type": "api_key", "api_key_id": key.id, "user_id": key.user_id},
            principal=actor,
        )
    except Exception:
        log.exception("failed to record api key audit event")


async def _preset_of(svc: IdentityServices, row: UserRow) -> Preset | None:
    try:
        return await svc.access.effective_preset(principal_from_row(row))
    except AccessUnavailable:
        return None


async def _stats_7d(request: Request, subjects: list[str]) -> dict[str, UsageStats]:
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        return {}
    return await audit_queries.user_stats(sessions, subjects, window="7d")


@router.get("/users", response_model=list[User], operation_id="listUsers", responses=TOTAL_COUNT_RESPONSES)
async def list_users(
    request: Request,
    response: Response,
    p: Viewer,
    q: str | None = None,
    group: str | None = None,
    limit: int = 100,
) -> list[User]:
    svc = _svc(request)
    rows, total = await svc.users.list_page(q=q, group=group, limit=limit)
    set_total(response, total)
    stats = await _stats_7d(request, [r.subject for r in rows])
    presets = await asyncio.gather(*(_preset_of(svc, r) for r in rows))
    return [
        user_from_row(r).model_copy(update={"preset": preset, "stats_7d": stats.get(r.subject)})
        for r, preset in zip(rows, presets, strict=True)
    ]


@router.get("/users/{user_id}", response_model=User, operation_id="getUser")
async def get_user(request: Request, user_id: str, p: Viewer) -> User:
    svc = _svc(request)
    row = await _user_or_404(svc, user_id)
    stats = await _stats_7d(request, [row.subject])
    return user_from_row(row).model_copy(
        update={"preset": await _preset_of(svc, row), "stats_7d": stats.get(row.subject)}
    )


@router.get("/users/{user_id}/effective-access", response_model=EffectiveAccess, operation_id="getEffectiveAccess")
async def effective_access(request: Request, user_id: str, p: Viewer) -> EffectiveAccess:
    """Resolved access with sources: org locks → group grants → user grants (with expiry)."""
    svc = _svc(request)
    row = await _user_or_404(svc, user_id)
    return await _effective(svc, principal_from_row(row))


@router.get("/users/{user_id}/activity", response_model=list[EventSummary], operation_id="getUserActivity")
async def activity(
    request: Request, user_id: str, p: Analyst, since: datetime | None = None, limit: int = 100
) -> list[EventSummary]:
    row = await _user_or_404(_svc(request), user_id)
    sessions = getattr(request.app.state, "db", None)
    if sessions is None:
        raise HTTPException(503, detail="database not ready")
    engine = getattr(request.app.state, "engine", None)
    return await audit_queries.list_events(
        sessions,
        since=since,
        subject=row.subject,
        limit=limit,
        policy=engine.policy if engine is not None else None,
    )


def _policy_writer(request: Request) -> tuple[PolicyService, PolicyWriter]:
    service = getattr(request.app.state, "policy_service", None)
    writer = getattr(request.app.state, "policy_writer", None)
    if service is None or writer is None:
        raise HTTPException(503, detail="policy service is not running")
    return service, writer


def _policy_group(service: PolicyService, name: str) -> None:
    """404 unless `name` is a group of the loaded policy (Keycloak-only groups are not editable)."""
    loaded = service.loaded
    if loaded is None:
        raise HTTPException(503, detail="policy not loaded yet")
    if name not in loaded.policy.groups:
        raise HTTPException(404, detail="group not found in policy (Keycloak-only groups are not editable)")


@router.get("/groups", response_model=list[Group], operation_id="listGroups")
async def list_groups(request: Request, p: Viewer) -> list[Group]:
    # Policy groups ∪ Keycloak groups seen in tokens (read-only: Keycloak owns membership).
    svc = _svc(request)
    counts = await svc.users.all_group_counts()
    engine = getattr(request.app.state, "engine", None)
    policy = engine.policy if engine is not None else None
    policy_groups = dict(policy.groups) if policy is not None else {}
    stats = await groups_edit.stats_today(getattr(request.app.state, "db", None))
    service = getattr(request.app.state, "policy_service", None)
    groups_text = groups_edit.read_groups_text(service) if service is not None else None
    return [
        groups_edit.group_model(name, policy, counts.get(name, 0), stats, groups_text)
        for name in sorted(set(policy_groups) | set(counts))
    ]


@router.get("/groups/{name:path}/detail", response_model=Group, operation_id="getGroup")
async def get_group(request: Request, name: str, p: Viewer) -> Group:
    svc = _svc(request)
    counts = await svc.users.all_group_counts()
    engine = getattr(request.app.state, "engine", None)
    policy = engine.policy if engine is not None else None
    if (policy is None or name not in policy.groups) and name not in counts:
        raise HTTPException(404, detail="group not found")
    stats = await groups_edit.stats_today(getattr(request.app.state, "db", None))
    service = getattr(request.app.state, "policy_service", None)
    groups_text = groups_edit.read_groups_text(service) if service is not None else None
    return groups_edit.group_model(name, policy, counts.get(name, 0), stats, groups_text)


@router.post(
    "/groups/{name:path}/settings/preview", response_model=GroupSettingsPreview, operation_id="previewGroupSettings"
)
async def preview_group_settings(
    request: Request, name: str, body: GroupSettingsUpdate, p: Analyst
) -> GroupSettingsPreview:
    """Draft → validate → impact (dry-run on recent traffic). Writes nothing."""
    service, writer = _policy_writer(request)
    _policy_group(service, name)
    return await groups_edit.preview_settings(service, writer, name, body.settings)


@router.put("/groups/{name:path}/settings", response_model=PolicyStatus, operation_id="updateGroupSettings")
async def update_group_settings(request: Request, name: str, body: GroupSettingsUpdate, p: Admin) -> PolicyStatus:
    """Save group settings through the policy writer as a new policy version (validated, hot-reloaded)."""
    service, writer = _policy_writer(request)
    _policy_group(service, name)
    writer.check_policy_version(body.base_version)  # stale -> 409 before any validation
    loaded = service.loaded
    assert loaded is not None
    try:
        texts = {n: f.content for n, f in service.current_files().items()}
        plan = groups_edit.plan_edit(loaded.policy, name, body.settings, texts)
    except groups_edit.GroupSettingsInvalid as exc:
        raise ValidationFailed(exc.errors) from exc
    if plan.empty:
        return await service.status()
    message = body.message.strip() or f"group {name}: " + ", ".join(plan.changes)
    return await writer.patch_files(plan.edits, p, base_version=body.base_version, message=message[:500])


@router.get("/grants", response_model=list[Grant], operation_id="listGrants", responses=TOTAL_COUNT_RESPONSES)
async def list_grants(
    request: Request,
    response: Response,
    p: Viewer,
    subject: str | None = None,
    resource_type: GrantResourceType | None = None,
    resource: str | None = None,
    active: bool | None = True,
) -> list[Grant]:
    grants = await _svc(request).grants.list(
        subject=subject, resource_type=resource_type, resource=resource, active=active
    )
    set_total(response, len(grants))
    return grants


@router.post("/grants", response_model=Grant, status_code=201, operation_id="createGrant")
async def create_grant(request: Request, body: GrantCreate, p: Admin) -> Grant:
    """Create a per-user/group grant. Rejected (422) if an org lock forbids it outright."""
    svc = _svc(request)
    if body.expires_at is not None and body.expires_at.astimezone(UTC) <= datetime.now(UTC):
        raise HTTPException(422, detail="expires_at must be in the future")
    if body.subject_type == "group" and not body.subject.strip("/"):
        raise HTTPException(422, detail="subject must not be empty")
    try:
        problem = svc.access.validate_grant(
            body.resource_type,
            body.resource,
            group_subject=body.subject.strip("/") if body.subject_type == "group" else None,
        )
    except AccessUnavailable as exc:
        raise HTTPException(503, detail="policy not loaded yet") from exc
    if problem is not None and body.effect == "allow":
        raise HTTPException(422, detail=problem)
    if body.effect == "allow" and body.constraints.preset is not None:
        await _check_grant_preset(svc, body)
    return await svc.grants.create(body, p)


async def _check_grant_preset(svc: IdentityServices, body: GrantCreate) -> None:
    """A grant may only tighten the preset: reject one laxer than the subject's current effective preset."""
    wanted = body.constraints.preset
    assert wanted is not None
    try:
        if body.subject_type == "group":
            current, source = await svc.access.group_preset(body.subject.strip("/"))
        else:
            row = await svc.users.get(body.subject)
            principal = (
                principal_from_row(row) if row is not None else Principal(subject=body.subject, username=body.subject)
            )
            current, source = await svc.access.effective_preset_with_source(principal)
    except AccessUnavailable as exc:
        raise HTTPException(503, detail="policy not loaded yet") from exc
    if preset_rank(wanted) < preset_rank(current):
        raise HTTPException(
            422,
            detail=(
                f"preset '{wanted.value}' is laxer than the {body.subject_type}'s current effective preset "
                f"'{current.value}' (from {source}); a grant can only make the preset stricter "
                "(monitor < balanced < strict < paranoid)"
            ),
        )


@router.delete("/grants/{grant_id}", response_model=Grant, operation_id="revokeGrant")
async def revoke_grant(request: Request, grant_id: str, p: Admin, reason: str) -> Grant:
    if len(reason.strip()) < 3:
        raise HTTPException(422, detail="reason must be at least 3 characters")
    try:
        return await _svc(request).grants.revoke(grant_id, p, reason.strip())
    except GrantNotFound as exc:
        raise HTTPException(404, detail="grant not found") from exc
    except GrantAlreadyRevoked as exc:
        raise HTTPException(409, detail="grant is already revoked") from exc


@router.get("/grants/changes", response_model=list[GrantChange], operation_id="listGrantChanges")
async def grant_changes(request: Request, p: Viewer, subject: str | None = None, limit: int = 100) -> list[GrantChange]:
    return await _svc(request).grants.changes(subject=subject, limit=limit)


@router.get("/users/{user_id}/api-keys", response_model=list[ApiKey], operation_id="listApiKeys")
async def list_keys(request: Request, user_id: str, p: Viewer) -> list[ApiKey]:
    svc = _svc(request)
    row = await _user_or_404(svc, user_id)
    return await svc.keys.list_for_user(row.id)


@router.post("/users/{user_id}/api-keys", response_model=ApiKeyCreated, status_code=201, operation_id="createApiKey")
async def create_key(request: Request, user_id: str, body: ApiKeyCreate, p: Admin) -> ApiKeyCreated:
    svc = _svc(request)
    row = await _user_or_404(svc, user_id)
    if body.expires_at is not None and body.expires_at.astimezone(UTC) <= datetime.now(UTC):
        raise HTTPException(422, detail="expires_at must be in the future")
    created = await svc.keys.create(row, body.name, body.expires_at)
    await _audit_key_event(request, p, "api_key.create", created)
    return created


@router.delete("/api-keys/{key_id}", response_model=ApiKey, operation_id="revokeApiKey")
async def revoke_key(request: Request, key_id: str, p: Admin) -> ApiKey:
    row = await _svc(request).keys.revoke(key_id)
    if row is None:
        raise HTTPException(404, detail="api key not found")
    key = key_from_row(row)
    await _audit_key_event(request, p, "api_key.revoke", key)
    return key


@router.get("/me", response_model=EffectiveAccess, operation_id="getMyAccess")
async def me(request: Request, p: PrincipalDep) -> EffectiveAccess:
    """Employee self-service: the caller's own effective access."""
    return await _effective(_svc(request), p)
