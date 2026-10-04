"""Admin: Automation Insights (4B). Repeated tasks mined from redacted prompts, draft skills, publish / dismiss.

Management views only show clusters with at least k distinct users in opted-in groups. `/insights/mine` and
`/insights/opt-in` are self-service for any signed-in person (no admin role): their own suggestions only.
"""

from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Request

from acl.api.deps import ERROR_RESPONSES, Admin, Analyst, PrincipalDep, Viewer, not_implemented
from acl.contracts.admin import (
    DismissInsightRequest,
    InsightCluster,
    InsightOptIn,
    InsightSkill,
    InsightsSettings,
    InsightsStatus,
    PublishSkillRequest,
    SkillPreview,
    SkillPreviewRequest,
)
from acl.insights.service import InsightsService

router = APIRouter(responses=ERROR_RESPONSES, tags=["insights"])


def _svc(request: Request) -> InsightsService:
    svc = getattr(request.app.state, "insights", None)
    if svc is None:
        not_implemented("insights")
    return svc


@router.get("/insights/clusters", response_model=list[InsightCluster], operation_id="listInsights")
async def insights(
    request: Request,
    p: Viewer,
    group: str | None = None,
    status: Literal["new", "published", "dismissed"] | None = None,
) -> list[InsightCluster]:
    return await _svc(request).list_clusters(group, status)


@router.get("/insights/clusters/{cluster_id}", response_model=InsightCluster, operation_id="getInsight")
async def get_insight(request: Request, cluster_id: str, p: Viewer) -> InsightCluster:
    return await _svc(request).get_cluster(cluster_id)


@router.post(
    "/insights/clusters/{cluster_id}/publish",
    response_model=InsightCluster,
    operation_id="publishSkill",
)
async def publish(request: Request, cluster_id: str, body: PublishSkillRequest, p: Admin) -> InsightCluster:
    # Validates the draft for every target group, then writes ONE new policy version (skill + group grants).
    return await _svc(request).publish(cluster_id, body, p)


@router.post(
    "/insights/clusters/{cluster_id}/dismiss",
    response_model=InsightCluster,
    operation_id="dismissInsight",
)
async def dismiss(request: Request, cluster_id: str, body: DismissInsightRequest, p: Admin) -> InsightCluster:
    return await _svc(request).dismiss(cluster_id, body.reason, p)


@router.post(
    "/insights/clusters/{cluster_id}/preview",
    response_model=SkillPreview,
    operation_id="previewInsightSkill",
)
async def preview(request: Request, cluster_id: str, body: SkillPreviewRequest, p: Analyst) -> SkillPreview:
    # "Try with an example": validates the inputs against the draft's schema and renders the template.
    return await _svc(request).preview(cluster_id, body.inputs)


@router.post("/insights/recompute", response_model=InsightsStatus, operation_id="recomputeInsights")
async def recompute(request: Request, p: Admin) -> InsightsStatus:
    return await _svc(request).recompute("admin")


@router.get("/insights/status", response_model=InsightsStatus, operation_id="getInsightsStatus")
async def status(request: Request, p: Viewer) -> InsightsStatus:
    return _svc(request).status()


@router.get("/insights/skills", response_model=list[InsightSkill], operation_id="listInsightSkills")
async def skills(request: Request, p: Viewer) -> list[InsightSkill]:
    return await _svc(request).skills()


@router.get("/insights/settings", response_model=InsightsSettings, operation_id="getInsightsSettings")
async def get_settings(request: Request, p: Viewer) -> InsightsSettings:
    return await _svc(request).settings()


@router.put("/insights/settings", response_model=InsightsSettings, operation_id="updateInsightsSettings")
async def put_settings(request: Request, body: InsightsSettings, p: Admin) -> InsightsSettings:
    return await _svc(request).update_settings(body, p)


@router.get("/insights/mine", response_model=list[InsightCluster], operation_id="listMyInsights")
async def mine(request: Request, p: PrincipalDep) -> list[InsightCluster]:
    return await _svc(request).mine(p)


@router.put("/insights/opt-in", response_model=InsightOptIn, operation_id="setInsightsOptIn")
async def opt_in(request: Request, body: InsightOptIn, p: PrincipalDep) -> InsightOptIn:
    return InsightOptIn(enabled=await _svc(request).set_opt_in(p, body.enabled))
