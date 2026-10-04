from fastapi import APIRouter

from acl.api.admin import access, approvals, artifacts, budgets, events, insights, mcp, platform, policy

router = APIRouter(prefix="/admin/v1")
router.include_router(policy.router)
router.include_router(access.router)
router.include_router(events.router)
router.include_router(approvals.router)
router.include_router(budgets.router)
router.include_router(platform.router)
router.include_router(insights.router)
router.include_router(mcp.router)
router.include_router(artifacts.router)

__all__ = ["router"]
