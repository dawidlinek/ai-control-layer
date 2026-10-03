from fastapi import APIRouter

from acl.api.admin import access, events, platform, policy

router = APIRouter(prefix="/admin/v1")
router.include_router(policy.router)
router.include_router(access.router)
router.include_router(events.router)
router.include_router(platform.router)

__all__ = ["router"]
