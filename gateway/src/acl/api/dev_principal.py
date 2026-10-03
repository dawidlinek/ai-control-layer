"""Dev-only principal override for in-process tests (never active in production).

`api/deps.py` (owned by 1C) calls `dev_principal_from_headers(request)` before its anonymous-dev fallback:

    if (p := dev_principal_from_headers(request)) is not None:
        return p

Active only when `app.state.allow_anonymous_dev` is True AND the request carries no Authorization header.
Headers: `X-ACL-Dev-User` (required), `X-ACL-Dev-Groups` and `X-ACL-Dev-Roles` (comma-separated).
"""

from __future__ import annotations

from fastapi import Request

from acl.contracts.common import AuthMethod, PrincipalKind
from acl.contracts.inspection import Principal


def _csv(value: str | None) -> list[str]:
    return [p.strip() for p in (value or "").split(",") if p.strip()]


def dev_principal_from_headers(request: Request) -> Principal | None:
    if not getattr(request.app.state, "allow_anonymous_dev", False):
        return None
    if request.headers.get("authorization"):
        return None
    user = request.headers.get("x-acl-dev-user")
    if not user:
        return None
    return Principal(
        subject=f"dev-{user}",
        kind=PrincipalKind.user,
        username=user,
        groups=_csv(request.headers.get("x-acl-dev-groups")),
        roles=_csv(request.headers.get("x-acl-dev-roles")),
        auth_method=AuthMethod.none,
    )
