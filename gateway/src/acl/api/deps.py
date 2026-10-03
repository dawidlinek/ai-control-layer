"""Shared FastAPI dependencies. Phase 1C (identity) owns the implementation of auth.

Phase 0: `current_principal` rejects every request (fail closed) unless the app was built with
`allow_anonymous_dev=True` (unit tests only). The OpenAPI security scheme is declared here so
generated clients know to send a bearer token.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated, NoReturn

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from acl.contracts.common import AuthMethod, PrincipalKind
from acl.contracts.inspection import Principal

bearer = HTTPBearer(auto_error=False, description="Keycloak access token (JWT) or personal API key (`acl_...`).")


async def current_principal(
    request: Request,
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> Principal:
    authenticator = getattr(request.app.state, "authenticator", None)
    if authenticator is not None:
        return await authenticator(request, creds)
    if getattr(request.app.state, "allow_anonymous_dev", False):
        return Principal(
            subject="dev", kind=PrincipalKind.user, username="dev", roles=["acl-admin"], auth_method=AuthMethod.none
        )
    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED, detail="authentication required", headers={"WWW-Authenticate": "Bearer"}
    )


PrincipalDep = Annotated[Principal, Depends(current_principal)]

ROLE_ADMIN = "acl-admin"
ROLE_ANALYST = "acl-analyst"
ROLE_VIEWER = "acl-viewer"
_ROLE_RANK = {ROLE_VIEWER: 0, ROLE_ANALYST: 1, ROLE_ADMIN: 2}


def require_role(minimum: str) -> Callable[..., Principal]:
    """Admin API guard: admin ⊇ analyst ⊇ viewer."""

    async def _guard(principal: PrincipalDep) -> Principal:
        rank = max((_ROLE_RANK[r] for r in principal.roles if r in _ROLE_RANK), default=-1)
        if rank < _ROLE_RANK[minimum]:
            raise HTTPException(status.HTTP_403_FORBIDDEN, detail=f"requires role {minimum}")
        return principal

    return _guard


Viewer = Annotated[Principal, Depends(require_role(ROLE_VIEWER))]
Analyst = Annotated[Principal, Depends(require_role(ROLE_ANALYST))]
Admin = Annotated[Principal, Depends(require_role(ROLE_ADMIN))]


def not_implemented(feature: str) -> NoReturn:
    raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, detail=f"{feature} is not implemented yet")


ERROR_RESPONSES: dict[int | str, dict] = {
    401: {"description": "Missing or invalid credentials"},
    403: {"description": "Insufficient role / forbidden resource"},
    501: {"description": "Not implemented yet"},
}
