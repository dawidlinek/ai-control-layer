"""`app.state.authenticator`: bearer credential (Keycloak JWT or personal API key) → `Principal`."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials

from acl.contracts.audit import EventType
from acl.contracts.common import Severity
from acl.contracts.inspection import Principal
from acl.identity.apikeys import ApiKeyService, looks_like_api_key
from acl.identity.tokens import (
    AuthError,
    IdentityProviderUnavailable,
    TokenVerifier,
    display_name_from_claims,
    principal_from_claims,
)
from acl.identity.users import UserStore

log = logging.getLogger(__name__)

_CHALLENGE = {"WWW-Authenticate": "Bearer"}
MAX_FAILURE_EVENTS_PER_10S = 100
STALE_IDENTITY_DETAIL = (
    "stale_identity: the API key owner's groups have not been refreshed by a Keycloak sign-in recently; "
    "sign in once to refresh them"
)


def _unauthorized(detail: str = "invalid or missing credentials") -> HTTPException:
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail=detail, headers=_CHALLENGE)


class Authenticator:
    def __init__(
        self,
        verifier: TokenVerifier,
        users: UserStore,
        keys: ApiKeyService,
        app: Any = None,
        on_authenticated: Callable[[Principal], Awaitable[None]] | None = None,
    ) -> None:
        self.on_authenticated = on_authenticated
        self.verifier = verifier
        self.users = users
        self.keys = keys
        self._app = app
        self._fail_window = (0.0, 0)  # (window start, events recorded): bound audit volume under credential spraying

    async def __call__(self, request: Request, creds: HTTPAuthorizationCredentials | None) -> Principal:
        principal = await self._authenticate(request, creds)
        if self.on_authenticated is not None:
            try:
                await self.on_authenticated(principal)  # e.g. warm the grant cache outside control timeouts
            except Exception:
                log.warning("post-authentication hook failed")
        return principal

    async def _authenticate(self, request: Request, creds: HTTPAuthorizationCredentials | None) -> Principal:
        if creds is None or creds.scheme.lower() != "bearer" or not creds.credentials:
            raise _unauthorized("authentication required")
        token = creds.credentials.strip()
        try:
            if looks_like_api_key(token):
                principal, _ = await self.keys.authenticate(token)
                # the user's last-known groups (refused when too old); never an admin-panel role
                return principal
            claims = await self.verifier.verify(token)
            principal = principal_from_claims(claims)
            disabled = await self.users.provision(
                principal, email=claims.get("email"), display_name=display_name_from_claims(claims)
            )
            if disabled:
                raise AuthError("account_disabled")
            return principal
        except AuthError as exc:
            await self._record_failure(request, exc.reason)
            if exc.reason == "stale_identity":
                raise _unauthorized(STALE_IDENTITY_DETAIL) from exc
            raise _unauthorized() from exc
        except IdentityProviderUnavailable as exc:
            log.error("identity provider unreachable: cannot verify tokens")
            raise HTTPException(
                status.HTTP_503_SERVICE_UNAVAILABLE, detail="identity provider unavailable", headers=_CHALLENGE
            ) from exc

    async def _record_failure(self, request: Request, reason: str) -> None:
        """Audit a rejected credential (reason code + path only: never the credential itself)."""
        sink = getattr(getattr(self._app or request.app, "state", None), "audit", None)
        if sink is None:
            return
        now = time.monotonic()
        start, count = self._fail_window
        if now - start > 10.0:
            start, count = now, 0
        if count >= MAX_FAILURE_EVENTS_PER_10S:
            return
        self._fail_window = (start, count + 1)
        try:
            await sink.record_event(
                EventType.auth_failure,
                severity=Severity.low,
                detail={"reason": reason, "path": request.url.path, "method": request.method},
            )
        except Exception:
            log.exception("failed to record auth_failure event")
