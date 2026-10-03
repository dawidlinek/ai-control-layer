"""Keycloak JWT verification (RS256/ES256 only) with a JWKS cache, and claim → Principal mapping.

Nothing here logs or returns token contents: failures carry a short machine-readable `reason` only.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt
from jwt import PyJWK

from acl.contracts.common import AuthMethod, PrincipalKind
from acl.contracts.inspection import Principal

log = logging.getLogger(__name__)

ALLOWED_ALGS = ("RS256", "ES256")
LEEWAY_S = 30
SERVICE_ACCOUNT_PREFIX = "service-account-"
AGENT_CLIENT_PREFIX = "agent-"


class AuthError(Exception):
    """Credential rejected. `reason` is a stable code that is safe to log and audit."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class IdentityProviderUnavailable(Exception):
    """JWKS could not be fetched and no cached key can verify the token."""


class JwksCache:
    """kid → public key. Refreshes on TTL expiry and (rate-limited) on an unknown `kid`."""

    def __init__(
        self,
        url: str,
        *,
        client: httpx.AsyncClient | None = None,
        ttl_s: float = 600.0,
        min_refresh_interval_s: float = 10.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.url = url
        self._client = client
        self._owns_client = client is None
        self.ttl_s = ttl_s
        self.min_refresh_interval_s = min_refresh_interval_s
        self._clock = clock
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None
        self._last_attempt: float | None = None
        self._lock = asyncio.Lock()
        self.fetch_count = 0

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=5.0)
        return self._client

    async def _fetch(self) -> None:
        self._last_attempt = self._clock()
        self.fetch_count += 1
        resp = await self._http().get(self.url)
        resp.raise_for_status()
        keys: dict[str, Any] = {}
        for jwk in resp.json().get("keys", []):
            if jwk.get("use", "sig") != "sig" or jwk.get("kty") not in ("RSA", "EC"):
                continue
            try:
                keys[jwk.get("kid", "")] = PyJWK.from_dict(jwk).key
            except Exception:
                log.warning("ignoring unparsable JWKS entry kid=%s", jwk.get("kid"))
        self._keys = keys
        self._fetched_at = self._clock()

    def _stale(self) -> bool:
        return self._fetched_at is None or self._clock() - self._fetched_at > self.ttl_s

    async def get(self, kid: str | None) -> Any:
        """Public key for `kid`; raises AuthError('unknown_kid') or IdentityProviderUnavailable."""
        if not self._stale() and kid in self._keys:
            return self._keys[kid]
        async with self._lock:
            now = self._clock()
            can_refresh = self._last_attempt is None or now - self._last_attempt >= self.min_refresh_interval_s
            if (self._stale() or kid not in self._keys) and can_refresh:
                try:
                    await self._fetch()
                except (httpx.HTTPError, ValueError) as exc:
                    log.warning("JWKS fetch failed: %s", type(exc).__name__)
                    if kid not in self._keys:
                        raise IdentityProviderUnavailable("jwks_unavailable") from exc
            if kid in self._keys:
                return self._keys[kid]
            if kid is None and len(self._keys) == 1:  # token without `kid` and a single-key realm
                return next(iter(self._keys.values()))
            if not self._keys:
                raise IdentityProviderUnavailable("jwks_unavailable")
            raise AuthError("unknown_kid")


class TokenVerifier:
    def __init__(self, issuer: str, audience: str, jwks: JwksCache) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks = jwks

    async def verify(self, token: str) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AuthError("malformed_token") from exc
        alg = header.get("alg")
        if alg not in ALLOWED_ALGS:  # rejects `none`, HS*, and anything exotic before any key lookup
            raise AuthError("alg_not_allowed")
        key = await self.jwks.get(header.get("kid"))
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=[alg],
                audience=self.audience,
                issuer=self.issuer,
                leeway=LEEWAY_S,
                options={"require": ["exp", "iss", "sub"], "verify_aud": True},
            )
        except jwt.ExpiredSignatureError as exc:
            raise AuthError("expired") from exc
        except jwt.ImmatureSignatureError as exc:
            raise AuthError("not_yet_valid") from exc
        except jwt.InvalidIssuerError as exc:
            raise AuthError("wrong_issuer") from exc
        except jwt.InvalidAudienceError as exc:
            raise AuthError("wrong_audience") from exc
        except jwt.MissingRequiredClaimError as exc:
            raise AuthError("missing_claim") from exc
        except jwt.InvalidSignatureError as exc:
            raise AuthError("bad_signature") from exc
        except jwt.PyJWTError as exc:
            raise AuthError("invalid_token") from exc
        return claims


# ---------------------------------------------------------------- claims → Principal


def normalise_groups(raw: Any) -> list[str]:
    """Keycloak group paths (`/agents/research-bot`) → `agents/research-bot`; deduplicated, order kept."""
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for g in raw or []:
        if not isinstance(g, str):
            continue
        g = g.strip().strip("/")
        if g and g not in out:
            out.append(g)
    return out


def delegation_chain(claims: dict[str, Any]) -> list[str]:
    """RFC 8693 `act` claim → [originating subject, innermost actor, ..., current actor]."""
    actors: list[str] = []
    act = claims.get("act")
    depth = 0
    while isinstance(act, dict) and depth < 16:
        sub = act.get("sub") or act.get("client_id")
        if isinstance(sub, str):
            actors.append(sub)
        act = act.get("act")
        depth += 1
    if not actors:
        return []
    return [str(claims["sub"]), *reversed(actors)]


def is_agent_token(claims: dict[str, Any]) -> bool:
    username = claims.get("preferred_username") or ""
    return bool(claims.get("agent_id")) or str(username).startswith(SERVICE_ACCOUNT_PREFIX)


def principal_from_claims(claims: dict[str, Any]) -> Principal:
    username = claims.get("preferred_username") or claims.get("username") or claims["sub"]
    azp = claims.get("azp")
    roles = (claims.get("realm_access") or {}).get("roles") or []
    agent = is_agent_token(claims)
    agent_id: str | None = None
    if agent:
        agent_id = claims.get("agent_id")
        if not agent_id:
            base = azp or str(username).removeprefix(SERVICE_ACCOUNT_PREFIX)
            agent_id = str(base).removeprefix(AGENT_CLIENT_PREFIX)
    return Principal(
        subject=str(claims["sub"]),
        kind=PrincipalKind.agent if agent else PrincipalKind.user,
        username=str(username),
        groups=normalise_groups(claims.get("groups")),
        roles=[str(r) for r in roles if isinstance(r, str)],
        agent_id=str(agent_id) if agent_id else None,
        client_id=str(azp) if azp else None,
        auth_method=AuthMethod.client_credentials if agent else AuthMethod.jwt,
        delegation_chain=delegation_chain(claims),
    )


def display_name_from_claims(claims: dict[str, Any]) -> str | None:
    name = claims.get("name")
    if not name:
        name = " ".join(p for p in (claims.get("given_name"), claims.get("family_name")) if p)
    return str(name) if name else None
