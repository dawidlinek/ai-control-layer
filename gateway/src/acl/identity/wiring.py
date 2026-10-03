"""Installer for the identity package (listed in `acl.main.INSTALLERS`).

Provides on the app:
    app.state.authenticator   async (request, creds) -> Principal       (used by `api/deps.py`)
    app.state.access          AccessResolver                            (also `control_deps["access"]`)
    app.state.identity        IdentityServices (users, api keys, grants, JWKS cache; admin routes use it)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import FastAPI

from acl.contracts.inspection import Principal
from acl.identity.access import DefaultAccessResolver, grant_keys
from acl.identity.apikeys import ApiKeyService
from acl.identity.authenticator import Authenticator
from acl.identity.config import IdentityOptions
from acl.identity.grants import GrantStore
from acl.identity.tokens import JwksCache, TokenVerifier
from acl.identity.users import UserStore
from acl.settings import Settings

log = logging.getLogger(__name__)


@dataclass
class IdentityServices:
    users: UserStore
    keys: ApiKeyService
    grants: GrantStore
    access: DefaultAccessResolver
    jwks: JwksCache
    authenticator: Authenticator


def build_services(app: FastAPI, settings: Settings) -> IdentityServices:
    def sessions():  # resolved lazily: the DB is created in the app lifespan
        return app.state.db

    def policy_view():
        engine = getattr(app.state, "engine", None)
        return None if engine is None else (engine.policy, engine.policy_version)

    users = UserStore(sessions)
    keys = ApiKeyService(
        sessions,
        settings.api_key_pepper.get_secret_value().encode("utf-8"),
        max_group_age=IdentityOptions().api_key_max_group_age,
    )
    grants = GrantStore(sessions, audit=lambda: getattr(app.state, "audit", None))
    access = DefaultAccessResolver(policy_view, grants)
    jwks = JwksCache(settings.jwks_url)
    verifier = TokenVerifier(settings.oidc_issuer, settings.oidc_audience, jwks)

    async def warm(principal: Principal) -> None:
        # Controls have tight timeouts (10 ms for SEC-MODEL-01): load grants during authentication so the
        # access check in the pipeline is served from the cache.
        user_keys, groups = grant_keys(principal)
        await grants.active_for(user_keys, groups)

    authenticator = Authenticator(verifier, users, keys, app, on_authenticated=warm)
    return IdentityServices(users, keys, grants, access, jwks, authenticator)


def install(app: FastAPI, settings: Settings) -> None:
    svc = build_services(app, settings)
    app.state.identity = svc
    app.state.authenticator = svc.authenticator
    app.state.access = svc.access
    app.state.control_deps.register("access", svc.access)

    async def start(app: FastAPI) -> None:
        await svc.grants.ensure_meta()

    async def stop(app: FastAPI) -> None:
        await svc.jwks.aclose()

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
