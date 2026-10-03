"""Authenticator end to end (against SQLite): JWT, API keys, JIT provisioning, audit of failures."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
import respx
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from sqlalchemy import select

from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.contracts.common import AuthMethod, PrincipalKind
from acl.db import create_all, make_engine, make_sessionmaker
from acl.identity.apikeys import ApiKeyService, generate_key, hash_key, parse_key
from acl.identity.authenticator import Authenticator
from acl.identity.db_models import ApiKeyRow, UserRow, utcnow
from acl.identity.testing import AUDIENCE, ISSUER, TestKey, claims, jwks_document
from acl.identity.tokens import JwksCache, TokenVerifier
from acl.identity.users import UserStore

JWKS_URL = "http://kc.test/realms/acl/protocol/openid-connect/certs"
PEPPER = b"unit-test-pepper"


class Env(SimpleNamespace):
    auth: Authenticator
    users: UserStore
    keys: ApiKeyService
    sm: object
    key: TestKey
    audit: RecordingSink
    router: respx.MockRouter


@pytest.fixture
async def env(tmp_path: Path) -> AsyncIterator[Env]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    await create_all(engine)
    sm = make_sessionmaker(engine)
    key = TestKey("k1")
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(key))
    users = UserStore(lambda: sm)
    keys = ApiKeyService(lambda: sm, PEPPER)
    jwks = JwksCache(JWKS_URL, client=httpx.AsyncClient())
    audit = RecordingSink()
    app = SimpleNamespace(state=SimpleNamespace(audit=audit))
    auth = Authenticator(TokenVerifier(ISSUER, AUDIENCE, jwks), users, keys, app)
    with router:
        yield Env(auth=auth, users=users, keys=keys, sm=sm, key=key, audit=audit, router=router)
    await engine.dispose()


def request(path: str = "/admin/v1/me"):
    return SimpleNamespace(url=SimpleNamespace(path=path), method="GET", app=SimpleNamespace(state=SimpleNamespace()))


def bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def rejected(env: Env, token: str | None) -> HTTPException:
    creds = bearer(token) if token is not None else None
    with pytest.raises(HTTPException) as exc:
        await env.auth(request(), creds)
    return exc.value


# ---------------------------------------------------------------- JWT + JIT provisioning


async def test_missing_credentials_is_401_with_challenge(env: Env) -> None:
    exc = await rejected(env, None)
    assert exc.status_code == 401 and exc.headers == {"WWW-Authenticate": "Bearer"}


async def test_valid_jwt_provisions_user_just_in_time(env: Env) -> None:
    token = env.key.sign(
        claims("kc-sub-1", username="anna", groups=["/developers"], email="anna@corp.example", name="Anna Nowak")
    )
    p = await env.auth(request(), bearer(token))
    assert (p.subject, p.username, p.groups, p.kind, p.auth_method) == (
        "kc-sub-1",
        "anna",
        ["developers"],
        PrincipalKind.user,
        AuthMethod.jwt,
    )
    async with env.sm() as s:  # type: ignore[operator]
        row = (await s.execute(select(UserRow).where(UserRow.subject == "kc-sub-1"))).scalar_one()
    assert row.email == "anna@corp.example" and row.display_name == "Anna Nowak"
    assert row.groups == ["developers"] and row.first_seen and row.last_seen and row.kind == "user"


async def test_group_change_is_picked_up_and_first_seen_kept(env: Env) -> None:
    await env.auth(request(), bearer(env.key.sign(claims("kc-sub-2", username="jan", groups=["/developers"]))))
    async with env.sm() as s:  # type: ignore[operator]
        first = (await s.execute(select(UserRow.first_seen).where(UserRow.subject == "kc-sub-2"))).scalar_one()
    env.users.forget()  # skip the provisioning throttle
    await env.auth(request(), bearer(env.key.sign(claims("kc-sub-2", username="jan", groups=["/credit-analysts"]))))
    async with env.sm() as s:  # type: ignore[operator]
        row = (await s.execute(select(UserRow).where(UserRow.subject == "kc-sub-2"))).scalar_one()
    assert row.groups == ["credit-analysts"] and row.first_seen == first


async def test_agent_token_is_provisioned_as_agent(env: Env) -> None:
    token = env.key.sign(
        claims(
            "sa-1",
            username="service-account-agent-research-bot",
            groups=["/agents/research-bot"],
            azp="agent-research-bot",
            agent_id="research-bot",
            roles=[],
        )
    )
    p = await env.auth(request(), bearer(token))
    assert p.kind == PrincipalKind.agent and p.agent_id == "research-bot"
    assert p.auth_method == AuthMethod.client_credentials and p.client_id == "agent-research-bot"
    async with env.sm() as s:  # type: ignore[operator]
        row = (await s.execute(select(UserRow).where(UserRow.subject == "sa-1"))).scalar_one()
    assert row.kind == "agent" and row.groups == ["agents/research-bot"]


async def test_bad_jwts_are_401_and_audited_without_the_token(env: Env) -> None:
    for bad in (
        env.key.sign(claims(exp_in=-600)),
        env.key.sign(claims(audience="other")),
        env.key.sign(claims(issuer="http://evil/")),
        TestKey("k1").sign(claims()),
    ):
        exc = await rejected(env, bad)
        assert exc.status_code == 401 and exc.headers == {"WWW-Authenticate": "Bearer"}
    events = [e for e in env.audit.events if e[0] == EventType.auth_failure]
    assert len(events) == 4
    assert {e[1]["detail"]["reason"] for e in events} == {"expired", "wrong_audience", "wrong_issuer", "bad_signature"}
    assert "eyJ" not in repr(env.audit.events)


async def test_disabled_account_is_rejected(env: Env) -> None:
    token = env.key.sign(claims("kc-sub-3", username="eve"))
    await env.auth(request(), bearer(token))
    async with env.sm() as s, s.begin():  # type: ignore[operator]
        (await s.execute(select(UserRow).where(UserRow.subject == "kc-sub-3"))).scalar_one().disabled = True
    env.users.forget()
    assert (await rejected(env, token)).status_code == 401


# ---------------------------------------------------------------- API keys


async def make_user(env: Env, subject: str = "kc-sub-9", username: str = "ola", groups=("security-analysts",)):
    await env.auth(
        request(), bearer(env.key.sign(claims(subject, username=username, groups=[f"/{g}" for g in groups])))
    )
    async with env.sm() as s:  # type: ignore[operator]
        return (await s.execute(select(UserRow).where(UserRow.subject == subject))).scalar_one()


async def test_key_format_and_storage(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    assert created.key.startswith("acl_") and created.prefix == created.key[:12]
    prefix, secret = parse_key(created.key)  # type: ignore[misc]
    assert len(prefix) == 8 and secret
    async with env.sm() as s:  # type: ignore[operator]
        row = (await s.execute(select(ApiKeyRow))).scalar_one()
    stored = " ".join(str(v) for v in vars(row).values())
    assert created.key not in stored and secret not in stored  # only the HMAC + prefix are persisted
    assert row.key_hash == hash_key(PEPPER, created.key) and row.prefix == prefix
    assert hash_key(b"another-pepper", created.key) != row.key_hash


async def test_valid_key_authenticates_as_owner(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    p = await env.auth(request(), bearer(created.key))
    assert (p.subject, p.username, p.groups) == ("kc-sub-9", "ola", ["security-analysts"])
    assert p.auth_method == AuthMethod.api_key and p.api_key_id == created.id
    async with env.sm() as s:  # type: ignore[operator]
        assert (await s.execute(select(ApiKeyRow.last_used_at))).scalar_one() is not None


async def test_key_uses_owners_current_groups(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    env.users.forget()
    await env.auth(request(), bearer(env.key.sign(claims("kc-sub-9", username="ola", groups=["/admins"]))))
    assert (await env.auth(request(), bearer(created.key))).groups == ["admins"]


async def test_wrong_secret_with_right_prefix(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    prefix = created.key.split("_")[1]
    for bad in (f"acl_{prefix}_not-the-secret", created.key + "x", f"acl_{prefix}_"):
        assert (await rejected(env, bad)).status_code == 401


async def test_unknown_prefix_and_malformed(env: Env) -> None:
    for bad in ("acl_deadbeef_whatever", "acl_short_x", "acl_", "acl"):
        assert (await rejected(env, bad)).status_code == 401


async def test_revoked_key_rejected(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    await env.auth(request(), bearer(created.key))
    await env.keys.revoke(created.id)
    assert (await rejected(env, created.key)).status_code == 401
    assert any(e[1]["detail"]["reason"] == "api_key_revoked" for e in env.audit.events)


async def test_expired_key_rejected(env: Env) -> None:
    user = await make_user(env)
    live = await env.keys.create(user, "live", utcnow() + timedelta(hours=1))
    await env.auth(request(), bearer(live.key))
    expired = await env.keys.create(user, "old", utcnow() + timedelta(milliseconds=1))
    async with env.sm() as s, s.begin():  # type: ignore[operator]
        row = await s.get(ApiKeyRow, expired.id)
        row.expires_at = utcnow() - timedelta(seconds=1)
    assert (await rejected(env, expired.key)).status_code == 401
    assert any(e[1]["detail"]["reason"] == "api_key_expired" for e in env.audit.events)


async def test_key_of_disabled_user_rejected(env: Env) -> None:
    user = await make_user(env)
    created = await env.keys.create(user, "ci", None)
    async with env.sm() as s, s.begin():  # type: ignore[operator]
        (await s.get(UserRow, user.id)).disabled = True
    assert (await rejected(env, created.key)).status_code == 401


def test_generated_keys_are_unique_and_parse() -> None:
    seen = {generate_key()[1] for _ in range(50)}
    assert len(seen) == 50
    assert all(parse_key(k) is not None for k in seen)
