"""CP1 review: identity fixes.

- a user/group grant preset can only tighten the effective preset (never laxer than the groups);
- API keys carry no admin-panel roles and are refused when the owner's groups are stale;
- API keys of agent principals keep `kind=agent` and `agent_id`.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
import respx
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient
from sqlalchemy import select

from acl.audit.sink import RecordingSink
from acl.contracts.admin import GrantConstraints, GrantCreate
from acl.contracts.common import AuthMethod, GrantResourceType, Preset, PrincipalKind
from acl.db import create_all, make_engine, make_sessionmaker
from acl.identity.access import DefaultAccessResolver
from acl.identity.apikeys import ApiKeyService
from acl.identity.authenticator import Authenticator
from acl.identity.config import IdentityOptions
from acl.identity.db_models import UserRow, utcnow
from acl.identity.grants import GrantStore
from acl.identity.testing import AUDIENCE, ISSUER, FakeClock, TestKey, claims, jwks_document, load_repo_policy
from acl.identity.tokens import JwksCache, TokenVerifier
from acl.identity.users import UserStore, principal_from_row
from acl.main import create_app
from acl.settings import Settings
from acl.testing import make_principal

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
PEPPER = b"unit-test-pepper"
BASE = "/admin/v1"
ADMIN = make_principal("adam", ["admins"], roles=["acl-admin"])


# ================================================================ finding 2: grant presets only tighten


@pytest.fixture
async def access(tmp_path: Path) -> AsyncIterator[SimpleNamespace]:
    db = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'access.db'}")
    await create_all(db)
    sm = make_sessionmaker(db)
    clock = FakeClock()
    grants = GrantStore(lambda: sm, audit=lambda: None, clock=clock.monotonic, now=clock.now)
    await grants.ensure_meta()
    policy = load_repo_policy(POLICY_DIR)
    resolver = DefaultAccessResolver(lambda: (policy, "v1"), grants, now=clock.now)
    yield SimpleNamespace(grants=grants, resolver=resolver, policy=policy)
    await db.dispose()


async def _grant(env: SimpleNamespace, preset: Preset, **kw: Any):
    body = GrantCreate(
        **{
            "subject_type": "user",
            "subject": "jan",
            "resource_type": GrantResourceType.alias,
            "resource": "smart",
            "reason": "pilot",
            "constraints": GrantConstraints(preset=preset),
            **kw,
        }
    )
    return await env.grants.create(body, ADMIN)


async def test_monitor_user_grant_cannot_loosen_strict_group(access: SimpleNamespace) -> None:
    jan = make_principal("jan", ["credit-analysts"])  # group preset: strict
    assert access.policy.groups["credit-analysts"].preset == Preset.strict
    await _grant(access, Preset.monitor)
    assert await access.resolver.effective_preset(jan) == Preset.strict
    eff = await access.resolver.effective_access(jan)
    assert eff.preset == Preset.strict and eff.preset_source == "group:credit-analysts"


async def test_group_subject_grant_cannot_loosen_either(access: SimpleNamespace) -> None:
    await _grant(access, Preset.monitor, subject_type="group", subject="credit-analysts")
    assert await access.resolver.effective_preset(make_principal("jan", ["credit-analysts"])) == Preset.strict


async def test_grant_cannot_go_below_the_global_default(access: SimpleNamespace) -> None:
    nobody = make_principal("jan", [])  # in no policy group: global.default_preset applies
    default = access.policy.global_.default_preset
    assert default != Preset.monitor
    await _grant(access, Preset.monitor)
    assert await access.resolver.effective_preset(nobody) == default


async def test_grant_can_tighten(access: SimpleNamespace) -> None:
    g = await _grant(access, Preset.paranoid)
    preset, source = await access.resolver.effective_preset_with_source(make_principal("jan", ["credit-analysts"]))
    assert (preset, source) == (Preset.paranoid, f"grant:{g.id}")


async def test_strictest_of_several_groups_and_grants(access: SimpleNamespace) -> None:
    both = make_principal("jan", ["developers", "credit-analysts"])  # balanced + strict
    await _grant(access, Preset.balanced)
    assert await access.resolver.effective_preset(both) == Preset.strict


# ---------------------------------------------------------------- admin API rejects laxer grant presets


class Stack:
    def __init__(self, client: TestClient, key: TestKey) -> None:
        self.client, self.key = client, key

    def token(self, sub: str, username: str, groups: list[str], roles: list[str]) -> dict[str, str]:
        t = self.key.sign(claims(sub, username=username, groups=[f"/{g}" for g in groups], roles=roles))
        return {"Authorization": f"Bearer {t}"}

    @property
    def admin(self) -> dict[str, str]:
        return self.token("sub-adam", "adam", ["admins"], ["acl-user", "acl-admin"])

    def jan(self) -> dict[str, str]:
        return self.token("sub-jan", "jan", ["credit-analysts"], ["acl-user"])


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    key = TestKey("k1")
    settings = Settings(
        policy_dir=POLICY_DIR,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        oidc_issuer=ISSUER,
        oidc_audience="gateway",
        deterministic=True,
    )
    app = create_app(settings)
    app.state.audit = RecordingSink()
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(key))
    with router, TestClient(app) as client:
        yield Stack(client, key)


def test_admin_api_rejects_a_grant_preset_laxer_than_the_subject(stack: Stack) -> None:
    c = stack.client
    for h in (stack.jan(), stack.admin):
        assert c.get(f"{BASE}/me", headers=h).status_code == 200
    base = {"subject_type": "user", "subject": "jan", "resource_type": "alias", "resource": "smart", "reason": "ok!"}
    r = c.post(f"{BASE}/grants", headers=stack.admin, json={**base, "constraints": {"preset": "monitor"}})
    assert r.status_code == 422, r.text
    assert "laxer" in r.text and "strict" in r.text
    r = c.post(
        f"{BASE}/grants",
        headers=stack.admin,
        json={**base, "subject_type": "group", "subject": "credit-analysts", "constraints": {"preset": "balanced"}},
    )
    assert r.status_code == 422, r.text
    # equal or stricter is fine
    assert (
        c.post(f"{BASE}/grants", headers=stack.admin, json={**base, "constraints": {"preset": "strict"}}).status_code
        == 201
    )
    assert (
        c.post(f"{BASE}/grants", headers=stack.admin, json={**base, "constraints": {"preset": "paranoid"}}).status_code
        == 201
    )
    # now jan is paranoid: strict would be laxer
    r = c.post(f"{BASE}/grants", headers=stack.admin, json={**base, "constraints": {"preset": "strict"}})
    assert r.status_code == 422 and "paranoid" in r.text
    me = c.get(f"{BASE}/me", headers=stack.jan()).json()
    assert me["preset"] == "paranoid"


# ================================================================ findings 3 + 4: API keys


@pytest.fixture
async def auth(tmp_path: Path) -> AsyncIterator[SimpleNamespace]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'auth.db'}")
    await create_all(engine)
    sm = make_sessionmaker(engine)
    key = TestKey("k1")
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(key))
    users = UserStore(lambda: sm)
    keys = ApiKeyService(lambda: sm, PEPPER, max_group_age=timedelta(days=30))
    jwks = JwksCache(JWKS_URL, client=httpx.AsyncClient())
    audit = RecordingSink()
    authn = Authenticator(
        TokenVerifier(ISSUER, AUDIENCE, jwks), users, keys, SimpleNamespace(state=SimpleNamespace(audit=audit))
    )
    with router:
        yield SimpleNamespace(auth=authn, users=users, keys=keys, sm=sm, key=key, audit=audit)
    await engine.dispose()


def _request() -> SimpleNamespace:
    return SimpleNamespace(
        url=SimpleNamespace(path="/v1/models"), method="GET", app=SimpleNamespace(state=SimpleNamespace())
    )


def _bearer(token: str) -> HTTPAuthorizationCredentials:
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


async def _sign_in(
    env: SimpleNamespace, sub: str, username: str, groups: list[str], roles: list[str], **kw: Any
) -> UserRow:
    token = env.key.sign(claims(sub, username=username, groups=[f"/{g}" for g in groups], roles=roles, **kw))
    await env.auth(_request(), _bearer(token))
    async with env.sm() as s:
        return (await s.execute(select(UserRow).where(UserRow.subject == sub))).scalar_one()


async def _age(env: SimpleNamespace, user_id: str, days: float | None) -> None:
    async with env.sm() as s, s.begin():
        row = await s.get(UserRow, user_id)
        row.last_seen = None if days is None else utcnow() - timedelta(days=days)


async def test_api_key_carries_no_admin_panel_roles(auth: SimpleNamespace) -> None:
    user = await _sign_in(auth, "sub-adam", "adam", ["admins"], ["acl-user", "acl-admin", "acl-analyst", "acl-viewer"])
    assert "acl-admin" in user.roles
    created = await auth.keys.create(user, "laptop", None)
    p = await auth.auth(_request(), _bearer(created.key))
    assert p.auth_method == AuthMethod.api_key
    assert p.roles == ["acl-user"]  # admin-panel roles stripped, others kept
    assert p.groups == ["admins"]  # groups from the last Keycloak sign-in are kept


def test_admin_api_refuses_an_admins_api_key(stack: Stack) -> None:
    c = stack.client
    assert c.get(f"{BASE}/users", headers=stack.admin).status_code == 200  # JWT: fine (also provisions adam)
    created = c.post(f"{BASE}/users/adam/api-keys", headers=stack.admin, json={"name": "laptop"}).json()
    key = {"Authorization": f"Bearer {created['key']}"}
    for method, path in (("get", "/users"), ("get", "/policy"), ("post", "/users/adam/api-keys")):
        r = c.request(method.upper(), f"{BASE}{path}", headers=key, json={"name": "x"} if method == "post" else None)
        assert r.status_code == 403, (path, r.text)
    me = c.get(f"{BASE}/me", headers=key)  # self-service keeps working with a key
    assert me.status_code == 200 and me.json()["username"] == "adam"


async def test_api_key_refused_when_owner_groups_are_stale(auth: SimpleNamespace) -> None:
    user = await _sign_in(auth, "sub-ola", "ola", ["security-analysts"], ["acl-user"])
    created = await auth.keys.create(user, "ci", None)
    await _age(auth, user.id, 29)
    assert (await auth.auth(_request(), _bearer(created.key))).username == "ola"
    await _age(auth, user.id, 31)
    with pytest.raises(HTTPException) as exc:
        await auth.auth(_request(), _bearer(created.key))
    assert exc.value.status_code == 401 and "stale_identity" in str(exc.value.detail)
    assert any(e[1]["detail"]["reason"] == "stale_identity" for e in auth.audit.events)
    await _age(auth, user.id, None)  # never signed in with Keycloak
    with pytest.raises(HTTPException):
        await auth.auth(_request(), _bearer(created.key))
    # a fresh Keycloak sign-in refreshes the groups and revives the key
    auth.users.forget()
    await _sign_in(auth, "sub-ola", "ola", ["developers"], ["acl-user"])
    assert (await auth.auth(_request(), _bearer(created.key))).groups == ["developers"]


async def test_api_key_of_disabled_owner_still_refused(auth: SimpleNamespace) -> None:
    user = await _sign_in(auth, "sub-eve", "eve", ["developers"], ["acl-user"])
    created = await auth.keys.create(user, "ci", None)
    async with auth.sm() as s, s.begin():
        (await s.get(UserRow, user.id)).disabled = True
    with pytest.raises(HTTPException) as exc:
        await auth.auth(_request(), _bearer(created.key))
    assert exc.value.status_code == 401


def test_max_group_age_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    assert IdentityOptions().api_key_max_group_age == timedelta(days=30)
    monkeypatch.setenv("ACL_API_KEY_MAX_GROUP_AGE_DAYS", "2")
    assert IdentityOptions().api_key_max_group_age == timedelta(days=2)


async def test_short_max_group_age_is_enforced(auth: SimpleNamespace, tmp_path: Path) -> None:
    user = await _sign_in(auth, "sub-ola", "ola", ["security-analysts"], ["acl-user"])
    created = await auth.keys.create(user, "ci", None)
    await _age(auth, user.id, 3)
    strict_keys = ApiKeyService(lambda: auth.sm, PEPPER, max_group_age=timedelta(days=2))
    with pytest.raises(Exception, match="stale_identity"):
        await strict_keys.authenticate(created.key)


async def test_agent_api_key_keeps_kind_and_agent_id(auth: SimpleNamespace) -> None:
    user = await _sign_in(
        auth,
        "sa-1",
        "service-account-agent-research-bot",
        ["agents/research-bot"],
        [],
        azp="agent-research-bot",
        agent_id="research-bot",
    )
    assert user.kind == "agent"
    created = await auth.keys.create(user, "bot", None)
    p = await auth.auth(_request(), _bearer(created.key))
    assert p.kind == PrincipalKind.agent and p.agent_id == "research-bot"
    assert p.auth_method == AuthMethod.api_key and p.groups == ["agents/research-bot"]


async def test_service_account_username_alone_marks_an_agent(auth: SimpleNamespace) -> None:
    user = await _sign_in(auth, "sa-2", "service-account-agent-ops", ["agents"], [])
    async with auth.sm() as s, s.begin():
        (await s.get(UserRow, user.id)).kind = "user"  # e.g. provisioned before agent detection
    created = await auth.keys.create(user, "bot", None)
    p = await auth.auth(_request(), _bearer(created.key))
    assert p.kind == PrincipalKind.agent and p.agent_id == "ops"
    async with auth.sm() as s:
        row = await s.get(UserRow, user.id)
    assert principal_from_row(row).agent_id == "ops"
