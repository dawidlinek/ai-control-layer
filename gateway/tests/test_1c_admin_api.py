"""Admin access API through the real app: JWT auth, JIT users, grants, API keys, effective access, /me."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import respx
from fastapi.testclient import TestClient

from acl.audit.sink import RecordingSink
from acl.contracts.audit import EventType
from acl.identity.testing import ISSUER, TestKey, claims, jwks_document
from acl.main import create_app
from acl.settings import Settings

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"
JWKS_URL = f"{ISSUER}/protocol/openid-connect/certs"
BASE = "/admin/v1"


class Stack:
    def __init__(self, client: TestClient, key: TestKey, audit: RecordingSink) -> None:
        self.client, self.key, self.audit = client, key, audit

    def token(self, sub: str, username: str, groups: list[str], roles: list[str] | None = None) -> dict[str, str]:
        t = self.key.sign(claims(sub, username=username, groups=[f"/{g}" for g in groups], roles=roles or []))
        return {"Authorization": f"Bearer {t}"}

    @property
    def admin(self) -> dict[str, str]:
        return self.token("sub-adam", "adam", ["admins"], ["acl-user", "acl-admin"])

    @property
    def viewer(self) -> dict[str, str]:
        return self.token("sub-ola", "ola", ["security-analysts"], ["acl-user", "acl-viewer"])

    def jan(self) -> dict[str, str]:
        return self.token("sub-jan", "jan", ["credit-analysts"], ["acl-user"])

    def anna(self) -> dict[str, str]:
        return self.token("sub-anna", "anna", ["developers"], ["acl-user"])


@pytest.fixture
def stack(tmp_path: Path) -> Iterator[Stack]:
    key = TestKey("k1")
    settings = Settings(
        policy_dir=POLICY_DIR,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'api.db'}",
        oidc_issuer=ISSUER,
        oidc_audience="gateway",
    )
    app = create_app(settings)
    audit = RecordingSink()
    app.state.audit = audit
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(key))
    with router, TestClient(app) as client:
        yield Stack(client, key, audit)


def provision(stack: Stack) -> None:
    for headers in (stack.jan(), stack.anna(), stack.viewer, stack.admin):
        assert stack.client.get(f"{BASE}/me", headers=headers).status_code == 200


def test_unauthenticated_and_underprivileged(stack: Stack) -> None:
    c = stack.client
    r = c.get(f"{BASE}/users")
    assert r.status_code == 401 and r.headers["www-authenticate"] == "Bearer"
    assert c.get(f"{BASE}/users", headers={"Authorization": "Bearer garbage"}).status_code == 401
    assert c.get(f"{BASE}/users", headers=stack.anna()).status_code == 403  # no panel role
    assert c.get(f"{BASE}/users", headers=stack.viewer).status_code == 200
    assert c.post(f"{BASE}/grants", headers=stack.viewer, json={}).status_code in (403, 422)
    assert any(e[0] == EventType.auth_failure for e in stack.audit.events)


def test_users_are_provisioned_on_first_request(stack: Stack) -> None:
    c = stack.client
    assert c.get(f"{BASE}/users", headers=stack.viewer).json()[0]["username"] == "ola"
    provision(stack)
    users = c.get(f"{BASE}/users", headers=stack.viewer).json()
    assert [u["username"] for u in users] == ["adam", "anna", "jan", "ola"]
    jan = next(u for u in users if u["username"] == "jan")
    assert jan["groups"] == ["credit-analysts"] and jan["kind"] == "user" and jan["first_seen"]
    assert [
        u["username"] for u in c.get(f"{BASE}/users", params={"group": "developers"}, headers=stack.viewer).json()
    ] == ["anna"]
    assert [u["username"] for u in c.get(f"{BASE}/users", params={"q": "JA"}, headers=stack.viewer).json()] == ["jan"]
    assert c.get(f"{BASE}/users/{jan['id']}", headers=stack.viewer).json()["subject"] == "sub-jan"
    assert c.get(f"{BASE}/users/jan", headers=stack.viewer).json()["id"] == jan["id"]  # username works too
    assert c.get(f"{BASE}/users/nobody", headers=stack.viewer).status_code == 404


def test_me_and_effective_access(stack: Stack) -> None:
    provision(stack)
    me = stack.client.get(f"{BASE}/me", headers=stack.jan()).json()
    assert me["username"] == "jan" and me["preset"] == "strict" and me["preset_source"] == "group:credit-analysts"
    assert {(i["resource_type"], i["resource"]) for i in me["items"]} >= {("alias", "auto"), ("tool", "bank.query")}
    eff = stack.client.get(f"{BASE}/users/jan/effective-access", headers=stack.viewer).json()
    assert eff["items"] == me["items"] and eff["policy_version"]
    assert eff["grants_version"].isdigit()


def test_grant_lifecycle_and_changes(stack: Stack) -> None:
    c = stack.client
    provision(stack)
    body = {
        "subject_type": "user",
        "subject": "jan",
        "resource_type": "alias",
        "resource": "smart",
        "reason": "Gemini pilot",
        "expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat(),
        "constraints": {"data_classes": ["public", "internal"]},
    }
    assert c.post(f"{BASE}/grants", headers=stack.viewer, json=body).status_code == 403
    r = c.post(f"{BASE}/grants", headers=stack.admin, json=body)
    assert r.status_code == 201
    g = r.json()
    assert g["active"] and g["created_by"] == "adam" and g["effect"] == "allow"

    before = c.get(f"{BASE}/users/jan/effective-access", headers=stack.viewer).json()
    item = next(i for i in before["items"] if i["source_ref"] == g["id"])
    assert (
        item["source"] == "user"
        and item["expires_at"]
        and item["constraints"]["data_classes"] == ["public", "internal"]
    )

    assert [x["id"] for x in c.get(f"{BASE}/grants", headers=stack.viewer).json()] == [g["id"]]
    assert c.get(f"{BASE}/grants", headers=stack.viewer, params={"subject": "anna"}).json() == []

    rv = c.delete(f"{BASE}/grants/{g['id']}", headers=stack.admin, params={"reason": "pilot over"})
    assert rv.status_code == 200 and rv.json()["revoked_by"] == "adam" and not rv.json()["active"]
    after = c.get(f"{BASE}/users/jan/effective-access", headers=stack.viewer).json()  # effective on the next call
    assert all(i["source_ref"] != g["id"] for i in after["items"])
    assert int(after["grants_version"]) == int(before["grants_version"]) + 1
    assert c.delete(f"{BASE}/grants/{g['id']}", headers=stack.admin, params={"reason": "again"}).status_code == 409
    assert c.delete(f"{BASE}/grants/nope", headers=stack.admin, params={"reason": "nope"}).status_code == 404
    assert c.get(f"{BASE}/grants", headers=stack.viewer).json() == []
    assert len(c.get(f"{BASE}/grants", headers=stack.viewer, params={"active": "false"}).json()) == 1

    changes = c.get(f"{BASE}/grants/changes", headers=stack.viewer, params={"subject": "jan"}).json()
    assert [x["change"] for x in changes] == ["revoke", "create"]
    assert changes[0]["reason"] == "pilot over" and changes[1]["snapshot"]["revoked_at"] is None

    assert [e[1]["detail"]["change"] for e in stack.audit.events if e[0] == EventType.grant_change] == [
        "create",
        "revoke",
    ]


def test_grant_validation(stack: Stack) -> None:
    c, h = stack.client, stack.admin
    base = {"subject_type": "user", "subject": "jan", "resource_type": "alias", "resource": "smart", "reason": "ok!"}
    assert c.post(f"{BASE}/grants", headers=h, json={**base, "resource": "gpt-5"}).status_code == 422
    assert (
        c.post(f"{BASE}/grants", headers=h, json={**base, "resource_type": "tool", "resource": "x.y"}).status_code
        == 422
    )
    past = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
    assert c.post(f"{BASE}/grants", headers=h, json={**base, "expires_at": past}).status_code == 422
    assert c.post(f"{BASE}/grants", headers=h, json={**base, "reason": "x"}).status_code == 422
    assert c.delete(f"{BASE}/grants/x", headers=h, params={"reason": "  "}).status_code == 422
    # an explicit deny on something unknown is harmless and allowed; a valid group grant works
    assert (
        c.post(
            f"{BASE}/grants", headers=h, json={**base, "subject_type": "group", "subject": "/credit-analysts"}
        ).status_code
        == 201
    )
    assert c.get(f"{BASE}/grants", headers=h).json()[0]["subject"] == "credit-analysts"


def test_api_key_lifecycle(stack: Stack) -> None:
    c = stack.client
    provision(stack)
    r = c.post(f"{BASE}/users/jan/api-keys", headers=stack.admin, json={"name": "laptop"})
    assert r.status_code == 201
    created = r.json()
    key = created["key"]
    assert key.startswith("acl_") and created["prefix"] == key[:12] and created["user_id"]
    assert c.post(f"{BASE}/users/jan/api-keys", headers=stack.viewer, json={"name": "x"}).status_code == 403

    listed = c.get(f"{BASE}/users/jan/api-keys", headers=stack.viewer).json()
    assert [k["id"] for k in listed] == [created["id"]] and "key" not in listed[0]

    me = c.get(f"{BASE}/me", headers={"Authorization": f"Bearer {key}"})
    assert me.status_code == 200 and me.json()["username"] == "jan"
    assert c.get(f"{BASE}/users/jan/api-keys", headers=stack.viewer).json()[0]["last_used_at"]

    rv = c.delete(f"{BASE}/api-keys/{created['id']}", headers=stack.admin)
    assert rv.status_code == 200 and rv.json()["revoked_at"]
    assert c.get(f"{BASE}/me", headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert c.delete(f"{BASE}/api-keys/nope", headers=stack.admin).status_code == 404
    assert c.post(f"{BASE}/users/ghost/api-keys", headers=stack.admin, json={"name": "x"}).status_code == 404


def test_groups_union_policy_and_keycloak(stack: Stack) -> None:
    provision(stack)
    stack.client.get(f"{BASE}/me", headers=stack.token("sub-x", "xena", ["contractors"]))
    groups = {g["name"]: g for g in stack.client.get(f"{BASE}/groups", headers=stack.viewer).json()}
    assert groups["developers"]["source"] == "both" and groups["developers"]["members"] == 1
    assert groups["developers"]["preset"] == "balanced"
    assert groups["contractors"]["source"] == "keycloak" and groups["contractors"]["members"] == 1
    assert groups["agents/research-bot"]["source"] == "policy" and groups["agents/research-bot"]["members"] == 0


def test_pending_event_store_endpoints_stay_501(stack: Stack) -> None:
    c = stack.client
    assert c.get(f"{BASE}/users/jan/activity", headers=stack.viewer).status_code in (403, 501)
    analyst = stack.token("sub-ola", "ola", ["security-analysts"], ["acl-analyst"])
    assert c.get(f"{BASE}/users/jan/activity", headers=analyst).status_code == 501
    body = {"event_id": "e1", "reason": "investigating incident 42"}
    assert c.post(f"{BASE}/users/jan/breakglass", headers=stack.admin, json=body).status_code == 501


def test_health_and_readiness_do_not_need_auth(stack: Stack) -> None:
    assert stack.client.get("/healthz").status_code == 200
    assert stack.client.get("/readyz").json()["status"] == "ok"


def test_anonymous_dev_flag_never_bypasses_presented_credentials(tmp_path: Path) -> None:
    settings = Settings(
        policy_dir=POLICY_DIR,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'dev.db'}",
        oidc_issuer=ISSUER,
        oidc_audience="gateway",
    )
    router = respx.mock(assert_all_called=False)
    router.get(JWKS_URL).respond(json=jwks_document(TestKey("k1")))
    with router, TestClient(create_app(settings, allow_anonymous_dev=True)) as client:
        assert client.get(f"{BASE}/users").status_code == 200  # no credentials: dev principal (tests only)
        assert client.get(f"{BASE}/users", headers={"Authorization": "Bearer garbage"}).status_code == 401
    with TestClient(create_app(settings)) as client:
        assert client.get(f"{BASE}/users").status_code == 401
