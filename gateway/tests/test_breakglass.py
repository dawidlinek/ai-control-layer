"""Break-glass: audited reveal of raw event content (reason, own audit event, incident, no reveal without audit)."""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from acl.contracts.common import AuthMethod, PrincipalKind
from acl.contracts.inspection import Principal
from acl.main import create_app
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
ADMIN = {"X-ACL-Dev-User": "adam", "X-ACL-Dev-Roles": "acl-admin"}
ANALYST = {"X-ACL-Dev-User": "ola", "X-ACL-Dev-Roles": "acl-analyst"}
VIEWER = {"X-ACL-Dev-User": "vera", "X-ACL-Dev-Roles": "acl-viewer"}
ANNA = {"X-ACL-Dev-User": "anna", "X-ACL-Dev-Groups": "operations"}
REASON = "verifying a false-negative report INC-0049"


def build(tmp: Path, *, store_raw: bool = False) -> Any:
    policy = tmp / "policy"
    shutil.copytree(REPO / "policy", policy)
    if store_raw:
        path = policy / "controls.yaml"
        text = path.read_text(encoding="utf-8")
        assert "store_raw_payloads: false" in text
        path.write_text(text.replace("store_raw_payloads: false", "store_raw_payloads: true"), "utf-8", newline="\n")
    settings = Settings(
        policy_dir=policy,
        database_url=f"sqlite+aiosqlite:///{tmp / 'acl.db'}",
        audit_path=tmp / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    return create_app(settings, allow_anonymous_dev=True)


@pytest.fixture
def harness(tmp_path: Path) -> Iterator[tuple[TestClient, Any, Path]]:
    app = build(tmp_path)
    with TestClient(app) as client:
        yield client, app, tmp_path / "audit.jsonl"


def provision(client: TestClient, name: str, groups: list[str]) -> None:
    """The user row that a Keycloak sign-in would create (dev headers do not provision)."""
    principal = Principal(
        subject=f"dev-{name}", kind=PrincipalKind.user, username=name, groups=groups, auth_method=AuthMethod.none
    )
    client.portal.call(client.app.state.identity.users.provision, principal)  # type: ignore[union-attr,attr-defined]


def anna_event(client: TestClient) -> tuple[str, str]:
    """(anna's user id, id of one of her decision events)."""
    provision(client, "anna", ["operations"])
    r = client.post(
        "/v1/chat/completions",
        json={"model": "local", "messages": [{"role": "user", "content": "hello there"}]},
        headers=ANNA,
    )
    assert r.status_code == 200, r.text
    users = client.get("/admin/v1/users", headers=ADMIN).json()
    uid = next(u["id"] for u in users if u["username"] == "anna")
    events = client.get("/admin/v1/events", headers=ADMIN, params={"limit": 50}).json()
    items = events if isinstance(events, list) else events["items"]
    mine = [e for e in items if e.get("username") == "anna"]
    assert mine, items
    return uid, mine[0]["event_id"]


def audit_lines(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_breakglass_is_audited_opens_an_incident_and_reports_raw_not_retained(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, audit_path = harness
    uid, event_id = anna_event(client)
    r = client.post(f"/admin/v1/users/{uid}/breakglass", headers=ANALYST, json={"event_id": event_id, "reason": REASON})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["event_id"] == event_id and body["raw_payload"] is None and body["available"] is False

    records = audit_lines(audit_path)
    [bg] = [x for x in records if x["event_type"] == "breakglass"]
    assert bg["event_id"] == body["audit_event_id"] and bg["principal"]["username"] == "ola"
    assert bg["detail"]["reason"] == REASON and bg["detail"]["target_event_id"] == event_id
    assert bg["detail"]["subject_username"] == "anna" and bg["detail"]["available"] is False
    assert bg["detail"]["visible_for_s"] == 300 and "raw_payload" not in json.dumps(bg)
    incidents = client.get("/admin/v1/incidents", headers=ADMIN).json()
    items = incidents if isinstance(incidents, list) else incidents["items"]
    assert any(i["category"] == "break_glass" and event_id in i["event_ids"] for i in items)


def test_breakglass_input_checks_and_roles(harness) -> None:  # type: ignore[no-untyped-def]
    client, _, audit_path = harness
    uid, event_id = anna_event(client)
    url = f"/admin/v1/users/{uid}/breakglass"
    ok = {"event_id": event_id, "reason": REASON}
    assert client.post(url, headers=VIEWER, json=ok).status_code == 403
    assert client.post(url, headers=ANNA, json=ok).status_code == 403
    assert client.post(url, headers=ADMIN, json={"event_id": event_id, "reason": "short"}).status_code == 422
    blank = {"event_id": event_id, "reason": " " * 6 + "ab" + " " * 6}
    assert client.post(url, headers=ADMIN, json=blank).status_code == 422  # blanks do not count as a reason
    assert client.post(url, headers=ADMIN, json={"event_id": "nope", "reason": REASON}).status_code == 404
    assert client.post("/admin/v1/users/nobody/breakglass", headers=ADMIN, json=ok).status_code == 404
    provision(client, "jan", ["credit-analysts"])
    jan = next(u["id"] for u in client.get("/admin/v1/users", headers=ADMIN).json() if u["username"] == "jan")
    assert (
        client.post(f"/admin/v1/users/{jan}/breakglass", headers=ADMIN, json=ok).status_code == 404
    )  # not jan's event
    assert not [
        x for x in audit_lines(audit_path) if x["event_type"] == "breakglass"
    ]  # refusals reveal and log nothing


def test_breakglass_returns_raw_only_within_retention_and_after_the_audit_record(tmp_path: Path) -> None:
    app = build(tmp_path, store_raw=True)
    with TestClient(app) as client:
        uid, event_id = anna_event(client)
        order: list[str] = []

        class Store:
            async def get(self, eid: str) -> str | None:
                order.append("read")
                return "RAW: hello there" if eid == event_id else None

        real_record = app.state.audit.record_event

        async def record_event(*a: Any, **kw: Any) -> Any:
            order.append("audit")
            return await real_record(*a, **kw)

        app.state.audit.record_event = record_event
        app.state.raw_payloads = Store()
        url = f"/admin/v1/users/{uid}/breakglass"
        r = client.post(url, headers=ADMIN, json={"event_id": event_id, "reason": REASON})
        assert r.status_code == 200 and r.json()["raw_payload"] == "RAW: hello there" and r.json()["available"] is True
        assert order[0] == "read" and "audit" in order  # the audit record is written before the response is returned

        async def failing(*a: Any, **kw: Any) -> Any:
            raise RuntimeError("chain unavailable")

        app.state.audit.record_event = failing
        denied = client.post(url, headers=ADMIN, json={"event_id": event_id, "reason": REASON})
        assert denied.status_code == 503 and "RAW" not in denied.text  # no audit record, no reveal


def test_breakglass_does_not_touch_enforcement(harness) -> None:  # type: ignore[no-untyped-def]
    client, app, _ = harness
    uid, event_id = anna_event(client)
    before = (app.state.engine.policy.org_locks, [c.id for c in app.state.engine.policy.controls])
    client.post(f"/admin/v1/users/{uid}/breakglass", headers=ADMIN, json={"event_id": event_id, "reason": REASON})
    assert (app.state.engine.policy.org_locks, [c.id for c in app.state.engine.policy.controls]) == before
