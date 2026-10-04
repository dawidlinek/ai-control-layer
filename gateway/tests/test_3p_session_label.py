"""SEC-SESSION-01 end to end: once a session is confidential, every later request stays local and says why."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from acl.contracts.common import DataClass, Integrity
from acl.contracts.inspection import SessionLabels
from acl.main import create_app
from acl.sessions.store import merge_labels
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
PESEL = "44051401359"  # synthetic, checksum-valid
OPS = {"X-ACL-Dev-User": "ewa", "X-ACL-Dev-Groups": "operations"}  # operations may use `smart` (cloud)
VIEWER = {"X-ACL-Dev-User": "vera", "X-ACL-Dev-Groups": "security-analysts", "X-ACL-Dev-Roles": "acl-viewer"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    settings = Settings(
        policy_dir=REPO / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    with TestClient(create_app(settings, allow_anonymous_dev=True)) as c:
        yield c


def chat(client: TestClient, text: str, *, session: str, model: str = "smart") -> Any:
    return client.post(
        "/v1/chat/completions",
        json={"model": model, "messages": [{"role": "user", "content": text}]},
        headers={**OPS, "X-Session-Id": session},
    )


def test_confidential_session_keeps_later_harmless_requests_local(client: TestClient) -> None:
    first = chat(client, "Hello, what can you do?", session="s-clean")
    assert first.status_code == 200, first.text
    assert first.headers["x-acl-model"] == "gemini/flash"
    assert "x-acl-session-label" not in first.headers

    sensitive = chat(client, f"Customer PESEL {PESEL}, please check the record.", session="s-conf")
    assert sensitive.status_code == 200, sensitive.text
    assert sensitive.headers["x-acl-model"].startswith("local/")  # this request itself: data class → local

    later = chat(client, "Thanks. Now give me three title ideas for the report.", session="s-conf")
    assert later.status_code == 200, later.text
    assert later.headers["x-acl-model"].startswith("local/")
    assert later.headers["x-acl-decision"] == "route_local"
    assert later.headers["x-acl-session-label"] == "confidential; local-only; rule=SEC-SESSION-01"

    events = client.get("/admin/v1/events", params={"rule_id": "SEC-SESSION-01"}, headers=VIEWER).json()
    assert events, "the session rule must be visible in the audit index"
    record = client.get(f"/admin/v1/events/{events[0]['event_id']}", headers=VIEWER).json()
    assert record["labels_after"]["confidentiality"] == "confidential"
    assert record["labels_after"]["since"] is not None
    assert "SEC-SESSION-01" in record["decision"]["rule_ids"]
    assert record["route"]["tier"] == "local"

    other = chat(client, "Thanks. Now give me three title ideas for the report.", session="s-clean")
    assert other.headers["x-acl-model"] == "gemini/flash", "another session of the same user is not affected"


def test_since_is_the_time_the_level_was_first_reached() -> None:
    t0 = datetime(2026, 10, 4, 14, 3, tzinfo=UTC)
    stored = SessionLabels(confidentiality=DataClass.confidential, since=t0)
    later = SessionLabels(confidentiality=DataClass.confidential, since=t0 + timedelta(minutes=5))
    assert merge_labels(stored, later).since == t0
    up = SessionLabels(confidentiality=DataClass.restricted, since=t0 + timedelta(minutes=9))
    merged = merge_labels(stored, up)
    assert merged.confidentiality == DataClass.restricted and merged.since == t0 + timedelta(minutes=9)
    untrusted = SessionLabels(integrity=Integrity.untrusted)
    assert merge_labels(stored, untrusted).since == t0
