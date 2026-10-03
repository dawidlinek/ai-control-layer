from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from acl.main import create_app
from acl.routing.connectors.base import ConnectorError
from acl.routing.connectors.mock import MockConnector
from acl.settings import Settings

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


def _req(text: str) -> dict:
    return {"messages": [{"role": "user", "content": text}]}


async def test_mock_echo_is_deterministic() -> None:
    c = MockConnector()
    a = await c.chat("m", _req("hi there"))
    b = await c.chat("m", _req("hi there"))
    assert a.body["choices"][0]["message"]["content"] == "MOCK[m]: hi there"
    assert a.usage.output_tokens == b.usage.output_tokens > 0


async def test_mock_directives() -> None:
    c = MockConnector()
    r = await c.chat("m", _req('[[mock:tool mail.send {"to": "x@evil.tld"}]]'))
    tc = r.body["choices"][0]["message"]["tool_calls"][0]
    assert tc["function"]["name"] == "mail.send" and json.loads(tc["function"]["arguments"])["to"] == "x@evil.tld"
    r = await c.chat("m", _req("[[mock:reasoning secret plan]]"))
    assert r.body["choices"][0]["message"]["reasoning_content"] == "secret plan"
    assert "logprobs" in r.body["choices"][0]
    with pytest.raises(ConnectorError):
        await c.chat("m", _req("[[mock:error 503]]"))


async def test_mock_stream_reassembles() -> None:
    c = MockConnector()
    parts, last = [], None
    async for ch in c.chat_stream("m", _req("[[mock:reply " + "abc " * 20 + "]]")):
        delta = ch.body["choices"][0]["delta"]
        parts.append(delta.get("content", ""))
        last = ch
    assert "".join(parts) == ("abc " * 20).strip()
    assert last is not None and last.usage is not None


def test_health_and_ready() -> None:
    app = create_app(Settings(policy_dir=POLICY_DIR))
    with TestClient(app) as client:
        assert client.get("/healthz").json()["status"] == "ok"
        ready = client.get("/readyz").json()
        assert ready["status"] == "ok" and ready["checks"]["policy"].startswith("v")


def test_admin_api_requires_auth() -> None:
    app = create_app(Settings(policy_dir=POLICY_DIR))
    with TestClient(app) as client:
        assert client.get("/admin/v1/policy").status_code == 401
        assert client.post("/v1/decide", json={}).status_code in (401, 422)


def test_not_ready_on_invalid_policy(tmp_path: Path) -> None:
    (tmp_path / "bad.yaml").write_text("controls: [1\n", encoding="utf-8")
    app = create_app(Settings(policy_dir=tmp_path))
    with TestClient(app) as client:
        assert client.get("/readyz").json()["status"] == "down"


def test_readyz_down_when_a_control_service_is_not_wired(tmp_path: Path) -> None:
    settings = Settings(
        policy_dir=POLICY_DIR, deterministic=True, database_url=f"sqlite+aiosqlite:///{tmp_path / 'r.db'}"
    )
    with TestClient(create_app(settings)) as client:
        body = client.get("/readyz").json()
        assert body["status"] == "ok", body
        assert body["checks"]["service:access"] == "ok"
    with TestClient(create_app(settings, installers=["acl.policy.wiring:install"])) as client:
        body = client.get("/readyz").json()
        assert body["status"] == "down" and body["checks"]["service:access"].startswith("missing")
