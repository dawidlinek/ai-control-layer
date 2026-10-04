"""Plugin-bypass detection: the model emitted an `opencode.*` tool call, the client returned its result, but the
managed plugin never asked `/v1/decide` → `incident` (category `plugin_bypass`)."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from acl.approvals.bypass import BypassDetector
from acl.main import create_app
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
ANNA = {"X-ACL-Dev-User": "anna", "X-ACL-Dev-Groups": "developers"}
BOB = {"X-ACL-Dev-User": "bob", "X-ACL-Dev-Groups": "developers"}


@pytest.fixture
def app(tmp_path: Path) -> Iterator[Any]:
    settings = Settings(
        policy_dir=REPO / "policy",
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    application = create_app(settings, allow_anonymous_dev=True)
    with TestClient(application) as client:
        application.state.test_client = client
        yield application


def incidents(app: Any) -> list[dict[str, Any]]:
    path: Path = app.state.settings.audit_path
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    return [r for r in rows if r["event_type"] == "incident" and r["detail"].get("category") == "plugin_bypass"]


def ask_model(
    app: Any, tool: str, args: dict[str, Any], session: str = "oc-b", who: dict[str, str] = ANNA
) -> dict[str, Any]:
    body = {
        "model": "local",
        "messages": [{"role": "user", "content": f"[[mock:tool {tool} {json.dumps(args)}]]"}],
    }
    r = app.state.test_client.post("/v1/chat/completions", json=body, headers={**who, "X-Session-Id": session})
    assert r.status_code == 200, r.text
    calls = r.json()["choices"][0]["message"]["tool_calls"]
    assert calls
    return calls[0]


def send_result(
    app: Any, call: dict[str, Any], session: str = "oc-b", who: dict[str, str] = ANNA, content: str = "result"
) -> None:
    msgs = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": None, "tool_calls": [call]},
        {"role": "tool", "tool_call_id": call["id"], "content": content},
    ]
    r = app.state.test_client.post(
        "/v1/chat/completions",
        json={"model": "local", "messages": msgs},
        headers={**who, "X-Session-Id": session},
    )
    assert r.status_code == 200, r.text


def decide(
    app: Any, tool: str, args: dict[str, Any], call_id: str | None, session: str = "oc-b", who: dict[str, str] = ANNA
) -> dict[str, Any]:
    action: dict[str, Any] = {"tool": tool, "arguments": args, "workspace_root": "/w", "cwd": "/w"}
    if call_id:
        action["tool_call_id"] = call_id
    r = app.state.test_client.post("/v1/decide", json={"session_id": session, "action": action}, headers=who)
    assert r.status_code == 200
    return r.json()


def test_undecided_client_tool_result_raises_an_incident(app) -> None:
    call = ask_model(app, "read", {"filePath": "src/a.py"})
    send_result(app, call)  # the plugin never called /v1/decide
    found = incidents(app)
    assert len(found) == 1
    d = found[0]["detail"]
    assert d["tool"] == "opencode.read" and d["rule_id"] == "SEC-TOOL-01.BYPASS"
    assert found[0]["severity"] == "high" and found[0]["principal"]["username"] == "anna"
    assert "src/a.py" not in json.dumps(found[0])  # no arguments, no results
    assert d["tool_call_id_hash"] and call["id"] not in json.dumps(found[0]["detail"])
    assert app.state.bypass_detector.reported == [d["tool_call_id_hash"]]


def test_decided_call_is_clean(app) -> None:
    call = ask_model(app, "read", {"filePath": "src/a.py"})
    assert decide(app, "opencode.read", {"filePath": "src/a.py"}, call["id"])["action"] == "allow"
    send_result(app, call)
    assert incidents(app) == []


def test_blocked_decision_still_counts_as_decided(app) -> None:
    call = ask_model(app, "read", {"filePath": "~/.ssh/id_rsa"})
    assert decide(app, "opencode.read", {"filePath": "~/.ssh/id_rsa"}, call["id"])["action"] == "block"
    send_result(app, call)  # the client ignored the block, but it did ask: not a plugin bypass
    assert incidents(app) == []


def test_history_replays_do_not_double_report(app) -> None:
    call = ask_model(app, "bash", {"command": "ls"})
    send_result(app, call)
    send_result(app, call)
    send_result(app, call)
    assert len(incidents(app)) == 1


def test_other_sessions_and_principals_do_not_mix(app) -> None:
    call = ask_model(app, "read", {"filePath": "a.py"}, session="s1")
    decide(app, "opencode.read", {"filePath": "a.py"}, call["id"], session="s2")  # a different session
    decide(app, "opencode.read", {"filePath": "a.py"}, call["id"], session="s1", who=BOB)  # a different principal
    send_result(app, call, session="s1")
    assert len(incidents(app)) == 1


def test_mcp_and_unknown_tools_are_not_client_local(app) -> None:
    call = ask_model(app, "files_read_file", {"path": "/data/x"})  # MCP tool: governed by the proxy, not /v1/decide
    send_result(app, call)
    call2 = ask_model(app, "mystery_tool", {}, session="oc-c")
    send_result(app, call2, session="oc-c")
    assert incidents(app) == []


def test_result_for_a_call_the_gateway_never_saw_is_ignored(app) -> None:
    ghost = {"id": "call_ghost", "type": "function", "function": {"name": "read", "arguments": "{}"}}
    send_result(app, ghost)
    assert incidents(app) == []


def test_decide_before_the_model_response_is_registered_still_counts(app) -> None:
    det: BypassDetector = app.state.bypass_detector
    det._put("sess", "c1", "opencode.read").decided = True
    det._put("sess", "c1", "opencode.read").emitted = True
    rec = det._calls("sess")["c1"]
    assert rec.emitted and rec.decided


def test_detector_is_bounded_and_expires() -> None:
    now = [0.0]
    det = BypassDetector(app=None, ttl_s=10, max_sessions=2, max_calls=3, clock=lambda: now[0])
    for i in range(5):
        det._put("s", f"c{i}", "opencode.read")
    assert len(det._calls("s")) == 3 and "c0" not in det._calls("s")
    det._put("s2", "x", None)
    det._put("s3", "x", None)
    assert len(det._sessions) == 2
    now[0] = 100.0
    assert not det._calls("s3")
