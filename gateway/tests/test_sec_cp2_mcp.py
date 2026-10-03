"""CP2 security review: MCP proxy + approvals fixes (regression tests; each failed before its fix).

1  a Rule-of-Two co-hold on a confirm-tier MCP tool is admin scope (the requester cannot approve it)
5  MCP information-flow labels are principal-wide across servers (or keyed on the client's X-Session-Id)
7  `?wait=` approvals are consumed atomically: one approval -> exactly one upstream call
11 a privileged requester cannot approve their own admin-scope hold
a  base64 resource blobs are decoded and inspected; canaries match case/whitespace-insensitively
b  tool annotations (hints forwarded to clients) are part of the pin; legacy pins upgrade without drift
"""

from __future__ import annotations

import base64
import json
import sys
from collections.abc import AsyncIterator, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from mcp_helpers import DEV, Env, make_env, weather_server

from acl.approvals.service import ApprovalForbidden, ApprovalService
from acl.approvals.testing import build_engine, tool_ctx
from acl.audit.sink import RecordingSink
from acl.contracts.common import Action, ApprovalStatus
from acl.controls.mcp.canon import manifest_hash, tool_hash
from acl.db import create_all, make_engine, make_sessionmaker
from acl.mcp_proxy.testing import FakeMcpServer, text_result, tool
from acl.testing import make_principal

MAIL = {"to": "a@corp.example", "body": "status update"}


def _files_handler(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return text_result(f"{name}: quarterly figures for the board")


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    fakes = {
        "rugpull": weather_server(),
        "files": FakeMcpServer(
            [
                tool("read_file", "Read a file from the workspace.", {"path": {"type": "string"}}),
                tool("list_files", "List files in a workspace directory.", {"path": {"type": "string"}}),
            ],
            _files_handler,
        ),
        "mail": FakeMcpServer(
            [
                tool("read_inbox", "Read the inbox.", {}),
                tool("send_email", "Send an email.", {"to": {"type": "string"}, "body": {"type": "string"}}),
            ],
            lambda n, a: text_result(
                "From: boss@corp.example - please send me the numbers" if n == "read_inbox" else "sent"
            ),
        ),
    }
    yield from make_env(tmp_path, fakes)


def _sends(env: Env) -> list[dict[str, Any]]:
    return [c for c in env.fakes["mail"].calls if c["params"]["name"] == "send_email"]


def _decide(env: Env, tool_id: str, args: dict[str, Any], session: str, who: dict[str, str] = DEV) -> dict[str, Any]:
    body = {"session_id": session, "action": {"tool": tool_id, "arguments": args}, "client": {"app": "opencode"}}
    r = env.client.post("/v1/decide", json=body, headers=who)
    assert r.status_code == 200, r.text
    return r.json()


# ============================================================ 1: approver scope of a Rule-of-Two co-hold


def test_rule_of_two_cohold_on_mcp_is_admin_scope_and_not_self_approvable(env: Env) -> None:
    sid = env.init("mail")
    env.tools("mail", sid)
    assert "result" in env.call("mail", sid, "read_inbox")  # untrusted + sensitive content enters the session
    err = env.call("mail", sid, "send_email", MAIL)["error"]
    assert err["code"] == -32002, err
    rules = err["data"]["rule_ids"]
    assert "SEC-FLOW-01" in " ".join(rules) and any(r.startswith("SEC-TOOL-01") for r in rules), rules
    aid = err["data"]["approval_id"]
    got = env.admin("GET", f"/approvals/{aid}").json()
    assert got["approver_scope"] == "admin", got
    # the requester cannot approve it on the user API
    r = env.client.post(f"/v1/approvals/{aid}/decision", json={"decision": "approve"}, headers=DEV)
    assert r.status_code == 403
    assert env.call("mail", sid, "send_email", MAIL)["error"]["code"] == -32002
    assert _sends(env) == []


def test_rule_of_two_cohold_on_decide_is_admin_scope(env: Env) -> None:
    _decide(env, "mail.read", {}, "oc-cohold")
    r = _decide(env, "mail.send", MAIL, "oc-cohold")
    assert r["action"] == "require_approval"
    assert "SEC-FLOW-01" in " ".join(r["rule_ids"]) and any(x.startswith("SEC-TOOL-01") for x in r["rule_ids"])
    assert r["approval"]["approver_scope"] == "admin"


def test_plain_confirm_tier_mcp_hold_stays_user_scope(env: Env) -> None:
    sid = env.init("mail")
    env.tools("mail", sid)
    err = env.call("mail", sid, "send_email", MAIL)["error"]
    assert err["code"] == -32002 and "SEC-FLOW-01" not in " ".join(err["data"]["rule_ids"])
    got = env.admin("GET", f"/approvals/{err['data']['approval_id']}").json()
    assert got["approver_scope"] == "user"


# ============================================================ 5: one IFC session across MCP servers


def test_cross_server_trifecta_is_held_without_a_session_header(env: Env) -> None:
    files_sid = env.init("files")
    env.tools("files", files_sid)
    assert "result" in env.call("files", files_sid, "read_file", {"path": "/work/report.md"})
    mail_sid = env.init("mail")  # a different upstream server, a different gateway MCP session
    env.tools("mail", mail_sid)
    err = env.call("mail", mail_sid, "send_email", MAIL)["error"]
    assert err["code"] == -32002 and "SEC-FLOW-01" in " ".join(err["data"]["rule_ids"]), err
    assert _sends(env) == []


def test_stateless_requests_share_the_principal_session(env: Env) -> None:
    # 2026-07-28 stateless clients: no Mcp-Session-Id, no X-Session-Id -> still one IFC session per principal
    r = env.rpc("files", "tools/call", {"name": "read_file", "arguments": {"path": "/work/r.md"}})
    assert "result" in r.json(), r.text
    err = env.rpc("mail", "tools/call", {"name": "send_email", "arguments": MAIL}).json()["error"]
    assert "SEC-FLOW-01" in " ".join(err["data"]["rule_ids"]), err


def test_shared_x_session_id_links_decide_and_mcp(env: Env) -> None:
    _decide(env, "files.read_file", {"path": "/work/x.md"}, "oc-shared-7")  # client-local tool, via /v1/decide
    sid = env.init("mail")
    env.tools("mail", sid)
    # the principal-wide default MCP session is clean: confirm tier only
    plain = env.call("mail", sid, "send_email", MAIL)["error"]
    assert "SEC-FLOW-01" not in " ".join(plain["data"]["rule_ids"])
    # the same id the OpenCode plugin sends for chat + decide: the read is seen
    err = env.call("mail", sid, "send_email", MAIL, headers={**DEV, "X-Session-Id": "oc-shared-7"})["error"]
    assert "SEC-FLOW-01" in " ".join(err["data"]["rule_ids"]), err
    assert _sends(env) == []


def test_the_default_mcp_session_is_per_principal(env: Env) -> None:
    sid = env.init("files")
    env.tools("files", sid)
    env.call("files", sid, "read_file", {"path": "/work/r.md"})
    other = {"X-ACL-Dev-User": "piotr", "X-ACL-Dev-Groups": "developers"}
    msid = env.init("mail", other)
    env.tools("mail", msid, other)
    err = env.call("mail", msid, "send_email", MAIL, headers=other)["error"]
    assert "SEC-FLOW-01" not in " ".join(err["data"]["rule_ids"])  # piotr never inherits anna's labels


# ============================================================ 7: approve once = one upstream call


def test_wait_path_consumes_the_approval(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    svc: ApprovalService = env.app.state.approvals
    real_wait = svc.wait
    approver = make_principal("anna", ["developers"], subject="dev-anna")

    async def approve_then_wait(approval_id: str, timeout_s: float) -> ApprovalStatus:
        await svc.decide(approval_id, approve=True, actor=approver)  # the user approves while the call waits
        return await real_wait(approval_id, timeout_s)

    monkeypatch.setattr(svc, "wait", approve_then_wait)
    sid = env.init("mail")
    env.tools("mail", sid)
    out = env.call("mail", sid, "send_email", MAIL, query="?wait=5")
    assert "result" in out, out
    assert len(_sends(env)) == 1
    monkeypatch.setattr(svc, "wait", real_wait)
    redeemed = [e for e in env.events("approval") if e["detail"]["state"] == "redeemed"]
    assert len(redeemed) == 1
    row = env.client.portal.call(svc.get_row, redeemed[0]["detail"]["approval_id"])  # type: ignore[union-attr]
    assert row.consumed_at is not None  # spent: `redeem` never accepts it again
    again = env.call("mail", sid, "send_email", MAIL)  # same call again (also a SEC-LOOP-01 repeat by now)
    assert "error" in again and again["error"]["code"] in (-32001, -32002), again
    assert len(_sends(env)) == 1


def test_wait_path_does_not_reuse_an_approval_already_redeemed(env: Env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Approval granted, the identical call redeemed elsewhere first, then the waiter wakes: it must not send."""
    svc: ApprovalService = env.app.state.approvals
    real_wait = svc.wait
    approver = make_principal("anna", ["developers"], subject="dev-anna")

    async def approve_spend_then_wait(approval_id: str, timeout_s: float) -> ApprovalStatus:
        await svc.decide(approval_id, approve=True, actor=approver)
        row = await svc.get_row(approval_id)
        async with svc._sessions()() as s:  # simulate a concurrent redemption of the same approval
            from sqlalchemy import update

            from acl.approvals.db_models import ApprovalRow

            await s.execute(update(ApprovalRow).where(ApprovalRow.id == row.id).values(consumed_at=datetime.now(UTC)))
            await s.commit()
        return await real_wait(approval_id, timeout_s)

    monkeypatch.setattr(svc, "wait", approve_spend_then_wait)
    sid = env.init("mail")
    env.tools("mail", sid)
    out = env.call("mail", sid, "send_email", MAIL, query="?wait=5")
    assert "error" in out and out["error"]["code"] == -32002, out
    assert _sends(env) == []


# ============================================================ 11: no self-approval of admin-scope holds


@pytest.fixture
async def approvals(tmp_path: Path) -> AsyncIterator[ApprovalService]:
    engine = make_engine(f"sqlite+aiosqlite:///{tmp_path / 'a.db'}")
    await create_all(engine)
    maker = make_sessionmaker(engine)
    yield ApprovalService(lambda: maker, lambda: RecordingSink(), salt=lambda: "test-salt")
    await engine.dispose()


async def test_privileged_requester_cannot_approve_own_admin_scope_hold(approvals: ApprovalService) -> None:
    eng = build_engine(["SEC-TOOL-01"])
    ctx = tool_ctx("mail.send", MAIL, username="adam")
    ctx = ctx.model_copy(update={"principal": make_principal("adam", ["developers"], roles=["acl-admin"])})
    decision = await eng.evaluate(ctx)
    assert decision.action == Action.require_approval
    ref = await approvals.create(ctx, decision, approver_scope="admin", preview="mail.send")
    with pytest.raises(ApprovalForbidden) as exc:
        await approvals.decide(ref.approval_id, approve=True, actor=ctx.principal)
    assert exc.value.status_code == 403 and "own" in str(exc.value)
    other = make_principal("ola", ["security-analysts"], roles=["acl-analyst"])
    ok = await approvals.decide(ref.approval_id, approve=True, actor=other)
    assert ok.status == ApprovalStatus.approved and ok.decided_by == "ola"


async def test_privileged_requester_may_deny_own_admin_scope_hold(approvals: ApprovalService) -> None:
    eng = build_engine(["SEC-TOOL-01"])
    ctx = tool_ctx("mail.send", MAIL, username="adam")
    ctx = ctx.model_copy(update={"principal": make_principal("adam", ["developers"], roles=["acl-admin"])})
    ref = await approvals.create(ctx, await eng.evaluate(ctx), approver_scope="admin", preview="mail.send")
    out = await approvals.decide(ref.approval_id, approve=False, actor=ctx.principal)
    assert out.status == ApprovalStatus.denied


# ============================================================ a: base64 blobs, canary normalisation


def _blob(text: str) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def test_pii_inside_a_text_blob_resource_is_redacted(env: Env) -> None:
    env.fakes["files"].handler = lambda n, a: {
        "content": [
            {
                "type": "resource",
                "resource": {"uri": "file:///c.txt", "mimeType": "text/plain", "blob": _blob("PESEL 44051401359")},
            }
        ]
    }
    sid = env.init("files")
    out = env.call("files", sid, "read_file", {"path": "c.txt"})
    assert "result" in out, out
    res = out["result"]["content"][0]["resource"]
    decoded = base64.b64decode(res["blob"]).decode("utf-8")
    assert "44051401359" not in decoded and "<PESEL_1>" in decoded


def test_secret_inside_a_blob_resource_read_is_withheld(env: Env) -> None:
    key = "AKIA" + "IOSFODNN7EXAMPLE"
    env.fakes["files"].extra_handlers["resources/read"] = lambda p: {
        "contents": [{"uri": p["uri"], "mimeType": "application/octet-stream", "blob": _blob(f"key = {key}")}]
    }
    sid = env.init("files")
    r = env.rpc("files", "resources/read", {"uri": "file:///cfg"}, session=sid).json()
    assert r["error"]["code"] == -32003, r
    assert key not in json.dumps(r) and _blob(f"key = {key}") not in json.dumps(r)


def test_canary_inside_a_blob_never_reaches_the_client(env: Env) -> None:
    canary = "Kanarek Zxq7f3Lm"
    env.fakes["files"].handler = lambda n, a: {
        "content": [
            {
                "type": "resource",
                "resource": {"uri": "file:///r.csv", "mimeType": "text/csv", "blob": _blob(f"id,name\n7,{canary}\n")},
            }
        ]
    }
    sid = env.init("files")
    out = env.call("files", sid, "read_file", {"path": "r.csv"})
    assert canary.lower() not in json.dumps(out).lower()
    blob = out["result"]["content"][0]["resource"]["blob"]
    assert canary not in base64.b64decode(blob).decode("utf-8")
    assert any(i["category"] == "canary_triggered" for i in env.admin("GET", "/incidents").json())


def test_undecodable_binary_blob_is_not_forwarded_unscanned(env: Env) -> None:
    raw = bytes(range(256)) * 4
    env.fakes["files"].handler = lambda n, a: {
        "content": [
            {
                "type": "resource",
                "resource": {
                    "uri": "file:///x.bin",
                    "mimeType": "application/octet-stream",
                    "blob": base64.b64encode(raw).decode(),
                },
            }
        ]
    }
    sid = env.init("files")
    out = env.call("files", sid, "read_file", {"path": "x.bin"})
    assert base64.b64encode(raw).decode() not in json.dumps(out)
    assert "omitted" in out["result"]["content"][0]["text"]


def test_canary_matching_ignores_case_and_whitespace(env: Env) -> None:
    env.fakes["files"].handler = lambda n, a: text_result("row: KANAREK   zxq7f3lm; Anna Nowak")
    sid = env.init("files")
    out = env.call("files", sid, "read_file", {"path": "x"})
    text = out["result"]["content"][0]["text"]
    assert "zxq7f3lm" not in text.lower() and "Anna Nowak" in text
    assert any(i["category"] == "canary_triggered" for i in env.admin("GET", "/incidents").json())


# ============================================================ b: annotations are pinned


def test_annotation_flip_after_pinning_is_drift(env: Env) -> None:
    fake = env.fakes["rugpull"]
    fake.tools[0]["annotations"] = {"readOnlyHint": True, "destructiveHint": False}
    sid = env.init("rugpull-demo")
    assert env.tools("rugpull-demo", sid) == ["get_weather"]
    assert "result" in env.call("rugpull-demo", sid, "get_weather", {"city": "Kraków"})
    fake.tools[0]["annotations"] = {"readOnlyHint": True, "destructiveHint": True}  # flipped after pinning
    assert env.tools("rugpull-demo", sid) == []
    (row,) = env.admin("GET", "/mcp/tools?server=rugpull-demo").json()
    assert row["status"] == "quarantined" and row["pinned_hash"] != row["current_hash"]
    n = len(fake.calls)
    err = env.call("rugpull-demo", sid, "get_weather", {"city": "Gdańsk"})["error"]
    assert "SEC-MCP-01" in err["data"]["rule_ids"] and len(fake.calls) == n


def test_annotation_title_is_not_forwarded(env: Env) -> None:
    env.fakes["rugpull"].tools[0]["annotations"] = {"title": "Totally safe", "readOnlyHint": True}
    sid = env.init("rugpull-demo")
    r = env.rpc("rugpull-demo", "tools/list", session=sid).json()
    assert r["result"]["tools"][0]["annotations"] == {"readOnlyHint": True}


def test_legacy_pins_upgrade_without_drift(env: Env) -> None:
    from sqlalchemy import update

    from acl.mcp_proxy.db_models import McpToolRow

    fake = env.fakes["rugpull"]
    fake.tools[0]["annotations"] = {"readOnlyHint": True}
    sid = env.init("rugpull-demo")
    env.tools("rugpull-demo", sid)
    t = fake.tools[0]
    legacy = tool_hash(t["name"], t["description"], t["inputSchema"])  # a pin written by the previous gateway

    async def downgrade() -> None:
        async with env.app.state.db() as s:
            await s.execute(update(McpToolRow).values(pinned_hash=legacy, current_hash=legacy))
            await s.commit()

    env.client.portal.call(downgrade)  # type: ignore[union-attr]
    assert env.tools("rugpull-demo", sid) == ["get_weather"]  # no drift on upgrade
    (row,) = env.admin("GET", "/mcp/tools?server=rugpull-demo").json()
    assert row["status"] == "pinned"
    assert row["pinned_hash"] == manifest_hash(t["name"], t["description"], t["inputSchema"], t["annotations"])
    assert not env.events("mcp_drift")
    # and from now on a flip is drift
    fake.tools[0]["annotations"] = {"readOnlyHint": False}
    assert env.tools("rugpull-demo", sid) == []


def test_manifest_hash_is_domain_separated_from_the_legacy_pin() -> None:
    schema = {"type": "object"}
    assert manifest_hash("t", "d", schema, None) != tool_hash("t", "d", schema)
    assert manifest_hash("t", "d", schema, {"readOnlyHint": True}) != manifest_hash("t", "d", schema, None)
    assert manifest_hash("t", "d", schema, {"title": "x"}) == manifest_hash("t", "d", schema, None)
