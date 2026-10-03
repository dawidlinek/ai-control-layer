"""Phase 2A: stdio upstreams, plus the end-to-end assertions that need Phase 2B's SEC-TOOL-01.

The SEC-TOOL-01 tests skip until the `tool_policy` control exists in the registry; the proxy side of that
contract (the pinned `tool_input_schema` handed to the engine) is asserted without it in test_2a_proxy.py.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).parent))
from mcp_helpers import ANALYST, DEV, make_env, policy_variant, weather_server

from acl.controls.base import load_builtin_controls
from acl.mcp_proxy.testing import FakeMcpServer, text_result, tool

STDIO_SERVER = r"""
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if "id" not in msg:
        continue
    method = msg["method"]
    if method == "initialize":
        res = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
               "serverInfo": {"name": "stdio-demo", "version": "1"}}
    elif method == "tools/list":
        res = {"tools": [{"name": "echo", "description": "Echo text back.",
                          "inputSchema": {"type": "object", "properties": {"text": {"type": "string"}},
                                          "required": ["text"]}}]}
    elif method == "tools/call":
        res = {"content": [{"type": "text", "text": "echo:" + msg["params"]["arguments"]["text"]}], "isError": False}
    else:
        res = {}
    print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": res}), flush=True)
"""


def test_stdio_server_is_spawned_and_governed(tmp_path: Path) -> None:
    script = tmp_path / "stdio_server.py"
    script.write_text(STDIO_SERVER, encoding="utf-8")
    command = json.dumps([sys.executable, str(script)])
    policy = policy_variant(
        tmp_path,
        {
            "tools.yaml": [
                ("mcp_servers:\n", f"mcp_servers:\n  stdio-demo:\n    transport: stdio\n    command: {command}\n"),
                (
                    "\ntools:\n",
                    "\ntools:\n  stdio.echo:\n    server: stdio-demo\n    name: echo\n    default_tier: allow\n",
                ),
            ],
            "groups.yaml": [
                ("mcp_servers: [governed-tools, files,", "mcp_servers: [stdio-demo, governed-tools, files,")
            ],
        },
    )
    for e in make_env(tmp_path / "run", {}, policy_dir=policy):
        sid = e.init("stdio-demo")
        assert e.tools("stdio-demo", sid) == ["echo"]
        out = e.call("stdio-demo", sid, "echo", {"text": "hej"})
        assert out["result"]["content"][0]["text"] == "echo:hej"
        r = e.client.request("DELETE", "/mcp/stdio-demo", headers={**DEV, "Mcp-Session-Id": sid})
        assert r.status_code == 204


def test_stdio_server_that_cannot_start_is_reported_unreachable(tmp_path: Path) -> None:
    policy = policy_variant(
        tmp_path,
        {
            "tools.yaml": [
                (
                    "mcp_servers:\n",
                    'mcp_servers:\n  stdio-demo:\n    transport: stdio\n    command: ["/nonexistent/acl-binary"]\n',
                ),
            ],
            "groups.yaml": [
                ("mcp_servers: [governed-tools, files,", "mcp_servers: [stdio-demo, governed-tools, files,")
            ],
        },
    )
    for e in make_env(tmp_path / "run", {}, policy_dir=policy):
        r = e.rpc("stdio-demo", "initialize", {"protocolVersion": "2025-11-25"})
        assert r.status_code == 502


# ============================================================ gated on 2B's SEC-TOOL-01

needs_tool_policy = pytest.mark.skipif(
    "tool_policy" not in load_builtin_controls(), reason="SEC-TOOL-01 (tool_policy, Phase 2B) not merged yet"
)


def tool_policy_dir(tmp_path: Path) -> Path:
    """The seed policy with SEC-TOOL-01 switched on (it ships disabled until 2B enables it)."""
    target = policy_variant(tmp_path, {})
    path = target / "controls.yaml"
    text = re.sub(
        r"(- id: SEC-TOOL-01\n    type: tool_policy\n    enabled: )false", r"\1true", path.read_text(encoding="utf-8")
    )
    path.write_text(text, encoding="utf-8", newline="\n")
    return target


@needs_tool_policy
def test_parasitic_argument_is_rejected_by_the_pinned_schema(tmp_path: Path) -> None:
    for e in make_env(tmp_path / "run", {"rugpull": weather_server()}, policy_dir=tool_policy_dir(tmp_path)):
        sid = e.init("rugpull-demo")
        e.tools("rugpull-demo", sid)
        assert "result" in e.call("rugpull-demo", sid, "get_weather", {"city": "Kraków"})
        bad = e.call("rugpull-demo", sid, "get_weather", {"city": "Kraków", "task_history": "everything the user said"})
        assert "SEC-TOOL-01" in bad["error"]["data"]["rule_ids"]
        assert len(e.fakes["rugpull"].calls) == 1


@needs_tool_policy
def test_core_banking_sql_scoping_and_stacked_statements(tmp_path: Path) -> None:
    bank = FakeMcpServer(
        [tool("query", "Run one read-only SQL SELECT statement.", {"sql": {"type": "string"}})],
        lambda n, a: text_result('{"columns": ["name"], "rows": [["Anna Nowak"]]}'),
    )
    for e in make_env(tmp_path / "run", {"core-banking": bank}, policy_dir=tool_policy_dir(tmp_path)):
        sid = e.init("core-banking", ANALYST)
        e.tools("core-banking", sid, ANALYST)

        def run(sql: str) -> dict[str, Any]:
            return e.call("core-banking", sid, "query", {"sql": sql}, headers=ANALYST)

        assert "result" in run("SELECT name, pesel FROM clients WHERE id = 1")
        assert "result" in run("SELECT c.name, a.balance FROM clients c JOIN accounts a ON a.client_id = c.id")
        for bad in (
            "SELECT 1; DROP TABLE clients",
            "SELECT name, internal_risk_notes FROM clients",
            "SELECT * FROM clients",
            "SELECT iban FROM accounts",
            "DELETE FROM loans",
        ):
            out = run(bad)
            assert "SEC-TOOL-01" in out["error"]["data"]["rule_ids"], bad
        assert len(bank.calls) == 2
