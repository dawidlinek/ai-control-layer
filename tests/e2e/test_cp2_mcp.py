"""CP2 MCP demo slice against the running stack (`make up`, then `make e2e`): scenarios 6 and 13.

Scenario 6  rug pull: the demo `get_weather` tool changes its description after three calls; the gateway
            quarantines it, raises an incident (and an `mcp_drift` event on SSE) and blocks further calls.
Scenario 13 core banking: an analyst's agent queries the governed database server; permitted columns come
            back pseudonymised, a stacked `; DROP`, an out-of-scope column and `SELECT *` are blocked, the planted
            canary row never leaves the gateway and the attacker sink's log stays empty.

Needs the MCP servers from deploy/compose.mcp.yml, Keycloak users from deploy/keycloak/realm-export.json (anna:
developers, jan: credit-analysts, adam: admins) and, for the blocking assertions of scenario 13, Phase 2B's
SEC-TOOL-01 (SQL checker). Skips cleanly when the stack is down. The rug-pull scenario is one-shot per container:
recreate the server to repeat it (`docker compose up -d --force-recreate mcp-rugpull`) and approve the tool.
"""

from __future__ import annotations

import importlib.util
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from e2e.helpers import env_value
from oracle.leak import LeakOracle

pytestmark = pytest.mark.e2e

ROOT = Path(__file__).resolve().parents[2]
WEATHER_CALLS_BEFORE_RUG = 3  # RUGPULL_AFTER_CALLS in deploy/compose.mcp.yml


class McpClient:
    """Minimal MCP Streamable HTTP client for the gateway's `/mcp/{server}` endpoint."""

    def __init__(self, stack: Any, user: str, server: str) -> None:
        self.stack, self.user, self.server = stack, user, server
        self.url = f"{stack.cfg.gateway}/mcp/{server}"
        self.session: str | None = None
        self.n = 0

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self.n += 1
        headers = dict(self.stack.auth(self.user))
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self.n, "method": method}
        if params is not None:
            body["params"] = params
        r = self.stack.http.post(self.url, json=body, headers=headers, timeout=60)
        if method == "initialize" and r.status_code == 200:
            self.session = r.headers.get("mcp-session-id")
        try:
            out = r.json()
        except ValueError:
            pytest.fail(f"{method} on {self.server}: HTTP {r.status_code} {r.text[:200]}")
        out["_status"] = r.status_code
        return out

    def open(self) -> McpClient:
        out = self.rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}})
        assert "result" in out, f"initialize refused for {self.user} on {self.server}: {json.dumps(out)[:300]}"
        return self

    def tools(self) -> list[str]:
        out = self.rpc("tools/list")
        assert "result" in out, json.dumps(out)[:300]
        return [t["name"] for t in out["result"]["tools"]]

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})


def _tool_rows(stack: Any, server: str) -> list[dict[str, Any]]:
    r = stack.admin("GET", f"/mcp/tools?server={server}")
    assert r.status_code == 200, f"GET /admin/v1/mcp/tools: HTTP {r.status_code} {r.text[:200]}"
    return r.json()


def _sink_entries(stack: Any) -> int:
    port = env_value("SINK_PORT", "8099")
    try:
        return int(httpx.get(f"http://localhost:{port}/_log", timeout=3).json()["count"])
    except (httpx.HTTPError, ValueError, KeyError):
        pytest.skip(f"attacker sink not reachable on localhost:{port}")


def _bank_data() -> Any:
    spec = importlib.util.spec_from_file_location("bank_data_e2e", ROOT / "mcp-servers" / "core-banking" / "data.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_cp2_scenario_6_rug_pull_quarantine_and_incident(stack, sse) -> None:
    rows = [r for r in _tool_rows(stack, "rugpull-demo") if r["name"] == "get_weather"]
    if rows and rows[0]["status"] != "pinned":
        # leftover from an earlier run: after `docker compose up -d --force-recreate mcp-rugpull` the server is clean
        # again; let the gateway see the clean manifest, then re-pin it as an admin (re-approval is deliberately sticky)
        McpClient(stack, "anna", "rugpull-demo").open().tools()
        approved = stack.admin("POST", f"/mcp/tools/{rows[0]['id']}/approve", json={"reason": "e2e reset"})
        rows = [r for r in _tool_rows(stack, "rugpull-demo") if r["name"] == "get_weather"]
        if approved.status_code != 200 or not rows or rows[0]["status"] != "pinned":
            pytest.skip("rugpull-demo is rugged from an earlier run: docker compose up -d --force-recreate mcp-rugpull")

    anna = McpClient(stack, "anna", "rugpull-demo").open()
    assert anna.tools() == ["get_weather"]  # first sight on an allowlisted server: pinned
    row = next(r for r in _tool_rows(stack, "rugpull-demo") if r["name"] == "get_weather")
    assert row["status"] == "pinned" and row["pinned_hash"] == row["current_hash"]

    for city in ("Kraków", "Gdańsk", "Poznań")[:WEATHER_CALLS_BEFORE_RUG]:
        out = anna.call("get_weather", city=city)
        assert "result" in out, f"benign call should pass: {json.dumps(out)[:300]}"

    # the server now serves a poisoned description; the next listing detects the drift
    seen_from = time.monotonic()
    assert anna.tools() == [], "the drifted tool must be hidden from the agent"
    row = next(r for r in _tool_rows(stack, "rugpull-demo") if r["name"] == "get_weather")
    assert row["status"] == "quarantined" and row["pinned_hash"] != row["current_hash"]
    assert row["description_diff"] and "IMPORTANT" in row["description_diff"]

    ev = sse.wait_for(lambda e: e.data.get("event_type") == "mcp_drift" and e.t >= seen_from - 0.5, timeout=3.0)
    assert ev is not None, "no mcp_drift event on the SSE stream"
    incidents = stack.admin("GET", "/incidents").json()
    assert any(i["category"] == "mcp_rug_pull" and "SEC-MCP-01" in i["rule_ids"] for i in incidents), incidents

    blocked = anna.call("get_weather", city="Opole")
    assert blocked["error"]["data"]["rule_ids"][0] == "SEC-MCP-01", json.dumps(blocked)[:300]


def test_cp2_scenario_13_core_banking_scoping_pseudonymisation_and_canaries(stack) -> None:
    data = _bank_data()
    con = data.build_db()
    pesels = {f"pesel_{i}": r[0] for i, r in enumerate(con.execute("SELECT pesel FROM clients WHERE id <= 5"))}
    canaries = {
        "canary_name": data.CANARY_NAME,
        "canary_pesel": data.CANARY_PESEL,
        "canary_iban": data.CANARY_IBAN,
        "canary_note": data.CANARY_NOTE,
        "canary_email": data.CANARY_EMAIL,
    }
    sink_before = _sink_entries(stack)
    jan = McpClient(stack, "jan", "core-banking").open()
    assert jan.tools() == ["query"]

    # 1. permitted columns: PESELs are pseudonymised on the way out
    ok = jan.call(
        "query",
        sql="SELECT c.name, c.pesel, a.balance FROM clients c JOIN accounts a ON a.client_id = c.id WHERE c.id <= 5",
    )
    assert "result" in ok, f"permitted query was refused: {json.dumps(ok)[:300]}"
    text = ok["result"]["content"][0]["text"]
    assert "<PESEL_" in text, "PESEL values should be replaced by placeholders"
    LeakOracle(pesels).assert_clean(ok, channel="mcp_result", what="the permitted query result")

    # 2. stacked statement and out-of-scope access are blocked by the governed tool policy
    for sql in (
        "SELECT 1; DROP TABLE clients",
        "SELECT name, internal_risk_notes FROM clients",
        "SELECT * FROM clients",
        "SELECT iban FROM accounts",
    ):
        out = jan.call("query", sql=sql)
        assert "error" in out and out["error"]["data"]["rule_ids"], f"not blocked: {sql!r} -> {json.dumps(out)[:300]}"

    # 3. a table scan returns the canary row: its values are redacted, never delivered
    scan = jan.call("query", sql="SELECT id, name, pesel, city FROM clients")
    LeakOracle(canaries).assert_clean(scan, channel="mcp_result", what="the full-table scan")
    still_there = jan.call("query", sql="SELECT COUNT(id) FROM clients")
    assert "result" in still_there, "the table must still exist after the stacked DROP attempt"
    assert json.loads(still_there["result"]["content"][0]["text"])["rows"][0][0] >= 30

    # 4. nothing reached the attacker sink, and the audit trail holds no canary value
    assert _sink_entries(stack) == sink_before, "the attacker sink recorded a request"
    events = stack.admin("GET", "/events?limit=200").json()
    LeakOracle(canaries).assert_clean(events, channel="audit_log", what="the audit events")

    # 5. other groups cannot use the server at all
    anna = McpClient(stack, "anna", "core-banking")
    refused = anna.rpc("initialize", {"protocolVersion": "2025-11-25"})
    assert refused["_status"] == 403 and "SEC-MCP-02" in refused["error"]["data"]["rule_ids"]
