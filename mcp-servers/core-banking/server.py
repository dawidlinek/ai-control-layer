"""core-banking: read-only SQL over synthetic Polish banking data, with canary rows.

Governance ladder from the concept (§9 "Database tools"): this server is the *first* rung only (a read-only
engine: `PRAGMA query_only`, an authorizer that allows nothing but SELECT, one statement per call). Per-role
column scoping, stacked-statement rejection, result pseudonymisation and canary redaction are done by the
gateway (SEC-TOOL-01 `sql` checker, SEC-PII-01, SEC-MCP-02 canaries). `data.py` documents the tables.
"""

from __future__ import annotations

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import data
from common import run
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

MAX_ROWS = 200
_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}

DESCRIPTION = (
    "Run one read-only SQL SELECT statement against the core-banking database and return the rows as JSON. "
    "Tables: clients(id, name, pesel, city, email), accounts(id, client_id, iban, balance, currency), "
    "loans(id, client_id, principal, currency, rate, term_months, status, purpose). At most 200 rows."
)

server = MCPServer("core-banking")
_con = data.build_db()
_con.execute("PRAGMA query_only = ON")


def _authorizer(action: int, arg1: str | None, arg2: str | None, db: str | None, source: str | None) -> int:
    return sqlite3.SQLITE_OK if action in _ALLOWED else sqlite3.SQLITE_DENY


_con.set_authorizer(_authorizer)


def run_query(sql: str) -> dict[str, object]:
    try:
        cur = _con.execute(sql)  # sqlite3 refuses more than one statement per execute()
        columns = [d[0] for d in cur.description or []]
        rows = cur.fetchmany(MAX_ROWS + 1)
    except (sqlite3.Error, sqlite3.Warning) as exc:
        raise ToolError(f"SQL error: {exc}") from exc
    return {"columns": columns, "rows": [list(r) for r in rows[:MAX_ROWS]], "truncated": len(rows) > MAX_ROWS}


@server.tool(name="query", description=DESCRIPTION)
def query(sql: str) -> str:
    return json.dumps(run_query(sql), ensure_ascii=False)


if __name__ == "__main__":
    run(server)
