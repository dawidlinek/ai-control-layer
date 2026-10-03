"""The 2A Alembic migration must create exactly the tables/columns declared in `acl.mcp_proxy.db_models`."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from alembic import command
from alembic.script import ScriptDirectory

from acl.db import Base, import_all_models
from acl.migrate import alembic_config, upgrade_head

TABLES = ("mcp_servers", "mcp_tools")


def _columns(con: sqlite3.Connection, table: str) -> dict[str, bool]:
    return {r[1]: bool(r[3]) for r in con.execute(f"PRAGMA table_info({table})")}  # name -> NOT NULL


def test_migration_matches_models_and_downgrades(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'm.db'}"
    upgrade_head(url)
    import_all_models()
    con = sqlite3.connect(tmp_path / "m.db")
    try:
        for name in TABLES:
            table = Base.metadata.tables[name]
            assert _columns(con, name) == {c.name: not c.nullable for c in table.columns}, name
        pk = [r[1] for r in con.execute("PRAGMA table_info(mcp_tools)") if r[5]]
        assert sorted(pk) == ["name", "server_id"]
        unique = {r[1] for r in con.execute("PRAGMA index_list(mcp_tools)") if r[2]}
        assert "ix_mcp_tools_tool_id" in unique
    finally:
        con.close()

    command.downgrade(alembic_config(url), "0001_base")
    con = sqlite3.connect(tmp_path / "m.db")
    try:
        left = {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert not left.intersection(TABLES)
    finally:
        con.close()


def test_revision_chain() -> None:
    script = ScriptDirectory.from_config(alembic_config("sqlite+aiosqlite:///:memory:"))
    rev = script.get_revision("2a_mcp")
    assert rev is not None and rev.down_revision == "0001_base"
