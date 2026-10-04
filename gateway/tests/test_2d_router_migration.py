"""2D: the router's budget-exhausted route, and the Alembic migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest
from alembic import command
from alembic.script import ScriptDirectory

from acl.contracts.common import ConnectorTier, DataClass
from acl.db import Base, import_all_models
from acl.migrate import alembic_config, upgrade_head
from acl.policy.loader import load_policy_dir
from acl.routing.dev_access import PermissiveAccess
from acl.routing.registry import ConnectorRegistry
from acl.routing.router import Router, RouteRequest

POLICY_DIR = Path(__file__).resolve().parents[2] / "policy"


@pytest.fixture
def setup():  # type: ignore[no-untyped-def]
    loaded = load_policy_dir(POLICY_DIR)
    table = ConnectorRegistry(deterministic=True).table_for(loaded.policy, loaded.version)
    access = PermissiveAccess(lambda: loaded.policy)

    async def route(requested: str, **kw):  # type: ignore[no-untyped-def]
        usable = await access.usable_models(None)  # type: ignore[arg-type]
        return Router(loaded.policy, table).route(
            RouteRequest(requested=requested, data_class=DataClass.public, usable=usable, **kw)
        )

    return route


async def test_budget_exhausted_serves_a_local_model_and_marks_it_degraded(setup) -> None:  # type: ignore[no-untyped-def]
    r = await setup("smart", budget_exhausted="tokens_day 510/500 on user:jan")
    assert r.info.model == "local/qwen3.8-27b" and r.info.tier == ConnectorTier.local
    assert r.info.degraded is True
    assert "budget exhausted" in r.info.reason and "tokens_day" in r.info.reason
    assert r.info.factors["budget_exhausted"].startswith("tokens_day")


async def test_budget_exhausted_leaves_local_requests_alone(setup) -> None:  # type: ignore[no-untyped-def]
    r = await setup("local", budget_exhausted="usd_day")
    assert r.info.model == "local/qwen3.8-27b" and not r.info.degraded
    plain = await setup("smart")
    assert plain.info.model == "gemini/flash" and not plain.info.degraded


async def test_budget_exhausted_composes_with_the_route_local_obligation(setup) -> None:  # type: ignore[no-untyped-def]
    r = await setup("smart", budget_exhausted="usd_day", force_local=True, force_reason="route_local")
    assert r.info.model == "local/qwen3.8-27b" and r.info.degraded


TABLES = ("budget_nodes", "budget_counters", "budget_breakers")


def _columns(con: sqlite3.Connection, table: str) -> dict[str, bool]:
    return {r[1]: bool(r[3]) for r in con.execute(f"PRAGMA table_info({table})")}


def test_migration_matches_models_and_downgrades(tmp_path: Path) -> None:
    url = f"sqlite+aiosqlite:///{tmp_path / 'm.db'}"
    upgrade_head(url)
    import_all_models()
    con = sqlite3.connect(tmp_path / "m.db")
    try:
        for name in TABLES:
            table = Base.metadata.tables[name]
            assert _columns(con, name) == {c.name: not c.nullable for c in table.columns}, name
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
    rev = script.get_revision("2d_budgets")
    assert rev is not None and rev.down_revision == "0001_base"
