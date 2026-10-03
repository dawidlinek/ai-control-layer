"""Database seam (orchestrator-owned). SQLAlchemy 2 async; Postgres in compose, SQLite in tests.

Each package declares its tables in `acl/<pkg>/db_models.py` using `Base` from here, and ships an
Alembic migration in `acl/migrations/versions/` whose `down_revision` is `"0001_base"` (the
orchestrator merges heads when integrating). Tests call `create_all()` on SQLite instead.
"""

from __future__ import annotations

import importlib
import pkgutil

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

NAMING = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    metadata = MetaData(naming_convention=NAMING)


def import_all_models() -> list[str]:
    """Import every `acl.<pkg>.db_models` module so its tables register on Base.metadata."""
    import acl

    loaded = []
    for mod in pkgutil.iter_modules(acl.__path__):
        if not mod.ispkg:
            continue
        name = f"acl.{mod.name}.db_models"
        try:
            importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name != name:
                raise
            continue
        loaded.append(name)
    return loaded


def make_engine(url: str) -> AsyncEngine:
    return create_async_engine(url, pool_pre_ping=True)


def make_sessionmaker(engine: AsyncEngine) -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(engine, expire_on_commit=False)


async def create_all(engine: AsyncEngine) -> None:
    import_all_models()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
