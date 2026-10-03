"""Alembic environment (async). Run via `python -m acl.migrate` (uses ACL_DATABASE_URL)."""

from __future__ import annotations

import asyncio

from alembic import context
from sqlalchemy.engine import Connection

from acl.db import Base, import_all_models, make_engine

import_all_models()
target_metadata = Base.metadata
config = context.config


def _run(connection: Connection) -> None:
    context.configure(connection=connection, target_metadata=target_metadata, render_as_batch=True)
    with context.begin_transaction():
        context.run_migrations()


async def _online() -> None:
    engine = make_engine(config.get_main_option("sqlalchemy.url"))
    async with engine.connect() as conn:
        await conn.run_sync(_run)
    await engine.dispose()


if context.is_offline_mode():
    context.configure(url=config.get_main_option("sqlalchemy.url"), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()
else:
    asyncio.run(_online())
