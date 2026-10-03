"""Apply database migrations: `python -m acl.migrate` (reads ACL_DATABASE_URL)."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from acl.settings import get_settings


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade_head(url: str | None = None) -> None:
    command.upgrade(alembic_config(url or get_settings().database_url), "heads")


if __name__ == "__main__":
    upgrade_head()
