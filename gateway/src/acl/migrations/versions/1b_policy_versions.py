"""Policy version snapshots.

Revision ID: 1b_policy_versions
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "1b_policy_versions"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policy_versions",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("version", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("author", sa.String(255), nullable=True),
        sa.Column("source", sa.String(16), nullable=False),
        sa.Column("message", sa.Text(), nullable=False, server_default=""),
        sa.Column("files_changed", sa.JSON(), nullable=False),
        sa.Column("files", sa.JSON(), nullable=False),
        sa.Column("diff", sa.Text(), nullable=False, server_default=""),
    )
    op.create_index("ix_policy_versions_version", "policy_versions", ["version"])


def downgrade() -> None:
    op.drop_index("ix_policy_versions_version", table_name="policy_versions")
    op.drop_table("policy_versions")
