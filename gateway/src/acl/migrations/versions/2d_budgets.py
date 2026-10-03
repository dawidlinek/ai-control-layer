"""Budget ledger: nodes, counters, circuit breakers.

Revision ID: 2d_budgets
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "2d_budgets"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "budget_nodes",
        sa.Column("node_id", sa.String(255), primary_key=True),
        sa.Column("level", sa.String(16), nullable=False),
        sa.Column("parent", sa.String(255), nullable=True),
        sa.Column("first_seen", sa.Float(), nullable=False, server_default="0"),
        sa.Column("last_seen", sa.Float(), nullable=False, server_default="0"),
    )
    op.create_index("ix_budget_nodes_level", "budget_nodes", ["level"])
    op.create_table(
        "budget_counters",
        sa.Column("node_id", sa.String(255), primary_key=True),
        sa.Column("meter", sa.String(48), primary_key=True),
        sa.Column("window", sa.String(16), nullable=False),
        sa.Column("value", sa.Float(), nullable=False, server_default="0"),
        sa.Column("soft_notified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("hard_notified", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("updated_at", sa.Float(), nullable=False, server_default="0"),
    )
    op.create_table(
        "budget_breakers",
        sa.Column("node_id", sa.String(255), primary_key=True),
        sa.Column("state", sa.String(12), nullable=False),
        sa.Column("opened_at", sa.Float(), nullable=True),
        sa.Column("cooldown_until", sa.Float(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("probes_used", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_probe_at", sa.Float(), nullable=True),
        sa.Column("cooldown_s", sa.Integer(), nullable=False, server_default="300"),
        sa.Column("half_open_probes", sa.Integer(), nullable=False, server_default="1"),
    )


def downgrade() -> None:
    op.drop_table("budget_breakers")
    op.drop_table("budget_counters")
    op.drop_index("ix_budget_nodes_level", table_name="budget_nodes")
    op.drop_table("budget_nodes")
