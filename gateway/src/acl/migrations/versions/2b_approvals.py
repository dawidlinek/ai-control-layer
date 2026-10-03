"""Approvals: the human-in-the-loop queue and time-boxed elevations (Phase 2B).

Revision ID: 2b_approvals
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "2b_approvals"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "approvals",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("status", sa.String(12), nullable=False),
        sa.Column("approver_scope", sa.String(8), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("requester_subject", sa.String(255), nullable=False),
        sa.Column("requested_by", sa.String(255), nullable=False),
        sa.Column("session_id", sa.String(255), nullable=False),
        sa.Column("trace_id", sa.String(64), nullable=False),
        sa.Column("decision_id", sa.String(64), nullable=True),
        sa.Column("tool", sa.String(255), nullable=True),
        sa.Column("server", sa.String(100), nullable=True),
        sa.Column("arguments_preview", sa.Text(), nullable=False),
        sa.Column("args_hash", sa.String(64), nullable=True),
        sa.Column("egress", sa.Boolean(), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("rule_ids", sa.JSON(), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("decided_by", sa.String(255), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("elevation_scope", sa.String(255), nullable=True),
        sa.Column("elevation_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("detail", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_approvals"),
    )
    op.create_index("ix_approvals_requester_subject", "approvals", ["requester_subject"])
    op.create_index("ix_approvals_status_expires", "approvals", ["status", "expires_at"])
    op.create_index("ix_approvals_session_tool", "approvals", ["session_id", "tool"])


def downgrade() -> None:
    op.drop_table("approvals")
