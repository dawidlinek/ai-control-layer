"""Audit index (`audit_events`) and incidents.

Revision ID: 1a_audit
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "1a_audit"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_events",
        sa.Column("event_id", sa.String(64), nullable=False),
        sa.Column("seq", sa.Integer(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("event_type", sa.String(40), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("trace_id", sa.String(64)),
        sa.Column("session_id", sa.String(128)),
        sa.Column("subject", sa.String(256)),
        sa.Column("username", sa.String(256)),
        sa.Column("groups_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("agent_id", sa.String(128)),
        sa.Column("point", sa.String(32)),
        sa.Column("model", sa.String(128)),
        sa.Column("connector", sa.String(64)),
        sa.Column("tier", sa.String(16)),
        sa.Column("degraded", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("tool", sa.String(256)),
        sa.Column("action", sa.String(24)),
        sa.Column("would_action", sa.String(24)),
        sa.Column("rules_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("controls_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("tags_text", sa.Text(), nullable=False, server_default=""),
        sa.Column("risk_score", sa.Float()),
        sa.Column("latency_ms", sa.Float()),
        sa.Column("input_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("output_tokens", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("usd", sa.Float(), nullable=False, server_default="0"),
        sa.Column("gpu_seconds", sa.Float(), nullable=False, server_default="0"),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("event_id", name="pk_audit_events"),
        sa.UniqueConstraint("seq", name="uq_audit_events_seq"),
    )
    for col in ("timestamp", "event_type", "trace_id", "session_id", "subject", "action"):
        op.create_index(f"ix_audit_events_{col}", "audit_events", [col])
    op.create_index("ix_audit_events_connector_timestamp", "audit_events", ["connector", "timestamp"])

    op.create_table(
        "incidents",
        sa.Column("id", sa.String(64), nullable=False),
        sa.Column("title", sa.String(300), nullable=False),
        sa.Column("category", sa.String(64), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("assignee", sa.String(256)),
        sa.Column("subject", sa.String(256)),
        sa.Column("event_ids", sa.JSON()),
        sa.Column("rule_ids", sa.JSON()),
        sa.Column("notes", sa.JSON()),
        sa.Column("detail", sa.JSON()),
        sa.PrimaryKeyConstraint("id", name="pk_incidents"),
    )
    for col in ("category", "status", "updated_at", "subject"):
        op.create_index(f"ix_incidents_{col}", "incidents", [col])


def downgrade() -> None:
    op.drop_table("incidents")
    op.drop_table("audit_events")
