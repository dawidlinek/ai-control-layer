"""MCP proxy: bound servers (`mcp_servers`) and pinned tool manifests (`mcp_tools`).

Revision ID: 2a_mcp
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "2a_mcp"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "mcp_servers",
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("transport", sa.String(24), nullable=False),
        sa.Column("bound_url", sa.String(1024), nullable=True),
        sa.Column("bound_origin", sa.String(512), nullable=True),
        sa.Column("protocol_version", sa.String(24), nullable=True),
        sa.Column("capabilities", sa.JSON(), nullable=False),
        sa.Column("server_info", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_error", sa.String(300), nullable=True),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("server_id", name="pk_mcp_servers"),
    )
    op.create_table(
        "mcp_tools",
        sa.Column("server_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("tool_id", sa.String(300), nullable=False),
        sa.Column("policy_tool_id", sa.String(300), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("pinned_hash", sa.String(64), nullable=True),
        sa.Column("current_hash", sa.String(64), nullable=False),
        sa.Column("pinned_description", sa.Text(), nullable=True),
        sa.Column("current_description", sa.Text(), nullable=True),
        sa.Column("pinned_schema", sa.JSON(), nullable=True),
        sa.Column("current_schema", sa.JSON(), nullable=True),
        sa.Column("description_diff", sa.Text(), nullable=True),
        sa.Column("reasons", sa.JSON(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("drift_detected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("approved_by", sa.String(255), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_note", sa.String(500), nullable=True),
        sa.PrimaryKeyConstraint("server_id", "name", name="pk_mcp_tools"),
    )
    op.create_index("ix_mcp_tools_tool_id", "mcp_tools", ["tool_id"], unique=True)
    op.create_index("ix_mcp_tools_status", "mcp_tools", ["status"])


def downgrade() -> None:
    op.drop_index("ix_mcp_tools_status", table_name="mcp_tools")
    op.drop_index("ix_mcp_tools_tool_id", table_name="mcp_tools")
    op.drop_table("mcp_tools")
    op.drop_table("mcp_servers")
