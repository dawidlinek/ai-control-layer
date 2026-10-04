"""Automation Insights: clusters, published skills, settings, personal opt-ins (Phase 4B).

Revision ID: 4b_insights
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "4b_insights"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "insight_clusters",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("group_name", sa.String(128), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("owner", sa.String(256), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("distinct_users", sa.Integer(), nullable=False),
        sa.Column("members", sa.JSON(), nullable=True),
        sa.Column("data", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_insight_clusters"),
    )
    op.create_index("ix_insight_clusters_group_name", "insight_clusters", ["group_name"])
    op.create_index("ix_insight_clusters_owner", "insight_clusters", ["owner"])
    op.create_table(
        "insight_skills",
        sa.Column("skill_id", sa.String(80), nullable=False),
        sa.Column("cluster_id", sa.String(40), nullable=True),
        sa.Column("groups", sa.JSON(), nullable=True),
        sa.Column("before_usd_per_run", sa.Float(), nullable=True),
        sa.Column("before_gpu_seconds_per_run", sa.Float(), nullable=True),
        sa.Column("projected_usd_per_run", sa.Float(), nullable=True),
        sa.Column("projected_gpu_seconds_per_run", sa.Float(), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("published_by", sa.String(256), nullable=True),
        sa.Column("policy_version", sa.String(64), nullable=True),
        sa.Column("version_id", sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint("skill_id", name="pk_insight_skills"),
    )
    op.create_table(
        "insight_settings",
        sa.Column("key", sa.String(160), nullable=False),
        sa.Column("value", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_by", sa.String(256), nullable=True),
        sa.PrimaryKeyConstraint("key", name="pk_insight_settings"),
    )
    op.create_table(
        "insight_opt_ins",
        sa.Column("subject", sa.String(256), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("subject", name="pk_insight_opt_ins"),
    )


def downgrade() -> None:
    op.drop_table("insight_opt_ins")
    op.drop_table("insight_settings")
    op.drop_table("insight_skills")
    op.drop_index("ix_insight_clusters_owner", table_name="insight_clusters")
    op.drop_index("ix_insight_clusters_group_name", table_name="insight_clusters")
    op.drop_table("insight_clusters")
