"""Model-artifact scan results (Phase 4A).

Revision ID: 4a_artifacts
Revises: 0001_base
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "4a_artifacts"
down_revision = "0001_base"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifact_scans",
        sa.Column("id", sa.String(40), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("size", sa.BigInteger(), nullable=False),
        sa.Column("format", sa.String(32), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("source", sa.Text(), nullable=True),
        sa.Column("exception", sa.Text(), nullable=True),
        sa.Column("decision_id", sa.String(64), nullable=True),
        sa.Column("scanned_by", sa.String(255), nullable=True),
        sa.Column("scanned_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id", name="pk_artifact_scans"),
    )
    op.create_index("ix_artifact_scans_sha256", "artifact_scans", ["sha256"])
    op.create_index("ix_artifact_scans_scanned_at", "artifact_scans", ["scanned_at"])


def downgrade() -> None:
    op.drop_table("artifact_scans")
