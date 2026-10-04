"""Policy versions: optional rollback reason.

Revision ID: 3p_policy_version_reason
Revises: 1b_policy_versions
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "3p_policy_version_reason"
down_revision = "1b_policy_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("policy_versions") as batch:
        batch.add_column(sa.Column("reason", sa.String(500), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("policy_versions") as batch:
        batch.drop_column("reason")
