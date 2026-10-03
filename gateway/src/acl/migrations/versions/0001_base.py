"""Base revision (empty). Package migrations use down_revision = "0001_base".

Revision ID: 0001_base
"""

from __future__ import annotations

revision = "0001_base"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
