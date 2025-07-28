"""Add roles field to User model for RBAC authorization

Revision ID: add_roles_field_rbac
Revises: 41eb10f48a60
Create Date: 2025-07-28

"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = "add_roles_field_rbac"
down_revision = "41eb10f48a60"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add roles field to users table for RBAC authorization."""
    # Add roles column with JSON type and default value
    op.add_column(
        "users",
        sa.Column(
            "roles",
            postgresql.JSON(astext_type=sa.Text()),
            nullable=False,
            server_default='["viewer"]',
            comment="User roles for RBAC authorization (viewer, tester, admin)",
        ),
    )

    # Update existing users to have default viewer role
    op.execute("UPDATE users SET roles = '[\"viewer\"]' WHERE roles IS NULL")


def downgrade() -> None:
    """Remove roles field from users table."""
    op.drop_column("users", "roles")
