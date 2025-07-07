"""merge heads

Revision ID: d7299f8dca82
Revises: a8edd3d92a35, add_role_to_users
Create Date: 2025-06-21 01:09:55.692031

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd7299f8dca82'
down_revision = ('a8edd3d92a35', 'add_role_to_users')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
