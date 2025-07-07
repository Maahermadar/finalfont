"""Add role column to users table

Revision ID: add_role_to_users
Revises: 35f7d58d9974
Create Date: 2024-06-08 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'add_role_to_users'
down_revision = '35f7d58d9974'
branch_labels = None
depends_on = None

def upgrade():
    op.add_column('users', sa.Column('role', sa.String(length=50), nullable=False, server_default='editor'))

def downgrade():
    op.drop_column('users', 'role') 