"""Add is_admin field

Revision ID: b69d8ceab401
Revises: 
Create Date: 2025-04-18 22:45:37.125059

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b69d8ceab401'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.add_column(sa.Column('is_admin', sa.Boolean(), default=False))

def downgrade():
    with op.batch_alter_table('users') as batch_op:
        batch_op.drop_column('is_admin')


