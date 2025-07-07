"""Create RawVideo table manually

Revision ID: a8edd3d92a35
Revises: 35f7d58d9974
Create Date: 2025-04-26 01:09:59.904381

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a8edd3d92a35'
down_revision = '35f7d58d9974'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'raw_video',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('subject', sa.String(length=100), nullable=False),
        sa.Column('chapter', sa.String(length=200), nullable=True),
        sa.Column('episode', sa.String(length=50), nullable=False),
        sa.Column('date', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False, server_default="Not Assigned")
    )
