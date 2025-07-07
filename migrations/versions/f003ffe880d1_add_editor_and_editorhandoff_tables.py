"""Add editor and editorhandoff tables

Revision ID: f003ffe880d1
Revises: 940e0c6a6b90
Create Date: 2025-06-01 10:00:00.000000

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = 'f003ffe880d1'
down_revision = '940e0c6a6b90'
branch_labels = None
depends_on = None

def upgrade():
    op.create_table(
        'editor_handoff',
        sa.Column('id', sa.Integer, primary_key=True, autoincrement=True),
        sa.Column('subject', sa.String(length=200), nullable=False),
        sa.Column('episode', sa.String(length=50), nullable=False),
        sa.Column('editor_id', sa.Integer, nullable=False),
        sa.Column('progress', sa.String(length=20), nullable=False),
        sa.Column('date_assigned', sa.String(length=20), nullable=False),
        sa.ForeignKeyConstraint(['editor_id'], ['editor.id'])
    )
    # If you also need to create the 'editor' table, add it here or make sure it exists.

def downgrade():
    op.drop_table('editor_handoff')
