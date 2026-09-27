"""Add site settings and bans

Revision ID: c4a9dd8d6b11
Revises: 9f4f58a31c5c
Create Date: 2026-04-16 00:30:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c4a9dd8d6b11'
down_revision = '9f4f58a31c5c'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'site_setting',
        sa.Column('key', sa.String(length=64), nullable=False),
        sa.Column('value', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('key'),
    )

    op.create_table(
        'ban',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('ip_address', sa.String(length=255), nullable=False),
        sa.Column('reason', sa.String(length=255), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('created_by_slip_id', sa.Integer(), nullable=True),
        sa.ForeignKeyConstraint(['created_by_slip_id'], ['slip.id']),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('ip_address'),
    )


def downgrade():
    op.drop_table('ban')
    op.drop_table('site_setting')
