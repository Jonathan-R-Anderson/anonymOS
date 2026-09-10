"""Add private boards and external source imports

Revision ID: 9f4f58a31c5c
Revises: b38b893343b7
Create Date: 2026-04-16 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9f4f58a31c5c'
down_revision = 'b38b893343b7'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'board_source',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('board_id', sa.Integer(), nullable=False),
        sa.Column('source_type', sa.String(length=16), nullable=False),
        sa.Column('source_name', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['board_id'], ['board.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('board_id', 'source_type', 'source_name', name='uq_board_source')
    )

    with op.batch_alter_table('board', schema=None) as batch_op:
        batch_op.add_column(sa.Column('owner_slip_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('is_private', sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.create_foreign_key('fk_board_owner_slip_id_slip', 'slip', ['owner_slip_id'], ['id'])

    with op.batch_alter_table('thread', schema=None) as batch_op:
        batch_op.add_column(sa.Column('source_type', sa.String(length=16), nullable=False, server_default='local'))
        batch_op.add_column(sa.Column('source_name', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('source_thread_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('source_url', sa.String(), nullable=True))
        batch_op.create_unique_constraint('uq_thread_board_source_thread', ['board', 'source_type', 'source_thread_id'])

    with op.batch_alter_table('poster', schema=None) as batch_op:
        batch_op.alter_column('ip_address', existing_type=sa.String(length=15), type_=sa.String(length=255), existing_nullable=False)

    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.alter_column('poster', existing_type=sa.Integer(), nullable=True)
        batch_op.add_column(sa.Column('author_name', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('source_type', sa.String(length=16), nullable=False, server_default='local'))
        batch_op.add_column(sa.Column('source_name', sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column('source_post_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('source_parent_post_id', sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column('source_url', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('external_media_url', sa.String(), nullable=True))
        batch_op.create_unique_constraint('uq_post_thread_source_post', ['thread', 'source_type', 'source_post_id'])


def downgrade():
    with op.batch_alter_table('post', schema=None) as batch_op:
        batch_op.drop_constraint('uq_post_thread_source_post', type_='unique')
        batch_op.drop_column('external_media_url')
        batch_op.drop_column('source_url')
        batch_op.drop_column('source_parent_post_id')
        batch_op.drop_column('source_post_id')
        batch_op.drop_column('source_name')
        batch_op.drop_column('source_type')
        batch_op.drop_column('author_name')
        batch_op.alter_column('poster', existing_type=sa.Integer(), nullable=False)

    with op.batch_alter_table('poster', schema=None) as batch_op:
        batch_op.alter_column('ip_address', existing_type=sa.String(length=255), type_=sa.String(length=15), existing_nullable=False)

    with op.batch_alter_table('thread', schema=None) as batch_op:
        batch_op.drop_constraint('uq_thread_board_source_thread', type_='unique')
        batch_op.drop_column('source_url')
        batch_op.drop_column('source_thread_id')
        batch_op.drop_column('source_name')
        batch_op.drop_column('source_type')

    with op.batch_alter_table('board', schema=None) as batch_op:
        batch_op.drop_constraint('fk_board_owner_slip_id_slip', type_='foreignkey')
        batch_op.drop_column('is_private')
        batch_op.drop_column('owner_slip_id')

    op.drop_table('board_source')
