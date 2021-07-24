"""Add comments to site updates

Revision ID: 9270baf773a5
Revises: 7f0e262d6370
Create Date: 2019-01-21 16:41:17.360120

"""

# revision identifiers, used by Alembic.
revision = '9270baf773a5'
down_revision = '7f0e262d6370'

from alembic import op   # lgtm[py/unused-import]
import sqlalchemy as sa  # lgtm[py/unused-import]
from sqlalchemy.dialects import postgresql

def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('siteupdatecomment',
    sa.Column('commentid', sa.Integer(), nullable=False),
    sa.Column('userid', sa.Integer(), nullable=False),
    sa.Column('targetid', sa.Integer(), nullable=False),
    sa.Column('parentid', sa.Integer(), nullable=True),
    sa.Column('content', sa.String(length=10000), nullable=False),
    sa.Column('created_at', postgresql.TIMESTAMP(timezone=True), server_default=sa.text(u'now()'), nullable=False),
    sa.Column('hidden_at', postgresql.TIMESTAMP(timezone=True), nullable=True),
    sa.Column('hidden_by', sa.Integer(), nullable=True),
    sa.CheckConstraint(u'hidden_by IS NULL OR hidden_at IS NOT NULL', name='siteupdatecomment_hidden_check'),
    sa.ForeignKeyConstraint(['hidden_by'], ['login.userid'], name='siteupdatecomment_hidden_by_fkey', ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['targetid', 'parentid'], ['siteupdatecomment.targetid', 'siteupdatecomment.commentid'], name='siteupdatecomment_parentid_fkey'),
    sa.ForeignKeyConstraint(['targetid'], ['siteupdate.updateid'], name='siteupdatecomment_targetid_fkey'),
    sa.ForeignKeyConstraint(['userid'], ['login.userid'], name='siteupdatecomment_userid_fkey'),
    sa.PrimaryKeyConstraint('commentid'),
    sa.UniqueConstraint('targetid', 'commentid')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('siteupdatecomment')
    # ### end Alembic commands ###
