"""Track IP and UA Strings

Revision ID: 5491fc6b3d51
Revises: dddf9a5cdd08
Create Date: 2018-03-15 21:53:30.916384

"""

# revision identifiers, used by Alembic.
revision = '5491fc6b3d51'
down_revision = 'dddf9a5cdd08'

from alembic import op
import sqlalchemy as sa


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('user_agents',
    sa.Column('user_agent_id', sa.Integer(), nullable=False),
    sa.Column('user_agent', sa.String(length=1024), nullable=False),
    sa.PrimaryKeyConstraint('user_agent_id'),
    sa.UniqueConstraint('user_agent')
    )
    op.add_column(u'login', sa.Column('ip_address_at_signup', sa.String(length=39), nullable=True))
    op.add_column(u'logincreate', sa.Column('ip_address_signup_request', sa.String(length=39), nullable=True))
    op.add_column(u'sessions', sa.Column('ip_address', sa.String(length=39), nullable=True))
    op.add_column(u'sessions', sa.Column('user_agent_id', sa.Integer(), nullable=True))
    op.create_foreign_key('sessions_user_agent_id_fkey', 'sessions', 'user_agents', ['user_agent_id'], ['user_agent_id'], onupdate='CASCADE', ondelete='CASCADE')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('sessions_user_agent_id_fkey', 'sessions', type_='foreignkey')
    op.drop_column(u'sessions', 'user_agent_id')
    op.drop_column(u'sessions', 'ip_address')
    op.drop_column(u'logincreate', 'ip_address_signup_request')
    op.drop_column(u'login', 'ip_address_at_signup')
    op.drop_table('user_agents')
    # ### end Alembic commands ###
