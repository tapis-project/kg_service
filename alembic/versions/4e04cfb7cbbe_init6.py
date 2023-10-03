"""init6

Revision ID: 4e04cfb7cbbe
Revises: 7955e1af30d0
Create Date: 2023-09-27 15:32:02.050941

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel              ##### Required when using sqlmodel and not use sqlalchemy
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '4e04cfb7cbbe'
down_revision = '7955e1af30d0'
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()["upgrade_alltenants"]()


def downgrade(engine_name):
    globals()["downgrade_alltenants"]()




def upgrade_alltenants():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pod', sa.Column('action_logs', postgresql.ARRAY(sa.String(), dimensions=1), server_default=sa.text("'{}'")))
    # ### end Alembic commands ###


def downgrade_alltenants():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('pod', 'action_logs')
    # ### end Alembic commands ###
