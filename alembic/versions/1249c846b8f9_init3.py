"""init3

Revision ID: 1249c846b8f9
Revises: 62000d2afe49
Create Date: 2022-10-17 15:35:16.845737

"""
from alembic import op
import sqlalchemy as sa
import sqlmodel              ##### Required when using sqlmodel and not use sqlalchemy
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '1249c846b8f9'
down_revision = '62000d2afe49'
branch_labels = None
depends_on = None


def upgrade(engine_name):
    globals()["upgrade_alltenants"]()


def downgrade(engine_name):
    globals()["downgrade_alltenants"]()




def upgrade_alltenants():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pod', sa.Column('time_to_stop_default', sa.Integer(), nullable=True))
    op.add_column('pod', sa.Column('time_to_stop_instance', sa.Integer(), nullable=True, server_default=sa.text("-1")))
    op.add_column('pod', sa.Column('time_to_stop_ts', sa.DateTime(), nullable=True))
    op.add_column('pod', sa.Column('start_instance_ts', sa.DateTime(), nullable=True))
    op.drop_column('pod', 'persistent_volume')
    op.add_column('pod', sa.Column('persistent_volume', postgresql.JSON(astext_type=sa.Text()), nullable=True, server_default=sa.text("'{}'::json")))
    op.drop_column('pod', 'instance_port')
    # ### end Alembic commands ###


def downgrade_alltenants():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('pod', sa.Column('instance_port', sa.INTEGER(), autoincrement=False, nullable=True))
    op.drop_column('pod', 'persistent_volume')
    op.add_column('pod', sa.Column('persistent_volume', sa.BOOLEAN(), nullable=False, server_default=str(False)))
    op.drop_column('pod', 'start_instance_ts')
    op.drop_column('pod', 'time_to_stop_ts')
    op.drop_column('pod', 'time_to_stop_instance')
    op.drop_column('pod', 'time_to_stop_default')
    # ### end Alembic commands ###
