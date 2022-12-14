"""empty message

Revision ID: 6386be665b9c
Revises: f8d9af20d7dc
Create Date: 2022-08-08 16:07:26.417908

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6386be665b9c'
down_revision = 'f8d9af20d7dc'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user_flask', 'password')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('user_flask', sa.Column('password', sa.VARCHAR(length=20), autoincrement=False, nullable=False))
    # ### end Alembic commands ###
