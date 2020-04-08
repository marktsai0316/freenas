"""empty message

Revision ID: a06b1946f6a3
Revises: 32f55c715352
Create Date: 2020-03-12 21:32:11.938578+00:00

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a06b1946f6a3'
down_revision = '32f55c715352'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_email', schema=None) as batch_op:
        batch_op.add_column(sa.Column('em_oauth', sa.TEXT(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('system_email', schema=None) as batch_op:
        batch_op.drop_column('em_oauth')

    # ### end Alembic commands ###