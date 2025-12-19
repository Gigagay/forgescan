# backend/alembic/versions/002_add_peach_payments.py
"""Add Peach Payments fields

Revision ID: 002
Revises: 001
Create Date: 2026-01-02 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '002'
down_revision = '001'


def upgrade() -> None:
    # Remove Stripe fields
    op.drop_column('tenants', 'stripe_customer_id')
    op.drop_column('tenants', 'stripe_subscription_id')
    
    # Add Peach Payments fields
    op.add_column('tenants', sa.Column('peach_registration_id', sa.String(255), unique=True))
    op.add_column('tenants', sa.Column('peach_transaction_id', sa.String(255)))


def downgrade() -> None:
    op.drop_column('tenants', 'peach_registration_id')
    op.drop_column('tenants', 'peach_transaction_id')
    
    op.add_column('tenants', sa.Column('stripe_customer_id', sa.String(255)))
    op.add_column('tenants', sa.Column('stripe_subscription_id', sa.String(255)))
