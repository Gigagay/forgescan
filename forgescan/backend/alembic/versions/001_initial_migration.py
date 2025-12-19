# backend/alembic/versions/001_initial_migration.py
"""Initial migration

Revision ID: 001
Revises: 
Create Date: 2026-01-01 00:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Create tenants table
    op.create_table(
        'tenants',
        sa.Column('id', sa.String(100), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('plan', sa.String(50), server_default=sa.text("'free'"), nullable=False),
        sa.Column('max_scans', sa.Integer(), server_default=sa.text("5")),
        sa.Column('max_users', sa.Integer(), server_default=sa.text("1")),
        sa.Column('settings', postgresql.JSON, server_default=sa.text("'{}'::json")),
        sa.Column('stripe_customer_id', sa.String(255), unique=True),
        sa.Column('stripe_subscription_id', sa.String(255), unique=True),
        sa.Column('subscription_status', sa.String(50)),
        sa.Column('trial_ends_at', sa.DateTime),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Create users table
    op.create_table(
        'users',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('email', sa.String(255), unique=True, nullable=False, index=True),
        sa.Column('hashed_password', sa.String(255)),
        sa.Column('full_name', sa.String(255)),
        sa.Column('avatar_url', sa.String(500)),
        sa.Column('tenant_id', sa.String(100), sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('role', sa.String(50), default='viewer', nullable=False),
        sa.Column('oauth_provider', sa.String(50)),
        sa.Column('oauth_id', sa.String(255)),
        sa.Column('mfa_enabled', sa.Boolean, default=False),
        sa.Column('mfa_secret', sa.String(255)),
        sa.Column('api_key_hash', sa.String(255)),
        sa.Column('is_active', sa.Boolean, default=True, nullable=False),
        sa.Column('is_verified', sa.Boolean, default=False, nullable=False),
        sa.Column('last_login', sa.DateTime),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Create scans table
    op.create_table(
        'scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.String(100), sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), nullable=False, index=True),
        sa.Column('scanner_type', sa.String(50), nullable=False, index=True),
        sa.Column('target', sa.String(500), nullable=False),
        sa.Column('options', postgresql.JSON, default={}),
        sa.Column('status', sa.String(20), default='pending', nullable=False, index=True),
        sa.Column('progress', sa.Integer, default=0),
        sa.Column('findings_summary', postgresql.JSON, server_default=sa.text("'{}'::json")),
        sa.Column('risk_score', sa.Numeric(5, 2)),
        sa.Column('started_at', sa.DateTime),
        sa.Column('completed_at', sa.DateTime),
        sa.Column('duration_seconds', sa.Integer),
        sa.Column('error_message', sa.String(1000)),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Create findings table
    op.create_table(
        'findings',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('scans.id', ondelete='CASCADE'), nullable=False, index=True),
        sa.Column('tenant_id', sa.String(100), sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('title', sa.String(500), nullable=False),
        sa.Column('description', sa.Text, nullable=False),
        sa.Column('severity', sa.String(20), nullable=False, index=True),
        sa.Column('url', sa.String(1000)),
        sa.Column('method', sa.String(10)),
        sa.Column('parameter', sa.String(255)),
        sa.Column('cwe_id', sa.String(50)),
        sa.Column('owasp_category', sa.String(100), index=True),
        sa.Column('evidence', sa.Text),
        sa.Column('request', sa.Text),
        sa.Column('response', sa.Text),
        sa.Column('remediation', sa.Text),
        sa.Column('references', postgresql.JSON, default=[]),
        sa.Column('risk_score', sa.Integer),
        sa.Column('exploitability', sa.String(20)),
        sa.Column('status', sa.String(20), default='open', nullable=False, index=True),
        sa.Column('false_positive', sa.Boolean, default=False),
        sa.Column('metadata', postgresql.JSON, default={}),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Create audit_logs table
    op.create_table(
        'audit_logs',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.String(100), sa.ForeignKey('tenants.id'), index=True),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('users.id'), index=True),
        sa.Column('action', sa.String(100), nullable=False, index=True),
        sa.Column('resource_type', sa.String(50)),
        sa.Column('resource_id', sa.String(100)),
        sa.Column('ip_address', postgresql.INET),
        sa.Column('user_agent', sa.Text),
        sa.Column('details', postgresql.JSON, server_default=sa.text("'{}'::json")),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Create usage_records table
    op.create_table(
        'usage_records',
        sa.Column('id', postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column('tenant_id', sa.String(100), sa.ForeignKey('tenants.id'), nullable=False, index=True),
        sa.Column('date', sa.Date, nullable=False, index=True),
        sa.Column('scans_count', sa.Integer, default=0),
        sa.Column('api_requests_count', sa.Integer, default=0),
        sa.Column('usage_by_scanner', postgresql.JSON, default={}),
        sa.Column('usage_by_user', postgresql.JSON, default={}),
        sa.Column('created_at', sa.DateTime, nullable=False),
        sa.Column('updated_at', sa.DateTime, nullable=False),
    )

    # Enable Row Level Security (RLS) - PostgreSQL specific
    # Note: This should be run manually after migration or in a separate script
    # op.execute("ALTER TABLE users ENABLE ROW LEVEL SECURITY;")
    # op.execute("ALTER TABLE scans ENABLE ROW LEVEL SECURITY;")
    # op.execute("ALTER TABLE findings ENABLE ROW LEVEL SECURITY;")


def downgrade() -> None:
    op.drop_table('usage_records')
    op.drop_table('audit_logs')
    op.drop_table('findings')
    op.drop_table('scans')
    op.drop_table('users')
    op.drop_table('tenants')

