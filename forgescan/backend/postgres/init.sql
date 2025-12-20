-- ForgeScan Multi-Tenant PostgreSQL Initialization Script
-- ============================================================================
-- This script:
-- 1. Creates schemas for multi-tenancy
-- 2. Creates database users with proper permissions
-- 3. Defines core tables with strict typing
-- 4. Enables Row-Level Security (RLS) policies
-- 5. Sets up audit trails and constraints
-- ============================================================================

-- ============================================================================
-- 1. CREATE SCHEMAS FOR MULTI-TENANCY
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS public;
CREATE SCHEMA IF NOT EXISTS audit;
CREATE SCHEMA IF NOT EXISTS rls;

-- ============================================================================
-- 2. CREATE CORE TABLES (public schema - tenant-agnostic)
-- ============================================================================

-- Tenants table
CREATE TABLE IF NOT EXISTS public.tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT true,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Users table
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tenant_id, email)
);

-- Scans table
CREATE TABLE IF NOT EXISTS public.scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    target VARCHAR(500) NOT NULL,
    scan_type VARCHAR(32) NOT NULL CHECK (scan_type IN ('web', 'sast', 'sca', 'dast')),
    status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    started_at TIMESTAMP WITH TIME ZONE,
    completed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Findings table (core security data)
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    scan_id UUID NOT NULL REFERENCES public.scans(id) ON DELETE CASCADE,
    scanner VARCHAR(32) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence FLOAT DEFAULT 0.85 CHECK (confidence >= 0 AND confidence <= 1),
    fingerprint VARCHAR(64) NOT NULL,  -- SHA256 for deduplication
    file VARCHAR(1000),
    line INTEGER,
    url VARCHAR(1000),
    method VARCHAR(10),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'false_positive', 'risk_accepted')),
    impact_score INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Remediations table (business-impact-driven)
CREATE TABLE IF NOT EXISTS public.remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
    priority VARCHAR(3) NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
    action TEXT NOT NULL,
    timeframe VARCHAR(100) NOT NULL,
    business_risk TEXT,
    technical_risk TEXT,
    justification TEXT,
    confidence VARCHAR(20),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'deferred')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Audit log table
CREATE TABLE IF NOT EXISTS audit.logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID NOT NULL REFERENCES public.tenants(id) ON DELETE CASCADE,
    user_id UUID,
    action VARCHAR(50) NOT NULL,
    table_name VARCHAR(100),
    record_id UUID,
    old_values JSONB,
    new_values JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 3. CREATE INDEXES FOR PERFORMANCE
-- ============================================================================

-- Tenant isolation
CREATE INDEX idx_users_tenant_id ON public.users(tenant_id);
CREATE INDEX idx_scans_tenant_id ON public.scans(tenant_id);
CREATE INDEX idx_findings_tenant_id ON public.findings(tenant_id);
CREATE INDEX idx_findings_scan_id ON public.findings(scan_id);
CREATE INDEX idx_remediations_tenant_id ON public.remediations(tenant_id);
CREATE INDEX idx_remediations_finding_id ON public.remediations(finding_id);
CREATE INDEX idx_audit_logs_tenant_id ON audit.logs(tenant_id);

-- Deduplication
CREATE UNIQUE INDEX idx_findings_fingerprint ON public.findings(tenant_id, fingerprint);

-- Status/filtering
CREATE INDEX idx_findings_severity ON public.findings(severity);
CREATE INDEX idx_findings_status ON public.findings(status);
CREATE INDEX idx_remediations_priority ON public.remediations(priority);
CREATE INDEX idx_scans_status ON public.scans(status);

-- Time-range queries
CREATE INDEX idx_findings_created_at ON public.findings(created_at DESC);
CREATE INDEX idx_scans_created_at ON public.scans(created_at DESC);

-- ============================================================================
-- 4. ENABLE ROW-LEVEL SECURITY (RLS)
-- ============================================================================

ALTER TABLE public.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit.logs ENABLE ROW LEVEL SECURITY;

-- ============================================================================
-- 5. CREATE RLS POLICIES (Tenant Isolation)
-- ============================================================================

-- Tenants: users can only see their own tenant
CREATE POLICY tenants_isolation ON public.tenants
    USING (id = current_setting('app.tenant_id')::uuid);

-- Users: users can only see users in their tenant
CREATE POLICY users_isolation ON public.users
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Scans: users can only see scans in their tenant
CREATE POLICY scans_isolation ON public.scans
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Findings: users can only see findings in their tenant
CREATE POLICY findings_isolation ON public.findings
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Remediations: users can only see remediations in their tenant
CREATE POLICY remediations_isolation ON public.remediations
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Audit logs: users can only see logs for their tenant
CREATE POLICY audit_logs_isolation ON audit.logs
    USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- ============================================================================
-- 6. INITIALIZE TEST DATA (for development)
-- ============================================================================

-- Insert test tenant
INSERT INTO public.tenants (id, name, domain) 
VALUES 
    ('10000000-0000-0000-0000-000000000001'::uuid, 'Test Tenant 1', 'test1.local'),
    ('20000000-0000-0000-0000-000000000002'::uuid, 'Test Tenant 2', 'test2.local')
ON CONFLICT DO NOTHING;

-- Insert test users
INSERT INTO public.users (tenant_id, email, hashed_password)
VALUES
    ('10000000-0000-0000-0000-000000000001'::uuid, 'admin@test1.local', 'hashed_password_1'),
    ('20000000-0000-0000-0000-000000000002'::uuid, 'admin@test2.local', 'hashed_password_2')
ON CONFLICT DO NOTHING;

-- ============================================================================
-- 7. GRANT PERMISSIONS (if using separate db users per tenant)
-- ============================================================================

-- Create test tenant users (optional)
-- CREATE USER tenant1_user WITH PASSWORD 'change_me_in_env';
-- CREATE USER tenant2_user WITH PASSWORD 'change_me_in_env';

-- Grant read/write on their respective schemas
-- GRANT USAGE ON SCHEMA public TO tenant1_user;
-- GRANT SELECT, INSERT, UPDATE, DELETE ON public.findings TO tenant1_user;

-- ============================================================================
-- NOTE: Before production use:
-- 1. Replace test data with real tenant setup
-- 2. Use proper password management (secrets manager)
-- 3. Review and adjust RLS policies based on actual user roles
-- 4. Consider adding role-based access control (RBAC) on top of RLS
-- ============================================================================
