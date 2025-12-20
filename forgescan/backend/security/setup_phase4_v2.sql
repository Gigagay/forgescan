-- ForgeScan 2.0: Complete Database Setup (Entry Point)
-- ============================================================================
-- Run this script to set up all Phase 4+ security features:
-- - Row-Level Security (RLS)
-- - Table Partitioning
-- - Token Bucket Rate Limiting
-- - Leakproof Functions
-- - Dynamic Data Masking
-- - Optimized Auditing
-- ============================================================================

-- ============================================================================
-- STEP 1: Install Required PostgreSQL Extensions
-- ============================================================================
CREATE EXTENSION IF NOT EXISTS "pgcrypto";      -- For UUID generation, hashing
CREATE EXTENSION IF NOT EXISTS "bloom";          -- For fast bloom filters

-- ============================================================================
-- STEP 2: Create Security Schema & Tenant Registry
-- ============================================================================
CREATE SCHEMA IF NOT EXISTS forgescan_security;

CREATE TABLE IF NOT EXISTS forgescan_security.tenant_registry (
    tenant_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_name VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255) UNIQUE,
    tier VARCHAR(32) DEFAULT 'free',  -- free, pro, enterprise
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Create role-based access levels
CREATE TABLE IF NOT EXISTS forgescan_security.user_roles (
    role_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_name VARCHAR(64) NOT NULL UNIQUE,
    clearance_level INTEGER NOT NULL DEFAULT 0,  -- 0 = viewer, 100 = admin
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert standard roles
INSERT INTO forgescan_security.user_roles (role_name, clearance_level, description)
VALUES
    ('viewer', 0, 'Read-only access'),
    ('analyst', 25, 'Can view and comment'),
    ('engineer', 50, 'Can remediate findings'),
    ('auditor', 75, 'Can access unmasked data'),
    ('compliance_officer', 90, 'Full audit access'),
    ('admin', 100, 'Full system access')
ON CONFLICT (role_name) DO NOTHING;

-- ============================================================================
-- STEP 3: Load RLS Functions (LEAKPROOF, O(1) rate limiting)
-- ============================================================================
\i rls_functions.sql

-- ============================================================================
-- STEP 4: Load Partitioned Audit Log Infrastructure
-- ============================================================================
\i partitioned_audit.sql

-- ============================================================================
-- STEP 5: Load Dynamic Data Masking Views
-- ============================================================================
\i data_masking.sql

-- ============================================================================
-- STEP 6: Initialize Rate Limiting Tables
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.rate_limits (
    tenant_id UUID PRIMARY KEY REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    bucket_size INTEGER NOT NULL DEFAULT 1000,
    tokens NUMERIC NOT NULL DEFAULT 1000,
    refill_rate NUMERIC NOT NULL DEFAULT 10,  -- tokens per second
    last_update TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for rate limiting
CREATE INDEX idx_rate_limits_tokens ON forgescan_security.rate_limits (tokens);

-- ============================================================================
-- STEP 7: Create Core Security Tables with Check Constraints
-- ============================================================================

-- Findings table with RLS
CREATE TABLE IF NOT EXISTS public.findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    scan_id UUID,
    scanner VARCHAR(32) NOT NULL,
    rule_id VARCHAR(64) NOT NULL,
    title VARCHAR(500) NOT NULL,
    description TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    confidence FLOAT DEFAULT 0.85 CHECK (confidence >= 0 AND confidence <= 1),
    fingerprint VARCHAR(64) NOT NULL,
    file VARCHAR(1000),
    line INTEGER,
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'fixed', 'false_positive', 'risk_accepted')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, fingerprint)
);

-- Enable RLS on findings
ALTER TABLE public.findings ENABLE ROW LEVEL SECURITY;

CREATE POLICY findings_rls ON public.findings
    USING (tenant_id = forgescan_security.get_context_uuid('forgescan.tenant_id'));

-- Create indexes for findings
CREATE INDEX idx_findings_tenant ON public.findings (tenant_id);
CREATE INDEX idx_findings_severity ON public.findings (severity);
CREATE INDEX idx_findings_status ON public.findings (status);
CREATE INDEX idx_findings_created ON public.findings (created_at DESC);

-- Enable audit trigger on findings
CREATE TRIGGER audit_findings
    AFTER INSERT OR UPDATE OR DELETE ON public.findings
    FOR EACH ROW EXECUTE FUNCTION forgescan_security.audit_trigger_func();

-- ============================================================================
-- STEP 8: Remediations Table (Business-Impact-Driven)
-- ============================================================================

CREATE TABLE IF NOT EXISTS public.remediations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    finding_id UUID NOT NULL REFERENCES public.findings(id) ON DELETE CASCADE,
    priority VARCHAR(3) NOT NULL CHECK (priority IN ('P0', 'P1', 'P2', 'P3', 'P4')),
    action TEXT NOT NULL,
    timeframe VARCHAR(100),
    status VARCHAR(20) DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'completed', 'deferred')),
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS on remediations
ALTER TABLE public.remediations ENABLE ROW LEVEL SECURITY;

CREATE POLICY remediations_rls ON public.remediations
    USING (tenant_id = forgescan_security.get_context_uuid('forgescan.tenant_id'));

-- Create indexes
CREATE INDEX idx_remediations_tenant ON public.remediations (tenant_id);
CREATE INDEX idx_remediations_priority ON public.remediations (priority);
CREATE INDEX idx_remediations_finding ON public.remediations (finding_id);

-- ============================================================================
-- STEP 9: Initialize Test Data
-- ============================================================================

-- Insert test tenant
INSERT INTO forgescan_security.tenant_registry (tenant_id, tenant_name, domain)
VALUES ('10000000-0000-0000-0000-000000000001'::UUID, 'Test Tenant', 'test.local')
ON CONFLICT DO NOTHING;

-- Initialize rate limit for test tenant
SELECT forgescan_security.init_rate_limit(
    '10000000-0000-0000-0000-000000000001'::UUID,
    1000,  -- bucket_size
    10     -- refill_rate (tokens per second)
);

-- ============================================================================
-- STEP 10: Set Session Context (Example for application)
-- ============================================================================
-- Applications should call this before queries:
-- SELECT set_config('forgescan.tenant_id', 'tenant-uuid', false);
-- SELECT set_config('forgescan.user_id', 'user-uuid', false);
-- SELECT set_config('forgescan.clearance', '50', false);
-- SELECT set_config('forgescan.roles', 'analyst,engineer', false);

-- ============================================================================
-- STEP 11: Grant Permissions (for multi-user databases)
-- ============================================================================
-- GRANT USAGE ON SCHEMA forgescan_security TO readonly_user;
-- GRANT SELECT ON ALL TABLES IN SCHEMA forgescan_security TO readonly_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA forgescan_security TO app_user;

-- ============================================================================
-- SETUP COMPLETE
-- ============================================================================
-- Database is now configured with:
-- ✅ Row-Level Security (tenant isolation)
-- ✅ Leakproof Functions (secure & performant)
-- ✅ Token Bucket Rate Limiting (O(1))
-- ✅ Partitioned Audit Logs (scalable)
-- ✅ Dynamic Data Masking (role-based)
-- ✅ Check Constraints (data validation)
-- ✅ Bloom Indexes (fast filtering)
-- 
-- Next steps:
-- 1. Create application user and set permissions
-- 2. Configure session context in app code
-- 3. Schedule partition creation/pruning (monthly)
-- 4. Set up background worker for audit log analysis
