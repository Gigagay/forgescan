-- Phase 6: Enforcement, Ingestion & CI/CD Gatekeeping
-- Created: 2025-12-21
-- Purpose: Bind scanner output -> canonical vulnerabilities -> DPL engine -> enforcement points

-- 9.1 Canonical vulnerabilities table (example tenant schema shown; in production create per-tenant schemas or a shared table with tenant_id)
CREATE SCHEMA IF NOT EXISTS forgescan_tenant;

CREATE TABLE IF NOT EXISTS forgescan_tenant.canonical_vulnerabilities (
    vuln_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,

    scanner_source TEXT NOT NULL,      -- web | api | sca | db
    vuln_type TEXT NOT NULL,           -- MUST map to remediation_rules.vuln_type

    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,

    detected_at TIMESTAMPTZ DEFAULT now(),
    fingerprint TEXT NOT NULL,         -- deterministic deduplication

    severity TEXT CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),

    metadata JSONB DEFAULT '{}'::JSONB,

    CONSTRAINT unique_finding UNIQUE (tenant_id, fingerprint)
);

-- Indexes for common queries
CREATE INDEX IF NOT EXISTS idx_canonical_vuln_tenant ON forgescan_tenant.canonical_vulnerabilities(tenant_id);
CREATE INDEX IF NOT EXISTS idx_canonical_vuln_type ON forgescan_tenant.canonical_vulnerabilities(vuln_type);
CREATE INDEX IF NOT EXISTS idx_canonical_vuln_detected_at ON forgescan_tenant.canonical_vulnerabilities(detected_at DESC);

-- 11.1 CI/CD Gate Function
CREATE OR REPLACE FUNCTION forgescan_security.block_if_critical_risk(
    p_tenant_id UUID,
    p_threshold INTEGER DEFAULT 90
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO v_count
    FROM forgescan_security.generate_remediation_plan(p_tenant_id)
    WHERE priority_rank >= p_threshold;

    IF v_count > 0 THEN
        RAISE EXCEPTION
            'ForgeScan Block: % critical business risks detected (priority >= %)',
            v_count, p_threshold;
    END IF;
END;
$$;

-- 11.2 Example usage (commented):
-- SELECT forgescan_security.block_if_critical_risk('uuid-tenant-1', 90);

-- 12 Runtime enforcement view (uses current_setting for tenant context if set)
CREATE OR REPLACE VIEW forgescan_security.runtime_blocklist AS
SELECT 
    asset_name,
    vulnerability,
    priority_rank
FROM forgescan_security.generate_remediation_plan(current_setting('forgescan.tenant')::UUID)
WHERE priority_rank >= 120;

-- 13 Ops & Audit: Example helper function to insert canonical findings atomically and deduplicated by fingerprint
CREATE OR REPLACE FUNCTION forgescan_tenant.ingest_canonical_vulnerability(
    p_tenant_id UUID,
    p_scanner_source TEXT,
    p_vuln_type TEXT,
    p_schema_name TEXT,
    p_table_name TEXT,
    p_column_name TEXT,
    p_fingerprint TEXT,
    p_severity TEXT,
    p_metadata JSONB DEFAULT '{}'::JSONB
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_vuln_id UUID;
BEGIN
    -- Try to insert; on conflict return existing
    INSERT INTO forgescan_tenant.canonical_vulnerabilities(
        tenant_id, scanner_source, vuln_type, schema_name, table_name, column_name, fingerprint, severity, metadata
    ) VALUES (
        p_tenant_id, p_scanner_source, p_vuln_type, p_schema_name, p_table_name, p_column_name, p_fingerprint, p_severity, p_metadata
    ) ON CONFLICT (tenant_id, fingerprint) DO UPDATE SET
        metadata = forgescan_tenant.canonical_vulnerabilities.metadata || EXCLUDED.metadata,
        detected_at = GREATEST(forgescan_tenant.canonical_vulnerabilities.detected_at, EXCLUDED.detected_at)
    RETURNING vuln_id INTO v_vuln_id;

    RETURN v_vuln_id;
END;
$$;

-- 12.1 Grant minimal rights for CI role to execute the block function (example role name: forgescan_ci)
-- GRANT EXECUTE ON FUNCTION forgescan_security.block_if_critical_risk(UUID, INTEGER) TO forgescan_ci;

-- 13.2 Notes: This file intentionally does NOT include priority or business logic inside the canonical table.
-- The canonical table is pure fact: detections only. Business scoring is done by the Phase 5 DPL engine.

-- End of Phase 6 enforcement SQL
