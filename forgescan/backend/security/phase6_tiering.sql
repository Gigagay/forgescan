-- Phase 6.1: Inclusive Tiering Without Dilution
-- Created: 2025-12-21
-- Purpose: Add operational_tier to assets and provide tier-aware enforcement gate

-- 1) Add operational_tier column to business_assets (non-destructive ALTER)
ALTER TABLE IF EXISTS forgescan_security.business_assets
ADD COLUMN IF NOT EXISTS operational_tier TEXT
    CHECK (operational_tier IN ('SOLO', 'STARTUP', 'GROWTH', 'ENTERPRISE'))
    DEFAULT 'STARTUP';

-- 2) Tier-aware enforcement function
CREATE OR REPLACE FUNCTION forgescan_security.enforce_by_tier(
    p_tenant_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tier TEXT;
    v_threshold INTEGER;
    v_violations INTEGER;
BEGIN
    SELECT operational_tier INTO v_tier
    FROM forgescan_security.tenant_registry
    WHERE tenant_id = p_tenant_id;

    -- Default to STARTUP if not set
    IF v_tier IS NULL THEN
        v_tier := 'STARTUP';
    END IF;

    v_threshold :=
        CASE v_tier
            WHEN 'SOLO' THEN 120
            WHEN 'STARTUP' THEN 100
            WHEN 'GROWTH' THEN 90
            ELSE 80
        END;

    SELECT COUNT(*) INTO v_violations
    FROM forgescan_security.generate_remediation_plan(p_tenant_id)
    WHERE priority_rank >= v_threshold;

    IF v_violations > 0 THEN
        RAISE EXCEPTION
        'ForgeScan Block [%]: % critical risks exceed threshold %',
        v_tier, v_violations, v_threshold;
    END IF;
END;
$$;

-- 3) Usage notes (commented):
-- CI/CD integration (example):
-- SELECT forgescan_security.enforce_by_tier('uuid-tenant-1');
-- For CI roles, grant execute to the CI role (example):
-- GRANT EXECUTE ON FUNCTION forgescan_security.enforce_by_tier(UUID) TO forgescan_ci;

-- 4) Optional: Backfill existing tenants with default 'STARTUP' (uncomment to run in controlled migration)
-- UPDATE forgescan_security.tenant_registry SET operational_tier = 'STARTUP' WHERE operational_tier IS NULL;

-- End of Phase 6.1 SQL
