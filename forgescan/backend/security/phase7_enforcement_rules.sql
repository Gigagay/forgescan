-- Phase 7: Deterministic Enforcement, CI/CD Gating & Monetization Locks
-- Created: 2025-12-21
-- Purpose: Bind detection & prioritization into non-negotiable CI/CD gates

-- 1) Enforcement levels table (for reference and audit)
CREATE TABLE IF NOT EXISTS forgescan_security.enforcement_levels (
    level_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    level_name TEXT UNIQUE NOT NULL,
    min_priority INTEGER NOT NULL,
    max_priority INTEGER,
    behavior TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert enforcement bands (hard-coded reference)
INSERT INTO forgescan_security.enforcement_levels (level_name, min_priority, max_priority, behavior, description)
VALUES
    ('HARD_FAIL', 100, 999, 'BLOCK', 'Block CI/CD, block deployment'),
    ('SOFT_FAIL', 80, 99, 'ALLOW_WITH_ACK', 'Allow deploy, require acknowledgement'),
    ('WARN', 60, 79, 'WARN', 'Logged, visible in dashboard'),
    ('INFO', 0, 59, 'INFO', 'No enforcement')
ON CONFLICT (level_name) DO NOTHING;

-- 2) Enforcement audit trail (immutable log of all gate decisions)
CREATE TABLE IF NOT EXISTS forgescan_security.enforcement_decisions (
    decision_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    pipeline_id TEXT,
    max_priority INTEGER,
    enforcement_level TEXT,
    decision TEXT NOT NULL CHECK (decision IN ('BLOCK', 'ALLOW_WITH_ACK', 'ALLOW', 'INFO')),
    reason TEXT,
    asset_at_risk TEXT,
    financial_risk_usd DECIMAL(15, 2),
    required_action TEXT,
    decided_at TIMESTAMPTZ DEFAULT NOW(),
    acked_by UUID,
    acked_at TIMESTAMPTZ,
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES forgescan_security.tenant_registry(tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_enforcement_decisions_tenant ON forgescan_security.enforcement_decisions(tenant_id);
CREATE INDEX IF NOT EXISTS idx_enforcement_decisions_decided_at ON forgescan_security.enforcement_decisions(decided_at DESC);

-- 3) Enforcement quota tracking (per-tenant, per-month)
CREATE TABLE IF NOT EXISTS forgescan_security.enforcement_quota (
    quota_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL UNIQUE,
    quota_year_month TEXT NOT NULL,  -- YYYY-MM
    hard_fails_limit INTEGER,         -- NULL = unlimited
    hard_fails_used INTEGER DEFAULT 0,
    soft_fails_allowed BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES forgescan_security.tenant_registry(tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_enforcement_quota_tenant_month ON forgescan_security.enforcement_quota(tenant_id, quota_year_month);

-- 4) Core enforcement gate function (database-level truth)
CREATE OR REPLACE FUNCTION forgescan_security.enforce_release_gate(
    p_tenant_id UUID,
    p_pipeline_id TEXT DEFAULT NULL
)
RETURNS TABLE (
    decision TEXT,
    max_priority INTEGER,
    enforcement_level TEXT,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
DECLARE
    v_max_priority INTEGER;
    v_enforcement_level TEXT;
    v_tier TEXT;
    v_reason TEXT;
BEGIN
    -- Get max priority from remediation plan
    SELECT COALESCE(MAX(priority_rank), 0) INTO v_max_priority
    FROM forgescan_security.generate_remediation_plan(p_tenant_id);

    -- Determine enforcement level
    IF v_max_priority >= 100 THEN
        v_enforcement_level := 'HARD_FAIL';
    ELSIF v_max_priority >= 80 THEN
        v_enforcement_level := 'SOFT_FAIL';
    ELSIF v_max_priority >= 60 THEN
        v_enforcement_level := 'WARN';
    ELSE
        v_enforcement_level := 'INFO';
    END IF;

    -- Get tenant tier for context
    SELECT operational_tier INTO v_tier
    FROM forgescan_security.tenant_registry
    WHERE tenant_id = p_tenant_id;

    IF v_tier IS NULL THEN
        v_tier := 'STARTUP';
    END IF;

    -- Apply tier-based enforcement modulation (documented in Phase 6.1)
    -- SOLO: only block >= 120, STARTUP: >= 100, GROWTH: >= 90, ENTERPRISE: >= 80
    CASE v_tier
        WHEN 'SOLO' THEN
            IF v_max_priority < 120 THEN
                v_enforcement_level := 'INFO';
            END IF;
        WHEN 'STARTUP' THEN
            IF v_max_priority < 100 THEN
                v_enforcement_level := 'INFO';
            END IF;
        WHEN 'GROWTH' THEN
            IF v_max_priority < 90 THEN
                v_enforcement_level := 'INFO';
            END IF;
        -- ENTERPRISE: no modulation (use raw thresholds)
    END CASE;

    -- Map enforcement level to decision
    v_reason := CASE v_enforcement_level
        WHEN 'HARD_FAIL' THEN 'Critical business risk detected (revenue/compliance impact)'
        WHEN 'SOFT_FAIL' THEN 'High-risk findings require acknowledgement'
        WHEN 'WARN' THEN 'Medium-risk findings detected; recommend remediation'
        ELSE 'No blocking risks detected'
    END;

    RETURN QUERY SELECT
        CASE v_enforcement_level
            WHEN 'HARD_FAIL' THEN 'BLOCK'::TEXT
            WHEN 'SOFT_FAIL' THEN 'ALLOW_WITH_ACK'::TEXT
            WHEN 'WARN' THEN 'WARN'::TEXT
            ELSE 'ALLOW'::TEXT
        END,
        v_max_priority,
        v_enforcement_level,
        v_reason;
END;
$$;

-- 5) Helper: Log enforcement decision to audit trail
CREATE OR REPLACE FUNCTION forgescan_security.log_enforcement_decision(
    p_tenant_id UUID,
    p_pipeline_id TEXT,
    p_decision TEXT,
    p_max_priority INTEGER,
    p_enforcement_level TEXT,
    p_reason TEXT,
    p_asset_at_risk TEXT DEFAULT NULL,
    p_financial_risk_usd DECIMAL DEFAULT NULL,
    p_required_action TEXT DEFAULT NULL
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_decision_id UUID;
BEGIN
    INSERT INTO forgescan_security.enforcement_decisions(
        tenant_id, pipeline_id, max_priority, enforcement_level, decision, reason,
        asset_at_risk, financial_risk_usd, required_action
    ) VALUES (
        p_tenant_id, p_pipeline_id, p_max_priority, p_enforcement_level, p_decision, p_reason,
        p_asset_at_risk, p_financial_risk_usd, p_required_action
    ) RETURNING decision_id INTO v_decision_id;

    RETURN v_decision_id;
END;
$$;

-- 6) Helper: Check quota for tier (e.g., free tier limited to 1 HARD_FAIL/month)
CREATE OR REPLACE FUNCTION forgescan_security.check_enforcement_quota(
    p_tenant_id UUID
)
RETURNS TABLE (
    allowed BOOLEAN,
    reason TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_tier TEXT;
    v_quota forgescan_security.enforcement_quota%ROWTYPE;
    v_year_month TEXT;
BEGIN
    SELECT operational_tier INTO v_tier
    FROM forgescan_security.tenant_registry
    WHERE tenant_id = p_tenant_id;

    IF v_tier IS NULL THEN
        v_tier := 'STARTUP';
    END IF;

    -- Current year-month
    v_year_month := TO_CHAR(NOW(), 'YYYY-MM');

    -- Fetch or create quota
    SELECT * INTO v_quota
    FROM forgescan_security.enforcement_quota
    WHERE tenant_id = p_tenant_id AND quota_year_month = v_year_month;

    IF v_quota IS NULL THEN
        -- Create quota for this month based on tier
        INSERT INTO forgescan_security.enforcement_quota(
            tenant_id, quota_year_month, hard_fails_limit, soft_fails_allowed
        ) VALUES (
            p_tenant_id, v_year_month,
            CASE v_tier
                WHEN 'SOLO' THEN 1
                WHEN 'STARTUP' THEN NULL  -- Unlimited
                WHEN 'GROWTH' THEN NULL
                ELSE NULL
            END,
            TRUE  -- All tiers allow soft fails (just for visibility)
        ) RETURNING * INTO v_quota;
    END IF;

    -- Check quota
    IF v_quota.hard_fails_limit IS NOT NULL AND v_quota.hard_fails_used >= v_quota.hard_fails_limit THEN
        RETURN QUERY SELECT FALSE, 'Hard fail quota exhausted for this month. Upgrade to remove limits.';
        RETURN;
    END IF;

    RETURN QUERY SELECT TRUE, 'Quota check passed.';
END;
$$;

-- 7) Grant minimal execute rights for CI role
-- GRANT EXECUTE ON FUNCTION forgescan_security.enforce_release_gate(UUID, TEXT) TO forgescan_ci;
-- GRANT EXECUTE ON FUNCTION forgescan_security.log_enforcement_decision(UUID, TEXT, TEXT, INTEGER, TEXT, TEXT, TEXT, DECIMAL, TEXT) TO forgescan_ci;

-- End of Phase 7 SQL
