-- ForgeScan 2.0: Business Logic Layer with Deterministic Prioritization
-- ============================================================================
-- This layer maps technical vulnerabilities to business impact using:
-- - Asset financial value (downtime cost)
-- - Compliance obligations (GDPR, PCI-DSS, HIPAA, SOC2)
-- - Data sensitivity (PII, PCI, PHI, etc.)
--
-- Result: Deterministic, audit-proof remediation priorities.
-- No AI guessing. Pure math: Priority = f(vulnerability, asset, compliance)
-- ============================================================================

-- ============================================================================
-- SECTION 1: Business Asset Registry
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.business_assets (
    asset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    
    -- Business Classification
    asset_type TEXT NOT NULL CHECK (asset_type IN ('REVENUE', 'COMPLIANCE', 'OPERATIONAL', 'ANALYTICS', 'ARCHIVE')),
    data_sensitivity TEXT NOT NULL CHECK (data_sensitivity IN ('PUBLIC', 'INTERNAL', 'PII', 'PCI', 'PHI')),
    
    -- Quantified Business Impact
    downtime_cost_per_hour INTEGER DEFAULT 0,  -- USD/hour loss if table is breached/unavailable
    max_exposure_records INTEGER DEFAULT 0,    -- Number of records affected if leaked
    criticality_score INTEGER DEFAULT 50,      -- 1-100: importance to operations
    
    -- Compliance Context
    compliance_frameworks TEXT[] DEFAULT '{}', -- e.g., ARRAY['GDPR', 'PCI-DSS', 'HIPAA', 'SOC2']
    
    -- Metadata
    data_owner TEXT,                           -- Team responsible
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT unique_asset UNIQUE (tenant_id, schema_name, table_name),
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES forgescan_security.tenant_registry(tenant_id)
);

-- Indexes for fast lookups
CREATE INDEX idx_business_assets_tenant ON forgescan_security.business_assets(tenant_id);
CREATE INDEX idx_business_assets_type ON forgescan_security.business_assets(asset_type);
CREATE INDEX idx_business_assets_sensitivity ON forgescan_security.business_assets(data_sensitivity);
CREATE INDEX idx_business_assets_frameworks ON forgescan_security.business_assets USING gin(compliance_frameworks);

-- ============================================================================
-- SECTION 2: Compliance Framework Reference
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.compliance_frameworks (
    framework_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_name TEXT NOT NULL UNIQUE,
    regulatory_body TEXT,
    max_fine_percent_revenue NUMERIC,  -- GDPR: 4%, CCPA: 2.5%
    fine_per_record_usd NUMERIC,       -- GDPR: up to €20
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert standard frameworks
INSERT INTO forgescan_security.compliance_frameworks 
    (framework_name, regulatory_body, max_fine_percent_revenue, fine_per_record_usd, description)
VALUES
    ('GDPR', 'EU', 4.0, 20, 'General Data Protection Regulation - Europe'),
    ('CCPA', 'California', 2.5, 2.50, 'California Consumer Privacy Act'),
    ('HIPAA', 'US HHS', 1.5, 100, 'Health Insurance Portability and Accountability Act'),
    ('PCI-DSS', 'PCI Council', NULL, NULL, 'Payment Card Industry Data Security Standard'),
    ('SOC2', 'AICPA', NULL, NULL, 'System and Organization Controls'),
    ('NIST', 'NIST', NULL, NULL, 'National Institute of Standards & Technology'),
    ('ISO27001', 'ISO', NULL, NULL, 'Information Security Management Systems')
ON CONFLICT (framework_name) DO NOTHING;

-- ============================================================================
-- SECTION 3: Vulnerability Type Reference
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.vulnerability_types (
    vuln_type_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_type TEXT NOT NULL UNIQUE,
    cve_pattern TEXT,
    technical_category TEXT,  -- 'access_control', 'data_integrity', 'performance', 'audit'
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

INSERT INTO forgescan_security.vulnerability_types 
    (vuln_type, technical_category, description)
VALUES
    ('RLS_BYPASS', 'access_control', 'Row-Level Security policy not enforced or bypassed'),
    ('WEAK_MASKING', 'access_control', 'Sensitive columns not properly masked'),
    ('PERFORMANCE_DEGRADATION', 'performance', 'Slow queries causing timeouts/revenue loss'),
    ('AUDIT_LOG_GAP', 'audit', 'Missing audit trail entries'),
    ('ENCRYPTION_FAILURE', 'data_integrity', 'Encrypted columns not properly encrypted'),
    ('PRIVILEGE_ESCALATION', 'access_control', 'User role clearance not enforced'),
    ('UNLOGGED_WRITES', 'audit', 'Critical data written to UNLOGGED tables'),
    ('PARTITION_FAILURE', 'operations', 'Audit partition chain broken'),
    ('RATE_LIMIT_BYPASS', 'operations', 'Token bucket rate limiting bypassed'),
    ('COMPLIANCE_GAP', 'audit', 'Compliance requirement not implemented')
ON CONFLICT (vuln_type) DO NOTHING;

-- ============================================================================
-- SECTION 4: Deterministic Rules Matrix
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.remediation_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_type TEXT NOT NULL REFERENCES forgescan_security.vulnerability_types(vuln_type),
    context_trigger TEXT NOT NULL,  -- 'REVENUE', 'PCI', 'GDPR', 'PHI', 'ALL'
    
    -- Deterministic Priority Calculation
    base_priority_score INTEGER NOT NULL CHECK (base_priority_score >= 0 AND base_priority_score <= 100),
    revenue_bonus INTEGER DEFAULT 20,      -- +20 if REVENUE asset
    compliance_bonus INTEGER DEFAULT 30,   -- +30 if matching compliance framework
    exposure_multiplier NUMERIC DEFAULT 1, -- Multiplier based on record count
    
    -- Output: What must be done
    required_action TEXT NOT NULL,
    technical_fix_template TEXT,  -- SQL command with %I (schema), %I (table) placeholders
    
    -- Metadata
    severity_label TEXT CHECK (severity_label IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')),
    mitigation_time_hours INTEGER DEFAULT 24,  -- SLA for remediation
    created_at TIMESTAMPTZ DEFAULT NOW(),
    
    CONSTRAINT unique_rule UNIQUE (vuln_type, context_trigger)
);

-- Indexes for rule lookup
CREATE INDEX idx_remediation_rules_vuln ON forgescan_security.remediation_rules(vuln_type);
CREATE INDEX idx_remediation_rules_context ON forgescan_security.remediation_rules(context_trigger);
CREATE INDEX idx_remediation_rules_priority ON forgescan_security.remediation_rules(base_priority_score DESC);

-- ============================================================================
-- SECTION 5: Populate Deterministic Rules
-- ============================================================================

INSERT INTO forgescan_security.remediation_rules 
    (vuln_type, context_trigger, base_priority_score, revenue_bonus, compliance_bonus, 
     required_action, technical_fix_template, severity_label, mitigation_time_hours)
VALUES
-- Rule 1: RLS Bypass on Revenue/PCI data = EMERGENCY
('RLS_BYPASS', 'PCI', 100, 20, 30, 
 'Immediate RLS Enforcement & Audit Review', 
 'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY; REVOKE ALL ON %I.%I FROM PUBLIC;',
 'CRITICAL', 1),

('RLS_BYPASS', 'REVENUE', 100, 20, 20,
 'Immediate RLS Enforcement & Isolation',
 'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY; REVOKE ALL ON %I.%I FROM PUBLIC;',
 'CRITICAL', 1),

('RLS_BYPASS', 'ALL', 75, 0, 10,
 'Enforce RLS Policy',
 'ALTER TABLE %I.%I FORCE ROW LEVEL SECURITY;',
 'HIGH', 4),

-- Rule 2: Weak Masking on PII (GDPR Risk)
('WEAK_MASKING', 'GDPR', 85, 10, 30,
 'Enforce Dynamic Column Masking',
 'CREATE OR REPLACE VIEW %I.safe_%I AS SELECT * FROM %I.%I WHERE forgescan_security.user_has_access(tenant_id);',
 'HIGH', 8),

('WEAK_MASKING', 'PHI', 90, 10, 35,
 'Enforce Dynamic Column Masking for PHI',
 'CREATE OR REPLACE VIEW %I.safe_%I AS SELECT forgescan_security.mask_pii_column(data) FROM %I.%I;',
 'CRITICAL', 4),

('WEAK_MASKING', 'PCI', 85, 15, 30,
 'Enforce PCI Data Masking',
 'CREATE OR REPLACE VIEW %I.safe_%I AS SELECT forgescan_security.mask_card_number(cc_field) FROM %I.%I;',
 'CRITICAL', 4),

-- Rule 3: Performance Degradation on Revenue paths
('PERFORMANCE_DEGRADATION', 'REVENUE', 75, 20, 5,
 'Optimize Locking & Query Performance',
 'CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_opt_%s ON %I.%I USING bloom (created_at DESC);',
 'HIGH', 24),

-- Rule 4: Audit Log Gap (Compliance Breach)
('AUDIT_LOG_GAP', 'ALL', 60, 5, 25,
 'Repair Partition Chain & Restore Audit Trail',
 'SELECT forgescan_security.repair_audit_partitions();',
 'HIGH', 2),

-- Rule 5: Encryption Failure
('ENCRYPTION_FAILURE', 'PCI', 95, 20, 30,
 'Re-encrypt Credit Card Data',
 'UPDATE %I.%I SET credit_card_encrypted = forgescan_security.encrypt_field(credit_card, key_id) WHERE credit_card_encrypted IS NULL;',
 'CRITICAL', 2),

('ENCRYPTION_FAILURE', 'PHI', 95, 10, 35,
 'Re-encrypt Patient Health Information',
 'UPDATE %I.%I SET phi_encrypted = forgescan_security.encrypt_field(phi, key_id) WHERE phi_encrypted IS NULL;',
 'CRITICAL', 2),

-- Rule 6: Privilege Escalation
('PRIVILEGE_ESCALATION', 'ALL', 80, 10, 20,
 'Audit User Roles & Reset Clearance',
 'CALL forgescan_security.audit_user_roles();',
 'HIGH', 4),

-- Rule 7: Unlogged Writes (Audit Trail Loss)
('UNLOGGED_WRITES', 'ALL', 70, 5, 25,
 'Convert UNLOGGED to Logged Tables',
 'ALTER TABLE %I.%I SET LOGGED;',
 'HIGH', 8),

-- Rule 8: Rate Limit Bypass
('RATE_LIMIT_BYPASS', 'REVENUE', 65, 20, 10,
 'Enforce Token Bucket Rate Limiting',
 'SELECT forgescan_security.init_rate_limit(tenant_id, 1000, 10);',
 'MEDIUM', 12),

-- Rule 9: Compliance Gap (Generic)
('COMPLIANCE_GAP', 'GDPR', 70, 5, 30,
 'Implement GDPR Compliance Controls',
 'SELECT forgescan_security.apply_compliance_framework(tenant_id, %L);',
 'HIGH', 48),

('COMPLIANCE_GAP', 'PCI', 85, 10, 35,
 'Implement PCI-DSS Compliance Controls',
 'SELECT forgescan_security.apply_compliance_framework(tenant_id, %L);',
 'CRITICAL', 24);

-- ============================================================================
-- SECTION 6: Context-Aware Remediation Generator (Main Function)
-- ============================================================================

CREATE OR REPLACE FUNCTION forgescan_security.generate_remediation_plan(p_tenant_id UUID)
RETURNS TABLE (
    priority_rank INTEGER,
    asset_name TEXT,
    asset_type TEXT,
    data_sensitivity TEXT,
    vulnerability TEXT,
    business_impact TEXT,
    financial_risk TEXT,
    compliance_obligations TEXT,
    downtime_cost_per_hour INTEGER,
    required_action TEXT,
    remediation_command TEXT,
    mitigation_sla_hours INTEGER,
    severity TEXT
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT 
        -- 1. Deterministic Priority Score (Pure Math)
        (r.base_priority_score + 
         CASE WHEN a.asset_type = 'REVENUE' THEN r.revenue_bonus ELSE 0 END + 
         CASE WHEN a.data_sensitivity = ANY(string_to_array(r.context_trigger, ',')) 
              OR r.context_trigger = 'ALL' THEN r.compliance_bonus ELSE 0 END +
         LEAST(100, (a.max_exposure_records / 1000)::INTEGER)  -- Scale by exposure
        )::INTEGER as rank,

        -- 2. Asset Identification
        (a.schema_name || '.' || a.table_name)::TEXT,
        a.asset_type::TEXT,
        a.data_sensitivity::TEXT,

        -- 3. Vulnerability Description
        v.vuln_type::TEXT,

        -- 4. Business Impact (Human-Readable)
        format('Risk to %s (%s). Est. downtime cost: $%s/hr. %s records exposed.',
               a.asset_type, a.data_sensitivity, a.downtime_cost_per_hour, 
               COALESCE(a.max_exposure_records::TEXT, 'unknown'))::TEXT,

        -- 5. Financial Risk Classification
        CASE 
            WHEN a.downtime_cost_per_hour > 10000 THEN 'CRITICAL: REVENUE LOSS'
            WHEN array_length(a.compliance_frameworks, 1) > 0 THEN 'HIGH: REGULATORY FINE'
            WHEN a.data_sensitivity IN ('PII', 'PCI', 'PHI') THEN 'MEDIUM: DATA BREACH'
            ELSE 'LOW: OPERATIONAL'
        END::TEXT,

        -- 6. Compliance Context
        COALESCE(array_to_string(a.compliance_frameworks, ', '), 'None')::TEXT,

        -- 7. Financial Quantification
        a.downtime_cost_per_hour,

        -- 8. Required Action (Non-Negotiable)
        r.required_action::TEXT,

        -- 9. Context-Aware SQL Fix (Template Injection)
        format(COALESCE(r.technical_fix_template, ''),
               a.schema_name, a.table_name, a.schema_name, a.table_name)::TEXT,

        -- 10. SLA Compliance
        r.mitigation_time_hours,

        -- 11. Severity Label
        r.severity_label::TEXT

    -- Complex Join: Vulnerabilities → Assets → Rules
    FROM public.findings v  -- Actual scan findings
    JOIN forgescan_security.business_assets a 
        ON v.table_name = a.table_name 
        AND a.tenant_id = p_tenant_id
    JOIN forgescan_security.remediation_rules r 
        ON v.rule_id = r.vuln_type  -- Assuming findings have rule_id field
        AND (r.context_trigger = 'ALL' 
             OR r.context_trigger = a.data_sensitivity 
             OR r.context_trigger = a.asset_type
             OR r.context_trigger = ANY(a.compliance_frameworks))
    
    ORDER BY rank DESC;
END;
$$;

-- ============================================================================
-- SECTION 7: Business Impact Calculator (Compliance Fine Estimation)
-- ============================================================================

CREATE OR REPLACE FUNCTION forgescan_security.estimate_compliance_fine(
    p_data_sensitivity TEXT,
    p_max_records INTEGER,
    p_frameworks TEXT[]
)
RETURNS TABLE (
    framework TEXT,
    max_fine_usd NUMERIC,
    estimated_fine_usd NUMERIC
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT
        f.framework_name::TEXT,
        f.max_fine_percent_revenue * 1000000,  -- Assume $25M revenue for estimate
        COALESCE(f.fine_per_record_usd * p_max_records, 0)::NUMERIC
    FROM forgescan_security.compliance_frameworks f
    WHERE f.framework_name = ANY(p_frameworks)
    ORDER BY estimated_fine_usd DESC;
END;
$$;

-- ============================================================================
-- SECTION 8: Asset Tagging Helper (For Operations Team)
-- ============================================================================

CREATE OR REPLACE FUNCTION forgescan_security.tag_business_asset(
    p_tenant_id UUID,
    p_schema_name TEXT,
    p_table_name TEXT,
    p_asset_type TEXT,
    p_data_sensitivity TEXT,
    p_downtime_cost_per_hour INTEGER,
    p_compliance_frameworks TEXT[]
)
RETURNS UUID
LANGUAGE sql
SECURITY DEFINER
AS $$
    INSERT INTO forgescan_security.business_assets 
        (tenant_id, schema_name, table_name, asset_type, data_sensitivity, 
         downtime_cost_per_hour, compliance_frameworks)
    VALUES 
        (p_tenant_id, p_schema_name, p_table_name, p_asset_type, p_data_sensitivity, 
         p_downtime_cost_per_hour, p_compliance_frameworks)
    ON CONFLICT (tenant_id, schema_name, table_name) DO UPDATE
    SET asset_type = EXCLUDED.asset_type,
        data_sensitivity = EXCLUDED.data_sensitivity,
        downtime_cost_per_hour = EXCLUDED.downtime_cost_per_hour,
        compliance_frameworks = EXCLUDED.compliance_frameworks,
        updated_at = NOW()
    RETURNING asset_id;
$$;
