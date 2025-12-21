-- Phase 8: Trust, Observability & AI-Readiness
-- Created: 2025-12-21
-- Purpose: Immutable evidence ledger, observability metrics, remediation effectiveness tracking

-- 1) Immutable Evidence Ledger (Append-Only, Audit-Grade)
CREATE TABLE IF NOT EXISTS forgescan_security.evidence_ledger (
    evidence_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    evidence_type TEXT NOT NULL CHECK (evidence_type IN (
        'SCAN',          -- Scan evidence: what was tested
        'ENFORCEMENT',   -- Enforcement decision: why was it blocked
        'REMEDIATION',   -- Remediation applied: what was fixed
        'CI_DECISION'    -- CI/CD decision: gate outcome
    )),
    related_entity TEXT NOT NULL,    -- e.g., "scan_id:123", "decision_id:456"
    hash TEXT NOT NULL,              -- SHA256 of payload (immutable proof)
    created_at TIMESTAMPTZ DEFAULT NOW(),
    payload JSONB NOT NULL,          -- Full context (not searchable, not indexed)
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES forgescan_security.tenant_registry(tenant_id)
);

-- Indexes for audit queries
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_tenant ON forgescan_security.evidence_ledger(tenant_id);
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_type ON forgescan_security.evidence_ledger(evidence_type);
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_entity ON forgescan_security.evidence_ledger(related_entity);
CREATE INDEX IF NOT EXISTS idx_evidence_ledger_created_at ON forgescan_security.evidence_ledger(created_at DESC);

-- 2) Remediation Effectiveness Tracking (Enables SLA Reporting)
CREATE TABLE IF NOT EXISTS forgescan_security.remediation_effectiveness (
    remediation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    vuln_type TEXT NOT NULL,        -- e.g., RLS_BYPASS, WEAK_MASKING
    asset_name TEXT,                -- e.g., public.orders
    severity TEXT,                  -- CRITICAL, HIGH, MEDIUM, LOW
    first_detected TIMESTAMPTZ NOT NULL,
    fixed_at TIMESTAMPTZ,
    recurrence_count INTEGER DEFAULT 0,
    time_to_fix_hours DECIMAL(10, 2),  -- (fixed_at - first_detected) / 3600
    sla_met BOOLEAN,                -- time_to_fix_hours <= mitigation_sla_hours
    sla_target_hours INTEGER,       -- From remediation_rules
    remediation_command TEXT,       -- The fix that was applied
    last_verified_at TIMESTAMPTZ,
    
    CONSTRAINT fk_tenant FOREIGN KEY (tenant_id) REFERENCES forgescan_security.tenant_registry(tenant_id)
);

CREATE INDEX IF NOT EXISTS idx_remediation_effectiveness_tenant ON forgescan_security.remediation_effectiveness(tenant_id);
CREATE INDEX IF NOT EXISTS idx_remediation_effectiveness_vuln_type ON forgescan_security.remediation_effectiveness(vuln_type);
CREATE INDEX IF NOT EXISTS idx_remediation_effectiveness_fixed_at ON forgescan_security.remediation_effectiveness(fixed_at DESC);

-- 3) Log Evidence Function (Append-Only)
CREATE OR REPLACE FUNCTION forgescan_security.log_evidence(
    p_tenant_id UUID,
    p_evidence_type TEXT,
    p_related_entity TEXT,
    p_payload JSONB
)
RETURNS UUID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_evidence_id UUID;
    v_hash TEXT;
BEGIN
    -- Compute SHA256 hash of payload (immutable fingerprint)
    v_hash := encode(
        digest(p_payload::TEXT, 'sha256'),
        'hex'
    );
    
    -- Insert evidence (append-only, no updates)
    INSERT INTO forgescan_security.evidence_ledger(
        tenant_id, evidence_type, related_entity, hash, payload
    ) VALUES (
        p_tenant_id, p_evidence_type, p_related_entity, v_hash, p_payload
    ) RETURNING evidence_id INTO v_evidence_id;
    
    RETURN v_evidence_id;
END;
$$;

-- 4) Query Evidence Function (Read-Only)
CREATE OR REPLACE FUNCTION forgescan_security.query_evidence(
    p_tenant_id UUID,
    p_evidence_type TEXT DEFAULT NULL,
    p_limit INTEGER DEFAULT 100
)
RETURNS TABLE (
    evidence_id UUID,
    evidence_type TEXT,
    related_entity TEXT,
    hash TEXT,
    created_at TIMESTAMPTZ,
    payload JSONB
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
AS $$
BEGIN
    RETURN QUERY
    SELECT e.evidence_id, e.evidence_type, e.related_entity, e.hash, e.created_at, e.payload
    FROM forgescan_security.evidence_ledger e
    WHERE e.tenant_id = p_tenant_id
      AND (p_evidence_type IS NULL OR e.evidence_type = p_evidence_type)
    ORDER BY e.created_at DESC
    LIMIT p_limit;
END;
$$;

-- 5) Business Metrics View: Revenue at Risk
CREATE OR REPLACE VIEW forgescan_security.metrics_revenue_at_risk AS
SELECT
    t.tenant_id,
    SUM(ba.downtime_cost_per_hour * 1) AS revenue_at_risk_1hr_usd,
    COUNT(DISTINCT ba.asset_id) AS high_value_assets,
    MAX(rp.priority_rank) AS max_priority_detected
FROM forgescan_security.tenant_registry t
LEFT JOIN forgescan_security.business_assets ba ON t.tenant_id = ba.tenant_id
LEFT JOIN LATERAL forgescan_security.generate_remediation_plan(t.tenant_id) rp ON TRUE
GROUP BY t.tenant_id;

-- 6) Business Metrics View: Compliance Exposure
CREATE OR REPLACE VIEW forgescan_security.metrics_compliance_exposure AS
SELECT
    t.tenant_id,
    COUNT(DISTINCT ba.compliance_frameworks) AS frameworks_at_risk,
    ARRAY_AGG(DISTINCT UNNEST(ba.compliance_frameworks)) AS frameworks_list,
    COUNT(DISTINCT ba.asset_id) FILTER (WHERE ba.data_sensitivity IN ('PII', 'PCI', 'PHI')) AS sensitive_assets,
    SUM(CASE WHEN ba.data_sensitivity = 'PCI' THEN ba.max_exposure_records ELSE 0 END) AS pci_records_exposed,
    SUM(CASE WHEN ba.data_sensitivity = 'PII' THEN ba.max_exposure_records ELSE 0 END) AS pii_records_exposed,
    SUM(CASE WHEN ba.data_sensitivity = 'PHI' THEN ba.max_exposure_records ELSE 0 END) AS phi_records_exposed
FROM forgescan_security.tenant_registry t
LEFT JOIN forgescan_security.business_assets ba ON t.tenant_id = ba.tenant_id
GROUP BY t.tenant_id;

-- 7) Business Metrics View: SLA Performance (Remediation Effectiveness)
CREATE OR REPLACE VIEW forgescan_security.metrics_sla_performance AS
SELECT
    t.tenant_id,
    COUNT(DISTINCT re.remediation_id) AS total_remediated,
    COUNT(DISTINCT re.remediation_id) FILTER (WHERE re.sla_met = TRUE) AS sla_met_count,
    ROUND(100.0 * COUNT(DISTINCT re.remediation_id) FILTER (WHERE re.sla_met = TRUE) / NULLIF(COUNT(DISTINCT re.remediation_id), 0), 2) AS sla_compliance_pct,
    ROUND(AVG(re.time_to_fix_hours), 2) AS avg_time_to_fix_hours,
    MAX(re.time_to_fix_hours) AS max_time_to_fix_hours,
    COUNT(DISTINCT re.remediation_id) FILTER (WHERE re.recurrence_count > 0) AS recurrence_count
FROM forgescan_security.tenant_registry t
LEFT JOIN forgescan_security.remediation_effectiveness re ON t.tenant_id = re.tenant_id
GROUP BY t.tenant_id;

-- 8) Business Metrics View: Enforcement Effectiveness
CREATE OR REPLACE VIEW forgescan_security.metrics_enforcement_effectiveness AS
SELECT
    t.tenant_id,
    COUNT(DISTINCT ed.decision_id) FILTER (WHERE ed.decision = 'BLOCK') AS builds_blocked,
    COUNT(DISTINCT ed.decision_id) FILTER (WHERE ed.decision = 'ALLOW_WITH_ACK') AS soft_fails_required_ack,
    COUNT(DISTINCT ed.decision_id) FILTER (WHERE ed.acked_by IS NOT NULL) AS soft_fails_acknowledged,
    MAX(ed.max_priority) AS max_priority_blocked,
    ROUND(100.0 * COUNT(DISTINCT ed.decision_id) FILTER (WHERE ed.decision = 'BLOCK') / NULLIF(COUNT(DISTINCT ed.decision_id), 0), 2) AS block_rate_pct
FROM forgescan_security.tenant_registry t
LEFT JOIN forgescan_security.enforcement_decisions ed ON t.tenant_id = ed.tenant_id
GROUP BY t.tenant_id;

-- 9) Grant minimal rights for read-only queries
-- GRANT SELECT ON forgescan_security.evidence_ledger TO forgescan_auditor;
-- GRANT SELECT ON forgescan_security.remediation_effectiveness TO forgescan_auditor;
-- GRANT SELECT ON forgescan_security.metrics_revenue_at_risk TO forgescan_auditor;
-- GRANT SELECT ON forgescan_security.metrics_compliance_exposure TO forgescan_auditor;
-- GRANT SELECT ON forgescan_security.metrics_sla_performance TO forgescan_auditor;
-- GRANT SELECT ON forgescan_security.metrics_enforcement_effectiveness TO forgescan_auditor;

-- End of Phase 8 SQL
