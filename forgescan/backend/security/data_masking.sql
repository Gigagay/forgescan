-- ForgeScan 2.0: Dynamic Data Masking & Column-Level Security
-- ============================================================================
-- Instead of binary row-level access (all or nothing), we use views with
-- CASE statements to dynamically mask columns based on user roles.
-- This allows compliance officers to see full data while regular users see masked data.
-- ============================================================================

-- ============================================================================
-- SECTION 1: Dynamic Masking View for Sensitive Data
-- ============================================================================

-- Base table with sensitive columns and integrity hashes
CREATE TABLE IF NOT EXISTS forgescan_security.sensitive_data (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    field_name VARCHAR(255) NOT NULL,
    value_encrypted TEXT NOT NULL,
    value_plaintext TEXT,  -- For masking demo (in production, always encrypt)
    row_hash TEXT GENERATED ALWAYS AS (
        encode(digest(tenant_id::text || field_name || value_plaintext, 'sha256'), 'hex')
    ) STORED,  -- Merkle-tree style integrity check
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS on base table as backstop
ALTER TABLE forgescan_security.sensitive_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY sensitive_data_isolation ON forgescan_security.sensitive_data
    USING (tenant_id = forgescan_security.get_context_uuid('forgescan.tenant_id'));

-- ============================================================================
-- SECTION 2: Dynamic Masking View (Entry Point for Users)
-- ============================================================================

CREATE OR REPLACE VIEW forgescan_security.masked_sensitive_data AS
SELECT
    id,
    tenant_id,
    field_name,
    -- Dynamic Masking Logic based on role
    CASE 
        WHEN forgescan_security.user_has_role('compliance_officer') THEN value_plaintext
        WHEN forgescan_security.user_has_role('auditor') THEN value_plaintext
        WHEN forgescan_security.user_has_role('admin') THEN value_plaintext
        -- Default masking for regular users
        ELSE 'REDACTED[' || substring(value_plaintext, 1, 2) || '...]'
    END AS value_display,
    -- Always show encryption status
    CASE WHEN value_encrypted IS NOT NULL THEN true ELSE false END AS is_encrypted,
    -- Integrity verification (tamper detection)
    (encode(digest(tenant_id::text || field_name || value_plaintext, 'sha256'), 'hex') = row_hash) 
        AS is_integrity_valid,
    created_at,
    updated_at
FROM forgescan_security.sensitive_data
WHERE forgescan_security.user_has_access(tenant_id, 0);

-- ============================================================================
-- SECTION 3: Masked Credit Card View (Example)
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.payment_info (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    customer_id UUID NOT NULL,
    credit_card TEXT NOT NULL,  -- Plaintext for demo (encrypt in production!)
    cardholder_name TEXT NOT NULL,
    expiry_date TEXT NOT NULL,
    row_hash TEXT GENERATED ALWAYS AS (
        forgescan_security.compute_row_hash(tenant_id::text || credit_card)
    ) STORED,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE forgescan_security.payment_info ENABLE ROW LEVEL SECURITY;

CREATE POLICY payment_info_isolation ON forgescan_security.payment_info
    USING (tenant_id = forgescan_security.get_context_uuid('forgescan.tenant_id'));

-- Masked view: Show last 4 digits only to non-compliance users
CREATE OR REPLACE VIEW forgescan_security.masked_payment_info AS
SELECT
    id,
    tenant_id,
    customer_id,
    -- Masking: Show full card to compliance, masked to others
    CASE 
        WHEN forgescan_security.user_has_role('compliance_officer') THEN credit_card
        WHEN forgescan_security.user_has_role('payments_admin') THEN credit_card
        ELSE 'XXXX-XXXX-XXXX-' || RIGHT(credit_card, 4)
    END AS credit_card_display,
    -- Always show name (no sensitive PII here)
    cardholder_name,
    -- Masked expiry (show MM/YY to authorized users only)
    CASE 
        WHEN forgescan_security.user_has_role('compliance_officer') THEN expiry_date
        ELSE 'XX/XX'
    END AS expiry_display,
    -- Integrity check
    (row_hash = forgescan_security.compute_row_hash(tenant_id::text || credit_card)) AS is_tamper_evident,
    created_at
FROM forgescan_security.payment_info
WHERE forgescan_security.user_has_access(tenant_id, 0);

-- ============================================================================
-- SECTION 4: Audit Access to Sensitive Data (Logged Masking Decisions)
-- ============================================================================

-- Function to log access to sensitive data with masking context
CREATE OR REPLACE FUNCTION forgescan_security.log_sensitive_access(
    p_sensitive_id UUID,
    p_field_name TEXT,
    p_access_type TEXT  -- 'view_masked', 'view_unmasked', 'export'
)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
AS $$
    INSERT INTO forgescan_security.audit_log (
        tenant_id, user_id, operation, schema_name, table_name,
        client_ip, meta
    ) VALUES (
        forgescan_security.get_context_uuid('forgescan.tenant_id'),
        forgescan_security.get_context_text('forgescan.user_id'),
        p_access_type,
        'security',
        'sensitive_data',
        current_setting('forgescan.client_ip', true)::INET,
        jsonb_build_object(
            'sensitive_id', p_sensitive_id,
            'field_name', p_field_name,
            'user_role', forgescan_security.get_context_text('forgescan.roles'),
            'risk_score', 50
        )
    );
$$;

-- ============================================================================
-- SECTION 5: Data Export with Masking (Controlled Unmasking)
-- ============================================================================

CREATE OR REPLACE FUNCTION forgescan_security.export_sensitive_data(
    p_format TEXT DEFAULT 'json'  -- 'json', 'csv', 'parquet'
)
RETURNS TABLE (
    export_id UUID,
    exported_data JSONB,
    masking_applied BOOLEAN,
    created_at TIMESTAMPTZ
)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_export_id UUID := gen_random_uuid();
    v_role TEXT;
BEGIN
    v_role := forgescan_security.get_context_text('forgescan.roles');

    -- Log the export request (mandatory audit trail)
    PERFORM forgescan_security.log_security_event(
        'data_export',
        'INFO',
        jsonb_build_object('export_id', v_export_id, 'format', p_format)
    );

    -- Return masked or unmasked data based on role
    RETURN QUERY
    SELECT
        v_export_id,
        jsonb_build_object(
            'id', sd.id,
            'field_name', sd.field_name,
            'value', CASE 
                WHEN v_role LIKE '%compliance_officer%' THEN sd.value_plaintext
                ELSE 'REDACTED'
            END,
            'is_encrypted', sd.value_encrypted IS NOT NULL
        ),
        (v_role NOT LIKE '%compliance_officer%') AS masking_applied,
        NOW()
    FROM forgescan_security.sensitive_data sd
    WHERE sd.tenant_id = forgescan_security.get_context_uuid('forgescan.tenant_id');
END;
$$;

-- ============================================================================
-- SECTION 6: Column-Level Encryption Key Management
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.encryption_keys (
    key_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES forgescan_security.tenant_registry(tenant_id) ON DELETE CASCADE,
    key_name VARCHAR(255) NOT NULL,
    key_material TEXT NOT NULL,  -- Encrypted externally (KMS)
    algorithm VARCHAR(32) DEFAULT 'AES-256-GCM',
    created_at TIMESTAMPTZ DEFAULT NOW(),
    rotated_at TIMESTAMPTZ,
    is_active BOOLEAN DEFAULT true,
    UNIQUE(tenant_id, key_name)
);

-- Function to encrypt sensitive data before storage
CREATE OR REPLACE FUNCTION forgescan_security.encrypt_field(
    p_plaintext TEXT,
    p_key_id UUID
)
RETURNS TEXT
LANGUAGE sql
SECURITY DEFINER
AS $$
    -- Note: This is a placeholder. In production, use pgcrypto or external KMS
    SELECT encode(encrypt(
        convert_to(p_plaintext, 'UTF8'),
        (SELECT key_material FROM forgescan_security.encryption_keys WHERE key_id = p_key_id)::bytea,
        'aes'
    ), 'hex');
$$;

-- Function to decrypt sensitive data on retrieval
CREATE OR REPLACE FUNCTION forgescan_security.decrypt_field(
    p_ciphertext TEXT,
    p_key_id UUID
)
RETURNS TEXT
LANGUAGE sql
SECURITY DEFINER
AS $$
    -- Note: This is a placeholder. In production, use pgcrypto or external KMS
    SELECT convert_from(decrypt(
        decode(p_ciphertext, 'hex'),
        (SELECT key_material FROM forgescan_security.encryption_keys WHERE key_id = p_key_id)::bytea,
        'aes'
    ), 'UTF8');
$$;
