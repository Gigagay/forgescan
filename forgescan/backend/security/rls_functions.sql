-- ForgeScan 2.0: LEAKPROOF Security Functions
-- ============================================================================
-- These functions are marked LEAKPROOF and STABLE to allow query planner
-- to push them down into scan nodes without side-channel risks.
-- They form the backbone of secure context management, MAC (Mandatory Access Control),
-- and high-performance authorization checks.
-- ============================================================================

-- ============================================================================
-- SECTION 1: Helper Functions for Context Management
-- ============================================================================

-- Safe UUID context extraction (LEAKPROOF for security)
CREATE OR REPLACE FUNCTION forgescan_security.get_context_uuid(key TEXT)
RETURNS UUID
LANGUAGE sql
STABLE
PARALLEL SAFE
LEAKPROOF
AS $$
    SELECT NULLIF(current_setting(key, true), '')::UUID;
$$;

-- Safe integer context extraction (for clearance levels)
CREATE OR REPLACE FUNCTION forgescan_security.get_context_int(key TEXT, default_val INTEGER DEFAULT 0)
RETURNS INTEGER
LANGUAGE sql
STABLE
PARALLEL SAFE
LEAKPROOF
AS $$
    SELECT COALESCE(NULLIF(current_setting(key, true), '')::INTEGER, default_val);
$$;

-- Safe text context extraction (for roles)
CREATE OR REPLACE FUNCTION forgescan_security.get_context_text(key TEXT)
RETURNS TEXT
LANGUAGE sql
STABLE
PARALLEL SAFE
LEAKPROOF
AS $$
    SELECT NULLIF(current_setting(key, true), '');
$$;

-- ============================================================================
-- SECTION 2: Secure Tenant & Access Control Functions
-- ============================================================================

-- Core access check combining tenant isolation + clearance levels
CREATE OR REPLACE FUNCTION forgescan_security.user_has_access(
    p_row_tenant_id UUID,
    p_required_clearance INTEGER DEFAULT 0
)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
LEAKPROOF
SECURITY DEFINER
AS $$
DECLARE
    v_session_tenant UUID;
    v_user_clearance INTEGER;
BEGIN
    -- Extract context variables safely
    v_session_tenant := forgescan_security.get_context_uuid('forgescan.tenant_id');
    v_user_clearance := forgescan_security.get_context_int('forgescan.clearance', 0);

    -- 1. Tenant Isolation (Primary Defense)
    IF v_session_tenant IS DISTINCT FROM p_row_tenant_id THEN
        RETURN FALSE;
    END IF;

    -- 2. Clearance Level (Mandatory Access Control)
    IF v_user_clearance < p_required_clearance THEN
        RETURN FALSE;
    END IF;

    RETURN TRUE;
END;
$$;

-- Check if user has specific role (for fine-grained authorization)
CREATE OR REPLACE FUNCTION forgescan_security.user_has_role(p_required_role TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
LEAKPROOF
SECURITY DEFINER
AS $$
    SELECT forgescan_security.get_context_text('forgescan.roles') LIKE '%' || p_required_role || '%';
$$;

-- ============================================================================
-- SECTION 3: Token Bucket Rate Limiting (O(1) Performance)
-- ============================================================================

-- Main rate limit check function
CREATE OR REPLACE FUNCTION forgescan_security.check_rate_limit(p_tenant_id UUID)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    r forgescan_security.rate_limits%ROWTYPE;
    v_now TIMESTAMPTZ := NOW();
    v_delta NUMERIC;
    v_new_tokens NUMERIC;
BEGIN
    -- Lock only the specific tenant row (row-level locking, not table-level)
    -- SKIP LOCKED allows other transactions to proceed
    SELECT * INTO r 
    FROM forgescan_security.rate_limits 
    WHERE tenant_id = p_tenant_id 
    FOR UPDATE SKIP LOCKED; 

    IF NOT FOUND THEN 
        -- Tenant not in rate limit table; fail open (allow) or closed (deny) based on policy
        RETURN TRUE;
    END IF; 

    -- Calculate token refill based on time elapsed
    v_delta := EXTRACT(EPOCH FROM (v_now - r.last_update));
    v_new_tokens := LEAST(r.bucket_size::NUMERIC, r.tokens + (v_delta * r.refill_rate));

    -- Check if we have tokens available
    IF v_new_tokens < 1 THEN
        RETURN FALSE; -- Throttled
    END IF;

    -- Deduct one token and update timestamp
    UPDATE forgescan_security.rate_limits
    SET tokens = v_new_tokens - 1,
        last_update = v_now
    WHERE tenant_id = p_tenant_id;

    RETURN TRUE;
END;
$$;

-- Initialize or reset rate limit for a tenant
CREATE OR REPLACE FUNCTION forgescan_security.init_rate_limit(
    p_tenant_id UUID,
    p_bucket_size INTEGER DEFAULT 1000,
    p_refill_rate NUMERIC DEFAULT 10
)
RETURNS VOID
LANGUAGE sql
SECURITY DEFINER
AS $$
    INSERT INTO forgescan_security.rate_limits (tenant_id, bucket_size, tokens, refill_rate)
    VALUES (p_tenant_id, p_bucket_size, p_bucket_size::NUMERIC, p_refill_rate)
    ON CONFLICT (tenant_id) DO UPDATE
    SET bucket_size = EXCLUDED.bucket_size,
        tokens = EXCLUDED.bucket_size::NUMERIC,
        refill_rate = EXCLUDED.refill_rate,
        last_update = NOW();
$$;

-- ============================================================================
-- SECTION 4: Session Context Management
-- ============================================================================

-- Validate and cache session context for high-speed checks
CREATE OR REPLACE FUNCTION forgescan_security.validate_session(
    p_session_token TEXT,
    p_tenant_id UUID,
    p_user_id TEXT,
    p_clearance INTEGER
)
RETURNS BOOLEAN
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Insert or update session cache (UNLOGGED for speed)
    INSERT INTO forgescan_security.session_cache (
        session_token, tenant_id, user_id, roles, clearance_level, expires_at
    ) VALUES (
        p_session_token,
        p_tenant_id,
        p_user_id,
        ARRAY['user'],  -- TODO: fetch from user.roles
        p_clearance,
        NOW() + INTERVAL '1 hour'
    )
    ON CONFLICT (session_token) DO UPDATE
    SET expires_at = NOW() + INTERVAL '1 hour',
        clearance_level = EXCLUDED.clearance_level;

    RETURN TRUE;
END;
$$;

-- Check if session is still valid
CREATE OR REPLACE FUNCTION forgescan_security.is_session_valid(p_session_token TEXT)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
LEAKPROOF
SECURITY DEFINER
AS $$
    SELECT EXISTS(
        SELECT 1 FROM forgescan_security.session_cache
        WHERE session_token = p_session_token
        AND expires_at > NOW()
    );
$$;

-- ============================================================================
-- SECTION 5: Audit & Logging Helpers
-- ============================================================================

-- Log security event to audit trail
CREATE OR REPLACE FUNCTION forgescan_security.log_security_event(
    p_event_type TEXT,
    p_severity TEXT,
    p_details JSONB
)
RETURNS UUID
LANGUAGE sql
SECURITY DEFINER
AS $$
    INSERT INTO forgescan_security.audit_log (
        tenant_id, user_id, operation, schema_name, table_name,
        client_ip, meta
    ) VALUES (
        forgescan_security.get_context_uuid('forgescan.tenant_id'),
        forgescan_security.get_context_text('forgescan.user_id'),
        p_event_type,
        'security',
        'event',
        current_setting('forgescan.client_ip', true)::INET,
        jsonb_build_object('severity', p_severity) || p_details
    )
    RETURNING audit_id;
$$;

-- ============================================================================
-- SECTION 6: Data Integrity Verification
-- ============================================================================

-- Generate cryptographic fingerprint for data integrity (used with GENERATED columns)
CREATE OR REPLACE FUNCTION forgescan_security.compute_row_hash(
    p_data TEXT
)
RETURNS TEXT
LANGUAGE sql
STABLE
LEAKPROOF
AS $$
    SELECT encode(digest(p_data, 'sha256'), 'hex');
$$;

-- Verify data hasn't been tampered with
CREATE OR REPLACE FUNCTION forgescan_security.verify_integrity(
    p_data TEXT,
    p_stored_hash TEXT
)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
LEAKPROOF
AS $$
    SELECT forgescan_security.compute_row_hash(p_data) = p_stored_hash;
$$;
