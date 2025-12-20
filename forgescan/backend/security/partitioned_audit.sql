-- ForgeScan 2.0: Partitioned Audit Log with High-Performance Indexing
-- ============================================================================
-- Table partitioning by date allows O(1) deletion of old data by detaching partitions
-- instead of DELETE (which is O(N) and locks the entire table).
-- Bloom indexes provide fast filtering on high-cardinality sparse columns.
-- ============================================================================

-- ============================================================================
-- SECTION 1: Create Partitioned Audit Log Table
-- ============================================================================

CREATE TABLE IF NOT EXISTS forgescan_security.audit_log (
    audit_id UUID DEFAULT gen_random_uuid() NOT NULL,
    event_timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    operation TEXT NOT NULL,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    query_text TEXT,
    affected_rows INTEGER,
    risk_score INTEGER DEFAULT 0,
    client_ip INET,
    meta JSONB,
    CONSTRAINT pk_audit_log PRIMARY KEY (audit_id, event_timestamp)
) PARTITION BY RANGE (event_timestamp);

-- ============================================================================
-- SECTION 2: Create Monthly Partitions
-- ============================================================================
-- Pattern: audit_log_yYYYYmMM (e.g., audit_log_y2025m12)
-- Auto-create on-demand using triggers or Alembic migrations

-- December 2025
CREATE TABLE IF NOT EXISTS forgescan_security.audit_log_y2025m12
    PARTITION OF forgescan_security.audit_log
    FOR VALUES FROM ('2025-12-01'::TIMESTAMPTZ) TO ('2026-01-01'::TIMESTAMPTZ);

-- January 2026
CREATE TABLE IF NOT EXISTS forgescan_security.audit_log_y2026m01
    PARTITION OF forgescan_security.audit_log
    FOR VALUES FROM ('2026-01-01'::TIMESTAMPTZ) TO ('2026-02-01'::TIMESTAMPTZ);

-- ============================================================================
-- SECTION 3: Partition-Level Indexes for Performance
-- ============================================================================

-- Tenant + timestamp lookup (primary access pattern)
CREATE INDEX idx_audit_log_y2025m12_tenant_time 
    ON forgescan_security.audit_log_y2025m12 (tenant_id, event_timestamp DESC);

CREATE INDEX idx_audit_log_y2026m01_tenant_time 
    ON forgescan_security.audit_log_y2026m01 (tenant_id, event_timestamp DESC);

-- Bloom index for user_id (high-cardinality, sparse searches)
CREATE INDEX idx_audit_log_y2025m12_user_bloom 
    ON forgescan_security.audit_log_y2025m12 USING bloom (user_id);

CREATE INDEX idx_audit_log_y2026m01_user_bloom 
    ON forgescan_security.audit_log_y2026m01 USING bloom (user_id);

-- Bloom index for operation (common patterns: INSERT, UPDATE, DELETE)
CREATE INDEX idx_audit_log_y2025m12_op_bloom 
    ON forgescan_security.audit_log_y2025m12 USING bloom (operation);

CREATE INDEX idx_audit_log_y2026m01_op_bloom 
    ON forgescan_security.audit_log_y2026m01 USING bloom (operation);

-- JSONB metadata for risk analysis
CREATE INDEX idx_audit_log_y2025m12_meta_gin 
    ON forgescan_security.audit_log_y2025m12 USING gin (meta);

CREATE INDEX idx_audit_log_y2026m01_meta_gin 
    ON forgescan_security.audit_log_y2026m01 USING gin (meta);

-- ============================================================================
-- SECTION 4: Partition Maintenance Functions
-- ============================================================================

-- Create new partition for the next month (run via cron or application)
CREATE OR REPLACE FUNCTION forgescan_security.create_next_audit_partition()
RETURNS VOID
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_partition_name TEXT;
    v_from_date DATE;
    v_to_date DATE;
BEGIN
    v_from_date := DATE_TRUNC('month', NOW() + INTERVAL '1 month')::DATE;
    v_to_date := v_from_date + INTERVAL '1 month';
    v_partition_name := 'audit_log_y' || TO_CHAR(v_from_date, 'YYYY') || 'm' || TO_CHAR(v_from_date, 'MM');

    EXECUTE format('
        CREATE TABLE IF NOT EXISTS forgescan_security.%I
        PARTITION OF forgescan_security.audit_log
        FOR VALUES FROM (%L::TIMESTAMPTZ) TO (%L::TIMESTAMPTZ)',
        v_partition_name, v_from_date, v_to_date
    );

    -- Create indexes on the new partition
    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_tenant_time
        ON forgescan_security.%I (tenant_id, event_timestamp DESC)',
        v_partition_name, v_partition_name
    );

    EXECUTE format('
        CREATE INDEX IF NOT EXISTS idx_%s_user_bloom
        ON forgescan_security.%I USING bloom (user_id)',
        v_partition_name, v_partition_name
    );

    RAISE NOTICE 'Created partition: %', v_partition_name;
END;
$$;

-- Detach and drop old partitions (run via cron, e.g., monthly)
CREATE OR REPLACE FUNCTION forgescan_security.prune_old_audit_partitions(p_months_to_keep INTEGER DEFAULT 12)
RETURNS TABLE(partition_name TEXT, status TEXT)
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_old_partition RECORD;
    v_cutoff_date TIMESTAMPTZ;
BEGIN
    v_cutoff_date := NOW() - (p_months_to_keep || ' months')::INTERVAL;

    FOR v_old_partition IN
        SELECT tablename
        FROM pg_tables
        WHERE schemaname = 'forgescan_security'
        AND tablename LIKE 'audit_log_y%'
        AND SUBSTRING(tablename, 11, 7)::DATE < v_cutoff_date::DATE
    LOOP
        EXECUTE format('
            ALTER TABLE forgescan_security.audit_log
            DETACH PARTITION forgescan_security.%I',
            v_old_partition.tablename
        );

        EXECUTE format('DROP TABLE IF EXISTS forgescan_security.%I',
            v_old_partition.tablename
        );

        RETURN QUERY SELECT v_old_partition.tablename::TEXT, 'dropped'::TEXT;
    END LOOP;
END;
$$;

-- ============================================================================
-- SECTION 5: UNLOGGED Session Cache (High-Speed, Non-Durable)
-- ============================================================================
-- Used for ephemeral data that can be rebuilt (session tokens, etc.)
-- UNLOGGED tables skip WAL writes, making them 10-100x faster

CREATE UNLOGGED TABLE IF NOT EXISTS forgescan_security.session_cache (
    session_token TEXT PRIMARY KEY,
    tenant_id UUID NOT NULL,
    user_id TEXT NOT NULL,
    roles TEXT[] NOT NULL,
    clearance_level INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for quick lookups
CREATE INDEX idx_session_cache_expires 
    ON forgescan_security.session_cache (expires_at);

-- ============================================================================
-- SECTION 6: Audit Trigger (Fast, Asynchronous-Ready)
-- ============================================================================

CREATE OR REPLACE FUNCTION forgescan_security.audit_trigger_func()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
BEGIN
    -- Fast insert without heavy processing
    -- Heavy anomaly detection should run asynchronously (background worker, cron)
    
    INSERT INTO forgescan_security.audit_log (
        tenant_id, user_id, operation, schema_name, 
        table_name, client_ip, meta
    ) VALUES (
        forgescan_security.get_context_uuid('forgescan.tenant_id'),
        forgescan_security.get_context_text('forgescan.user_id'),
        TG_OP,
        TG_TABLE_SCHEMA,
        TG_TABLE_NAME,
        current_setting('forgescan.client_ip', true)::INET,
        jsonb_build_object('risk_score', 0) -- Placeholder for async processor
    );
    
    RETURN NULL; -- For AFTER triggers
END;
$$;

-- Enable on sensitive tables
-- Example: CREATE TRIGGER audit_log_fast AFTER INSERT OR UPDATE OR DELETE ON tenant1.findings
--          FOR EACH ROW EXECUTE FUNCTION forgescan_security.audit_trigger_func();
