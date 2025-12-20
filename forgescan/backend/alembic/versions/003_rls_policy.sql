-- PostgreSQL Row Level Security (RLS) Configuration for Multi-Tenancy
-- 
-- These commands must be executed against the PostgreSQL database to enable
-- Row Level Security on the scans and findings tables. This ensures that
-- queries are automatically filtered by tenant_id based on the current session.
--
-- Prerequisites:
-- - The scans and findings tables must already exist
-- - The app.tenant_id setting must be set by the backend before queries
--
-- Execution:
-- Run these commands in a psql session with a superuser account:
--   psql -U postgres -d forgescan -f rls_policy.sql
--

-- Enable Row Level Security on the scans table
ALTER TABLE scans ENABLE ROW LEVEL SECURITY;

-- Enable Row Level Security on the findings table
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;

-- Create policy for scans table: users can only see scans from their tenant
CREATE POLICY tenant_scan_policy ON scans
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Create policy for findings table: users can only see findings from their tenant
CREATE POLICY tenant_findings_policy ON findings
  USING (tenant_id = current_setting('app.tenant_id')::uuid);

-- Note: The backend must set the tenant context before queries:
--   BEGIN;
--   SET LOCAL app.tenant_id TO '<tenant_uuid>';
--   -- Execute queries here
--   COMMIT;
