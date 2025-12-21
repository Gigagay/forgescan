# Phase 6 — Enforcement, Ingestion & CI/CD Gatekeeping

Date: 2025-12-21

Purpose (Strict Definition)
---------------------------
Phase 6 operationalizes deterministic intelligence from Phases 2–5 by binding scanner output → business logic → enforcement points, ensuring high-impact risks cannot be ignored, bypassed, or deprioritized by humans.

This phase does NOT add new intelligence. It forces compliance with existing intelligence.

What Phase 6 IS (And Is Not)
-----------------------------
✅ Phase 6 IS
- Deterministic ingestion of scan findings
- Canonical vulnerability normalization
- Hard enforcement via CI/CD & runtime gates
- Priority-based blocking (profit & compliance aware)
- Zero AI
- Zero opinions

❌ Phase 6 IS NOT
- New scanners
- New rules
- AI remediation
- Dashboards
- UX polish

Architecture Flow
-----------------
[ Scanner Output ]
        ↓
[ Normalization Layer ]
        ↓
[ tenant.vulnerabilities ]   ← Canonical truth
        ↓
[ Phase 5 DPL Engine ]
        ↓
[ Enforcement Points ]
   ├── CI/CD (Fail Builds)
   ├── Runtime (Block Deploy)
   └── Ops Reports (Read-only)

SECTION 9 — Canonical Vulnerability Ingestion
---------------------------------------------
9.1 Canonical Vulnerabilities Table
This is the single source of truth consumed by Phase 5.

```sql
CREATE TABLE tenant1.vulnerabilities (
    vuln_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,

    scanner_source TEXT NOT NULL,      -- web | api | sca | db
    vuln_type TEXT NOT NULL,            -- MUST map to remediation_rules.vuln_type

    schema_name TEXT,
    table_name TEXT,
    column_name TEXT,

    detected_at TIMESTAMPTZ DEFAULT now(),
    fingerprint TEXT NOT NULL,          -- deterministic deduplication

    severity TEXT CHECK (severity IN (
        'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    )),

    metadata JSONB DEFAULT '{}',

    CONSTRAINT unique_finding UNIQUE (tenant_id, fingerprint)
);
```

Important:
- No priorities here
- No business logic here
- This table is pure fact

SECTION 10 — Deterministic Normalization Layer
-----------------------------------------------
All scanners must map raw findings → canonical `vuln_type`.

10.1 Example Normalization Mapping

| Scanner Finding | Canonical `vuln_type` |
|---|---|
| Missing RLS Policy | RLS_BYPASS |
| PII exposed in `SELECT *` | WEAK_MASKING |
| Sequential Scan on Orders | PERFORMANCE_DEGRADATION |
| Audit partition gap | AUDIT_LOG_GAP |

This guarantees:
- Rule stability
- Auditability
- No scanner-specific chaos

SECTION 11 — Enforcement Engine (The Point of No Return)
--------------------------------------------------------
11.1 CI/CD Gate Function

```sql
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
```

11.2 CI/CD Usage (Hard Fail)

```sql
SELECT forgescan_security.block_if_critical_risk(
    'uuid-tenant-1',
    90
);
```

- ≥ 90 → Build fails
- No override
- No “accept risk” button
- Executives must fix root cause

SECTION 12 — Runtime Enforcement (Optional, Still Deterministic)
----------------------------------------------------------------
Used only for extreme cases.

```sql
CREATE OR REPLACE VIEW forgescan_security.runtime_blocklist AS
SELECT asset_name, vulnerability, priority_rank
FROM forgescan_security.generate_remediation_plan(current_setting('forgescan.tenant')::UUID)
WHERE priority_rank >= 120;
```

Used by:
- Connection poolers
- Feature flags
- Canary deploys

SECTION 13 — Ops & Audit Outputs
--------------------------------
13.1 Immutable Evidence Trail
Every enforcement decision is:
- Queryable
- Reproducible
- Math-backed

Auditors can run:

```sql
SELECT *
FROM forgescan_security.generate_remediation_plan('uuid-tenant-1')
ORDER BY priority_rank DESC;
```

No black boxes.
No ML explanations.
No hand-waving.

Phase 6 Outcome (Locked)
------------------------
Phase 6 enforces the deterministic decisions produced by Phases 2–5.

-- End of Phase 6 documentation
