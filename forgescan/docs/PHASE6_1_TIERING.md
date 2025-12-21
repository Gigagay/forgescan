# Phase 6.1 — Inclusive Tiering Without Dilution

Date: 2025-12-21

Goal
----
Capture solo developers and small startups without weakening ForgeScan’s deterministic, enterprise-grade core.

This is NOT a “cheap mode.” This is scope-aware enforcement: same math, same rules, different thresholds and scopes.

Core idea
---------
- Use the same Phase 5 DPL engine and remediation rules.
- Add an `operational_tier` to business assets/tenants.
- Enforcement gates adapt thresholds based on tier to reduce noise for small teams while preserving strict enforcement for enterprise.

Principles
----------
- Inclusivity through determinism, not features.
- No new scanners, no new rules, no AI.
- Reduced obligation surface: fewer blocking triggers for small teams, but still block existential/compliance-critical risks.

Operational Tier
----------------
Add an `operational_tier` to `forgescan_security.business_assets` (or `tenant_registry`) with values:
- `SOLO`
- `STARTUP` (default)
- `GROWTH`
- `ENTERPRISE`

SQL (schema change):

```sql
ALTER TABLE forgescan_security.business_assets
ADD COLUMN operational_tier TEXT
CHECK (operational_tier IN ('SOLO', 'STARTUP', 'GROWTH', 'ENTERPRISE'))
DEFAULT 'STARTUP';
```

Enforcement Threshold Matrix
----------------------------
| Tier | Priority Block Threshold | Enforcement Style |
|---|---:|---|
| SOLO | ≥ 120 | Hard block only on existential risks |
| STARTUP | ≥ 100 | Block revenue & compliance killers |
| GROWTH | ≥ 90 | Block most high-impact issues |
| ENTERPRISE | ≥ 80 | Zero tolerance |

Key insight:
- Solo dev with one production DB is not blocked for minor performance degradation or non-critical audit gaps.
- But they are blocked for PCI exposure, RLS bypass on revenue data, plaintext credentials, etc.

Tier-aware Gate Function
------------------------
The gate evaluates the tenant's operational tier and applies the threshold accordingly.

```sql
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
```

Usage
-----
- CI: call `forgescan_security.enforce_by_tier(tenant_id)` as part of pre-deploy checks.
- No overrides or "accept risk" buttons.
- Tenant admin can change `operational_tier` in `tenant_registry` to match risk appetite.

Example GitHub Actions snippet (CI integration)
----------------------------------------------
```yaml
- name: ForgeScan enforcement
  run: |
    psql "$DATABASE_URL" -c "SELECT forgescan_security.enforce_by_tier('$TENANT_ID');"
  env:
    DATABASE_URL: ${{ secrets.DATABASE_URL }}
```

Migration notes
---------------
- Default is `STARTUP` for backward compatibility.
- Consider a one-time migration to set `operational_tier` in `tenant_registry` based on account type.
- Ensure `tenant_registry` and `business_assets` are consistent: enforcement reads tier from `tenant_registry`.

Testing recommendations
-----------------------
- Unit test `enforce_by_tier()` by creating synthetic remediation plan results (mock `generate_remediation_plan()` or insert findings/business assets with known priorities).
- Integration test CI flow calling `enforce_by_tier()` with tenants in each tier.

Why this works
---------------
- Same deterministic rules ensure auditability and no surprise behavior.
- Different thresholds reduce noise for small teams while preserving strict enforcement for enterprise clients.
- Operational tier is an administrative knob, not a change in vulnerability semantics.

-- End of Phase 6.1 Documentation
