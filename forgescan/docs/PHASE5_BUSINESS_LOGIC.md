# ForgeScan 2.0 Phase 5: Business Logic Layer

## Overview

Phase 5 integrates business context into the vulnerability prioritization pipeline. Instead of treating all RLS bypasses as equal (dangerous!), the system now:

1. **Tags assets** with financial/compliance context (asset_type, data_sensitivity, downtime_cost_per_hour, compliance_frameworks)
2. **Applies deterministic rules** that map vulnerability type + context → priority + remediation action
3. **Calculates priorities** using the formula: `priority = base_score + revenue_bonus + compliance_bonus + exposure_multiplier`
4. **Generates remediation plans** sorted by business impact (highest risk first)

## Architecture

```
Scanner Output (CRITICAL RLS_BYPASS)
    ↓
[Business Asset Lookup]  ← Query: Is this on REVENUE or COMPLIANCE asset?
    ↓                      Is this PCI/PII/PHI data?
[Remediation Rules]      ← Lookup: RLS_BYPASS on PCI asset = priority 150 (100 base + 20 revenue + 30 PCI)
    ↓
[Priority Calculation]   ← Formula: base + revenue_bonus + compliance_bonus
    ↓
[Remediation Plan]       ← Output: Sorted by priority DESC + SLA, compliance obligations, financial risk
    ↓
API Response + Dashboard
```

## Key Concepts

### Asset Tagging (CRITICAL!)

Every database table should be tagged BEFORE scanning:

```python
POST /api/v1/remediation/assets/tag
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "schema_name": "public",
  "table_name": "orders",
  "asset_type": "REVENUE",           # REVENUE | COMPLIANCE | OPERATIONAL | ANALYTICS | ARCHIVE
  "data_sensitivity": "PCI",         # PUBLIC | INTERNAL | PII | PCI | PHI
  "downtime_cost_per_hour": 50000,   # USD/hour if table is down
  "compliance_frameworks": ["PCI-DSS", "GDPR"]
}
```

**Why this matters:**
- Without tagging, all vulnerabilities get equal priority (WRONG)
- With tagging, system knows PCI breach on payment table = $500K GDPR fine + $50K/hr downtime
- This enables **deterministic prioritization** (math, not guessing)

### Deterministic Remediation Rules

13 rules map vulnerability type + context:

| Vulnerability | Context | Base Priority | Revenue Bonus | Compliance Bonus | Severity | SLA |
|---|---|---|---|---|---|---|
| RLS_BYPASS | PCI data | 100 | +20 | +30 | CRITICAL | 1 hour |
| RLS_BYPASS | PII data | 100 | +20 | +25 | CRITICAL | 1 hour |
| WEAK_MASKING | PHI data | 90 | 0 | +35 | HIGH | 4 hours |
| WEAK_MASKING | PCI data | 90 | 0 | +30 | HIGH | 4 hours |
| PERFORMANCE_DEGRADATION | REVENUE asset | 70 | +20 | 0 | MEDIUM | 24 hours |
| AUDIT_LOG_GAP | Any | 110 | +10 | +20 | CRITICAL | 2 hours |
| ... (7 more rules) | | | | | | |

**Fetch rules:**
```bash
GET /api/v1/remediation/rules
GET /api/v1/remediation/rules?vuln_type=RLS_BYPASS
```

### Priority Calculation

```
priority_rank = base_priority_score
              + revenue_bonus (if asset_type == REVENUE)
              + compliance_bonus (if data_sensitivity == PCI|PII|PHI)
              + exposure_multiplier (if many records exposed)
```

**Example:**
- RLS_BYPASS on payment table (REVENUE + PCI): 100 + 20 + 30 = **150** (CRITICAL)
- PERFORMANCE_DEGRADATION on analytics table (ANALYTICS + INTERNAL): 70 + 0 + 0 = **70** (MEDIUM)

### Compliance Fine Estimation

Calculate potential regulatory fines for different scenarios:

```bash
GET /api/v1/remediation/estimate-fine?data_sensitivity=PCI&max_records=500000&frameworks=GDPR,PCI-DSS

Response:
{
  "fines": [
    {"framework": "GDPR", "max_fine_usd": 25000000, "estimated_fine_usd": 2500000},
    {"framework": "PCI-DSS", "max_fine_usd": 600000, "estimated_fine_usd": 500000}
  ],
  "total_fine_usd": 3000000
}
```

**Statutory Maximums:**
- GDPR: 4% annual revenue or €20M (~$25M)
- CCPA: 2.5% annual revenue or $7.5M
- HIPAA: $1.5M+ per incident
- PCI-DSS: $600K (not strict %)
- SOC2/NIST/ISO27001: Reputational damage, but not statutory

## API Endpoints

### 1. Generate Remediation Plan

```bash
GET /api/v1/remediation/plans/{tenant_id}

Response:
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "plan": [
    {
      "priority_rank": 150,
      "asset_name": "public.orders",
      "asset_type": "REVENUE",
      "data_sensitivity": "PCI",
      "vulnerability": "RLS_BYPASS",
      "business_impact": "Direct impact to payment processing. $50,000/hr downtime cost.",
      "financial_risk": "CRITICAL: REVENUE LOSS + $2.5M GDPR fine",
      "compliance_obligations": "PCI-DSS (critical), GDPR (4% revenue)",
      "downtime_cost_per_hour": 50000,
      "required_action": "Immediate RLS enforcement and full audit",
      "remediation_command": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;",
      "mitigation_sla_hours": 1,
      "severity": "CRITICAL"
    },
    { ... }
  ],
  "count": 23
}
```

**Workflow:**
1. Call this after every scan to get prioritized list
2. Use `mitigation_sla_hours` to track deadline
3. Use `remediation_command` as basis for remediation script

### 2. Get High-Level Summary

```bash
GET /api/v1/remediation/summary/{tenant_id}

Response:
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "summary": {
    "total_findings": 23,
    "critical_count": 3,
    "high_count": 8,
    "medium_count": 10,
    "low_count": 2,
    "total_assets": 45
  },
  "risk": {
    "total_downtime_risk_usd_1hr": 150000,
    "estimated_compliance_fines_usd": {
      "PCI-DSS": 500000,
      "GDPR": 1000000
    }
  },
  "critical_remediations": [ ... ],
  "asset_summary": {
    "revenue_assets": 15,
    "pci_assets": 8,
    "compliance_assets": 12
  }
}
```

**For Dashboard:**
- Display `total_downtime_risk_usd_1hr` prominently (executive dashboard)
- Show `critical_count` to track progress
- Alert on compliance fines >$500K

### 3. List Business Assets

```bash
GET /api/v1/remediation/assets?tenant_id={uuid}&asset_type=REVENUE&data_sensitivity=PCI

Response:
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "assets": [
    {
      "asset_id": "550e8400-e29b-41d4-a716-446655440001",
      "schema_name": "public",
      "table_name": "orders",
      "asset_type": "REVENUE",
      "data_sensitivity": "PCI",
      "downtime_cost_per_hour": 50000,
      "max_exposure_records": 5000000,
      "criticality_score": 95,
      "compliance_frameworks": ["PCI-DSS", "GDPR"],
      "data_owner": "payments-team@company.com",
      "description": "Production payment processing. Primary revenue stream."
    }
  ],
  "count": 1
}
```

### 4. Tag Business Asset (CRITICAL!)

```bash
POST /api/v1/remediation/assets/tag

Request:
{
  "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
  "schema_name": "public",
  "table_name": "orders",
  "asset_type": "REVENUE",
  "data_sensitivity": "PCI",
  "downtime_cost_per_hour": 50000,
  "compliance_frameworks": ["PCI-DSS", "GDPR"]
}

Response:
{
  "asset_id": "550e8400-e29b-41d4-a716-446655440001",
  "message": "Asset public.orders tagged successfully"
}
```

### 5. Estimate Compliance Fines

```bash
GET /api/v1/remediation/estimate-fine?data_sensitivity=PCI&max_records=500000&frameworks=GDPR,PCI-DSS

Response:
{
  "exposure": {
    "data_sensitivity": "PCI",
    "estimated_records_exposed": 500000
  },
  "fines": [
    {
      "framework": "PCI-DSS",
      "max_fine_usd": 600000,
      "estimated_fine_usd": 500000
    },
    {
      "framework": "GDPR",
      "max_fine_usd": 25000000,
      "estimated_fine_usd": 2500000
    }
  ],
  "total_fine_usd": 3000000
}
```

### 6. Get Remediation Rules

```bash
GET /api/v1/remediation/rules
GET /api/v1/remediation/rules?vuln_type=RLS_BYPASS

Response:
{
  "rules": [
    {
      "rule_id": "550e8400-e29b-41d4-a716-446655440002",
      "vuln_type": "RLS_BYPASS",
      "context_trigger": "RLS detection on PCI data",
      "base_priority_score": 100,
      "revenue_bonus": 20,
      "compliance_bonus": 30,
      "required_action": "Immediate RLS Enforcement & Audit Review",
      "severity_label": "CRITICAL",
      "mitigation_time_hours": 1
    }
  ],
  "count": 13
}
```

## Python Integration

### Evaluator Usage

```python
from app.remediation.business_evaluator import BusinessLogicEvaluator

evaluator = BusinessLogicEvaluator(db_session)

# 1. Tag an asset
asset_id = await evaluator.tag_asset(
    tenant_id=tenant_uuid,
    schema_name="public",
    table_name="orders",
    asset_type=AssetType.REVENUE,
    data_sensitivity=DataSensitivity.PCI,
    downtime_cost_per_hour=50000,
    compliance_frameworks=["PCI-DSS", "GDPR"],
)

# 2. Get remediation plan
plan = await evaluator.generate_remediation_plan(tenant_uuid)
for item in plan:
    print(f"Priority {item['priority_rank']}: {item['vulnerability']} on {item['asset_name']}")

# 3. Estimate fines
fines = await evaluator.estimate_compliance_fines(
    data_sensitivity="PCI",
    max_records=500000,
    frameworks=["GDPR", "PCI-DSS"],
)

# 4. Get rules
rules = await evaluator.get_remediation_rules(vuln_type="RLS_BYPASS")
```

## Database Schema

### business_assets Table

```sql
CREATE TABLE forgescan_security.business_assets (
    asset_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL,
    schema_name TEXT NOT NULL,
    table_name TEXT NOT NULL,
    asset_type TEXT CHECK (asset_type IN ('REVENUE', 'COMPLIANCE', 'OPERATIONAL', 'ANALYTICS', 'ARCHIVE')),
    data_sensitivity TEXT CHECK (data_sensitivity IN ('PUBLIC', 'INTERNAL', 'PII', 'PCI', 'PHI')),
    downtime_cost_per_hour INT NOT NULL,
    max_exposure_records INT,
    criticality_score INT DEFAULT 50,
    compliance_frameworks TEXT[] DEFAULT '{}',
    data_owner TEXT,
    description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### remediation_rules Table

```sql
CREATE TABLE forgescan_security.remediation_rules (
    rule_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vuln_type TEXT NOT NULL,
    context_trigger TEXT,
    base_priority_score INT NOT NULL,
    revenue_bonus INT DEFAULT 0,
    compliance_bonus INT DEFAULT 0,
    required_action TEXT,
    severity_label TEXT,
    mitigation_time_hours INT,
    UNIQUE(vuln_type, context_trigger)
);
```

### compliance_frameworks Table

```sql
CREATE TABLE forgescan_security.compliance_frameworks (
    framework_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    framework_name TEXT UNIQUE,
    max_fine_percent_revenue DECIMAL(5, 2),
    fine_per_record_usd DECIMAL(10, 2),
    max_fine_usd DECIMAL(15, 2),
    jurisdiction TEXT
);
```

## Testing

Run integration tests:

```bash
pytest backend/tests/test_business_logic.py -v

# Specific test
pytest backend/tests/test_business_logic.py::TestBusinessLogicLayer::test_priority_formula_rls_bypass_on_pci_revenue -v
```

**Test Coverage:**
- Asset tagging (REVENUE, COMPLIANCE, REVENUE+PCI, COMPLIANCE+PHI)
- Rule fetching (all rules, filtered by vuln_type)
- Priority calculation (formula validation)
- Compliance fines (GDPR, HIPAA, CCPA, PCI-DSS)
- Remediation plan generation (sorting, required fields)
- Summary generation (counts, risk exposure)

## Deployment Checklist

- [ ] Run `backend/security/setup_phase4_v2.sql` to create all tables + functions
- [ ] Run `backend/tests/test_business_logic.py` to verify database integration
- [ ] Tag all customer assets via `POST /api/v1/remediation/assets/tag`
- [ ] Verify remediation plan via `GET /api/v1/remediation/plans/{tenant_id}`
- [ ] Update dashboard to display `total_downtime_risk_usd_1hr`
- [ ] Alert on compliance fines >$500K

## Performance Considerations

**O(1) Operations:**
- Asset lookup (indexed by tenant_id + table_name)
- Rule lookup (indexed by vuln_type)
- Priority calculation (deterministic formula, no loops)

**O(N) Operations:**
- Remediation plan generation (JOIN findings + assets + rules, sorts by priority)
- Summary generation (aggregate counts by severity)

**Optimization:**
- Cache remediation rules in memory (13 rules, reload daily)
- Use materialized view for business_assets (refresh hourly)
- Index on findings(tenant_id, scanner, rule_id) for fast lookup

## Related Documentation

- [API.md](../docs/API.md) - Full API reference
- [DEPLOYMENT.md](../docs/DEPLOYMENT.md) - Production deployment
- [Phase 1-4 Documentation](../docs/) - Scanner, parser, RLS, audit logging

## Example End-to-End Workflow

```bash
# 1. Admin tags assets (one-time setup per tenant)
POST /api/v1/remediation/assets/tag
{
  "schema_name": "public",
  "table_name": "orders",
  "asset_type": "REVENUE",
  "data_sensitivity": "PCI",
  "downtime_cost_per_hour": 50000,
  "compliance_frameworks": ["PCI-DSS", "GDPR"]
}

# 2. Security team runs scan
POST /api/v1/scans
{
  "tenant_id": "...",
  "scanner_type": "bandit",
  "repository_url": "https://..."
}

# 3. System generates remediation plan
GET /api/v1/remediation/plans/{tenant_id}
# Returns: 3 CRITICAL findings (RLS_BYPASS) with priority 150+

# 4. Dashboard displays risk
GET /api/v1/remediation/summary/{tenant_id}
# Shows: $150K downtime risk + $2.5M GDPR fine if not fixed in 1 hour

# 5. Team implements remediation
# Using remediation_command from plan as template

# 6. Compliance reports compliance exposure
GET /api/v1/remediation/estimate-fine?...
# Shows: GDPR liability, SLA tracking, audit evidence
```

## Key Takeaways

1. **Asset tagging is critical** - Without it, you're flying blind
2. **Deterministic, not AI** - Rules are explicit, auditable, consistent
3. **Business impact first** - Priorities based on financial risk + compliance, not just CVSS
4. **Compliance-aware** - GDPR, HIPAA, PCI-DSS fines baked into priority calculation
5. **Actionable remediation** - Each finding includes SLA, required action, remediation command
