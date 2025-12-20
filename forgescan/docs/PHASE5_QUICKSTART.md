# Phase 5: Quick Start Guide

## 5-Minute Setup

### 1. Database Setup
```bash
# Run in PostgreSQL container (one-time)
psql -U postgres -d forgescan < backend/security/setup_phase4_v2.sql

# Verify tables created
SELECT COUNT(*) FROM forgescan_security.remediation_rules;
-- Should return: 13
```

### 2. Start Application
```bash
cd backend
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

### 3. Test Endpoints
```bash
# Health check
curl http://localhost:8000/health

# Get all remediation rules
curl http://localhost:8000/api/v1/remediation/rules

# Should return 13 rules with RLS_BYPASS, WEAK_MASKING, etc.
```

## Typical Workflow

### Step 1: Tag Your Assets (One-Time Setup)

```bash
TENANT_ID="550e8400-e29b-41d4-a716-446655440000"

# Tag payment table as HIGH VALUE
curl -X POST http://localhost:8000/api/v1/remediation/assets/tag \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "schema_name": "public",
    "table_name": "orders",
    "asset_type": "REVENUE",
    "data_sensitivity": "PCI",
    "downtime_cost_per_hour": 50000,
    "compliance_frameworks": ["PCI-DSS", "GDPR"]
  }'

# Tag user table
curl -X POST http://localhost:8000/api/v1/remediation/assets/tag \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "schema_name": "public",
    "table_name": "users",
    "asset_type": "OPERATIONAL",
    "data_sensitivity": "PII",
    "downtime_cost_per_hour": 10000,
    "compliance_frameworks": ["GDPR"]
  }'

# Tag internal logs (low risk)
curl -X POST http://localhost:8000/api/v1/remediation/assets/tag \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "schema_name": "public",
    "table_name": "audit_logs",
    "asset_type": "COMPLIANCE",
    "data_sensitivity": "INTERNAL",
    "downtime_cost_per_hour": 1000,
    "compliance_frameworks": ["SOC2"]
  }'
```

### Step 2: View Your Assets

```bash
TENANT_ID="550e8400-e29b-41d4-a716-446655440000"

curl "http://localhost:8000/api/v1/remediation/assets?tenant_id=$TENANT_ID"

# Response:
# {
#   "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
#   "assets": [
#     {
#       "asset_id": "...",
#       "schema_name": "public",
#       "table_name": "orders",
#       "asset_type": "REVENUE",
#       "data_sensitivity": "PCI",
#       "downtime_cost_per_hour": 50000,
#       "compliance_frameworks": ["PCI-DSS", "GDPR"]
#     },
#     ...
#   ],
#   "count": 3
# }
```

### Step 3: Run a Security Scan

```bash
TENANT_ID="550e8400-e29b-41d4-a716-446655440000"

# Via existing scanner API (Phase 1-2)
curl -X POST http://localhost:8000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "'$TENANT_ID'",
    "scanner_type": "bandit",
    "repository_url": "https://github.com/example/repo.git"
  }'

# This creates findings in the database
# Example: RLS_BYPASS detected in public.orders
```

### Step 4: Get Remediation Plan

```bash
TENANT_ID="550e8400-e29b-41d4-a716-446655440000"

# Get prioritized remediation plan
curl "http://localhost:8000/api/v1/remediation/plans/$TENANT_ID"

# Response:
# {
#   "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
#   "plan": [
#     {
#       "priority_rank": 150,          # CRITICAL
#       "asset_name": "public.orders",
#       "asset_type": "REVENUE",
#       "data_sensitivity": "PCI",
#       "vulnerability": "RLS_BYPASS",
#       "business_impact": "Direct impact to payment processing. $50,000/hr downtime cost.",
#       "financial_risk": "CRITICAL: REVENUE LOSS + GDPR fine $2.5M",
#       "compliance_obligations": "PCI-DSS, GDPR",
#       "downtime_cost_per_hour": 50000,
#       "required_action": "Immediate RLS enforcement and full audit",
#       "remediation_command": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;",
#       "mitigation_sla_hours": 1,
#       "severity": "CRITICAL"
#     },
#     {
#       "priority_rank": 95,           # MEDIUM
#       "asset_name": "public.users",
#       "asset_type": "OPERATIONAL",
#       "data_sensitivity": "PII",
#       "vulnerability": "WEAK_MASKING",
#       "business_impact": "Risk to user privacy. $10,000/hr downtime cost.",
#       "financial_risk": "HIGH: GDPR fine $500K-$1M",
#       "compliance_obligations": "GDPR",
#       "downtime_cost_per_hour": 10000,
#       "required_action": "Implement dynamic column masking",
#       "remediation_command": "CREATE MASKED VIEW users_masked AS SELECT ...",
#       "mitigation_sla_hours": 4,
#       "severity": "HIGH"
#     }
#   ],
#   "count": 2
# }
```

**Key Insight:** 
- RLS_BYPASS on **orders** (REVENUE+PCI) = **150** (CRITICAL, 1hr SLA)
- RLS_BYPASS on **users** (OPERATIONAL+PII) = **95** (HIGH, 4hr SLA)
- Same vulnerability, different priority based on **business context**

### Step 5: Get Executive Dashboard

```bash
TENANT_ID="550e8400-e29b-41d4-a716-446655440000"

curl "http://localhost:8000/api/v1/remediation/summary/$TENANT_ID"

# Response:
# {
#   "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
#   "summary": {
#     "total_findings": 2,
#     "critical_count": 1,
#     "high_count": 1,
#     "medium_count": 0,
#     "low_count": 0,
#     "total_assets": 3
#   },
#   "risk": {
#     "total_downtime_risk_usd_1hr": 60000,      # All CRITICAL items if down 1 hour
#     "estimated_compliance_fines_usd": {
#       "PCI-DSS": 500000,
#       "GDPR": 2500000
#     }
#   },
#   "critical_remediations": [ ... ],
#   "asset_summary": {
#     "revenue_assets": 1,
#     "pci_assets": 1,
#     "compliance_assets": 1
#   }
# }
```

**For Executive Reports:**
- Total risk exposure: **$60,000/hour** (downtime)
- Compliance fines: **$3M+** (GDPR + PCI-DSS)
- Critical findings: **1** (must fix in 1 hour)

### Step 6: Estimate Regulatory Impact

```bash
# If all PCI data was breached
curl "http://localhost:8000/api/v1/remediation/estimate-fine?data_sensitivity=PCI&max_records=5000000&frameworks=GDPR,PCI-DSS,CCPA"

# Response:
# {
#   "exposure": {
#     "data_sensitivity": "PCI",
#     "estimated_records_exposed": 5000000
#   },
#   "fines": [
#     {
#       "framework": "GDPR",
#       "max_fine_usd": 25000000,
#       "estimated_fine_usd": 2500000
#     },
#     {
#       "framework": "PCI-DSS",
#       "max_fine_usd": 600000,
#       "estimated_fine_usd": 500000
#     },
#     {
#       "framework": "CCPA",
#       "max_fine_usd": 7500000,
#       "estimated_fine_usd": 1250000
#     }
#   ],
#   "total_fine_usd": 4250000
# }
```

## Common Use Cases

### Case 1: CEO Asks "What's Our Risk?"

```bash
curl http://localhost:8000/api/v1/remediation/summary/{tenant_id}

# Key metric: total_downtime_risk_usd_1hr + estimated_compliance_fines_usd
# Answer: "We have $60K/hour downtime risk + $3M compliance liability"
```

### Case 2: Security Team Reviews High-Priority Findings

```bash
curl http://localhost:8000/api/v1/remediation/plans/{tenant_id}

# Filter response for severity=CRITICAL or priority_rank > 100
# Use remediation_command as implementation guide
# Track mitigation_sla_hours for deadline
```

### Case 3: Compliance Officer Needs Audit Trail

```bash
# Query audit logs (Phase 4 RLS)
SELECT * FROM audit_log 
WHERE operation = 'TAG_BUSINESS_ASSET'
ORDER BY event_timestamp DESC;

# Shows:
# - Which assets were tagged
# - When they were tagged
# - By whom
# - Changes to compliance frameworks
```

### Case 4: New Database Table Added

```bash
# 1. Tag the asset
POST /api/v1/remediation/assets/tag

# 2. Next scan automatically includes it in remediation plan
# Priority calculated based on asset_type + data_sensitivity
```

### Case 5: Data Sensitivity Changes

```bash
# Customer reports: "table X now contains PHI"

# Solution:
curl -X POST http://localhost:8000/api/v1/remediation/assets/tag \
  -d '{
    "table_name": "X",
    "data_sensitivity": "PHI",  # Updated!
    ...
  }'

# Next plan generation immediately increases priority for any findings on table X
# Because: compliance_bonus for PHI is +35
```

## Integration with Existing Tools

### With Jenkins/GitHub Actions

```yaml
# .github/workflows/security.yml
- name: Run ForgeScan
  run: |
    curl -X POST http://forgescan.internal/api/v1/scans \
      -d "scanner_type=bandit&repository_url=${{ github.repository }}"

- name: Get Remediation Plan
  run: |
    FINDINGS=$(curl http://forgescan.internal/api/v1/remediation/plans/$TENANT_ID)
    CRITICAL=$(echo $FINDINGS | jq '.plan[] | select(.severity=="CRITICAL")')
    
    if [ ! -z "$CRITICAL" ]; then
      echo "⚠️ Critical findings detected!"
      exit 1
    fi
```

### With Slack

```bash
# Send daily summary to #security channel
curl -X POST https://hooks.slack.com/services/... \
  -d '{
    "text": "Security Summary",
    "blocks": [
      {
        "text": "Critical Findings: 1, High: 3, Medium: 5",
      },
      {
        "text": "Downtime Risk: $60K/hr, Compliance Liability: $3M"
      }
    ]
  }'
```

### With Jira

```bash
# Auto-create Jira tickets for critical findings
PLAN=$(curl http://localhost:8000/api/v1/remediation/plans/$TENANT_ID)

echo $PLAN | jq '.plan[] | select(.severity=="CRITICAL")' | while read item; do
  curl -X POST https://jira.company.com/rest/api/2/issue \
    -d '{
      "fields": {
        "project": {"key": "SECURITY"},
        "summary": "Fix RLS bypass in public.orders",
        "description": "'$(echo $item | jq '.remediation_command')'",
        "issuetype": {"name": "Bug"},
        "priority": {"name": "Critical"}
      }
    }'
done
```

## Troubleshooting

### Issue: No remediation plan returned

**Check:**
1. Have you tagged any assets?
   ```bash
   curl http://localhost:8000/api/v1/remediation/assets?tenant_id={id}
   ```
2. Have you run any scans?
   ```bash
   curl http://localhost:8000/api/v1/scans?tenant_id={id}
   ```
3. Are there any findings?
   ```bash
   curl http://localhost:8000/api/v1/findings?tenant_id={id}
   ```

### Issue: Priority doesn't match expected value

**Verify:**
1. Asset tags are correct (check data_sensitivity, asset_type)
2. Remediation rule exists
   ```bash
   curl http://localhost:8000/api/v1/remediation/rules?vuln_type=RLS_BYPASS
   ```
3. Formula: base (100) + revenue_bonus (20) + compliance_bonus (30) = 150

### Issue: Compliance fines seem wrong

**Check:**
1. Max records value is reasonable (compare to actual data size)
2. Frameworks match your company's obligations
3. Currency conversion (GDPR is in EUR, convert to USD)

## Testing

```bash
# Run all Phase 5 tests
pytest backend/tests/test_business_logic.py -v

# Specific test
pytest backend/tests/test_business_logic.py::TestBusinessLogicLayer::test_priority_formula_rls_bypass_on_pci_revenue -v

# Coverage report
pytest backend/tests/test_business_logic.py --cov=app.remediation.business_evaluator
```

## Key Takeaways

1. **Tag first, scan later** - Asset context drives priorities
2. **Priority = context** - Same finding, different assets = different priorities
3. **Use remediation_command** - It's ready-to-run SQL/code
4. **Track SLAs** - mitigation_sla_hours is your deadline
5. **Monitor financial impact** - total_downtime_risk_usd_1hr is real money at risk

---

**Next Step**: [Read Full Documentation](PHASE5_BUSINESS_LOGIC.md)
