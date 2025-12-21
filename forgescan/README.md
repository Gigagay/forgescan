# ForgeScan 2.0

ForgeScan is a production-grade, deterministic security scanning and enforcement platform. It detects vulnerabilities, prioritizes them by business impact, enforces remediation through CI/CD gates, and maintains immutable audit trails for compliance.

**Core Value Proposition**: Security findings only matter if they stop bad outcomes. ForgeScan transforms detections into deterministic business decisions that are non-negotiable, auditable, and AI-safe.

## Technology Stack

- **Backend**: FastAPI (async) + SQLAlchemy (async) + Alembic migrations
- **Database**: PostgreSQL 15 (pgcrypto, bloom filters, partitioning, RLS)
- **Broker & Cache**: Redis (Celery broker, worker state)
- **Background Workers**: Celery for async task processing
- **Frontend**: Vite + React (TypeScript)
- **Scanning**: Go scanner-runner with Docker client integration
- **Orchestration**: Docker Compose (postgres, redis, backend, worker, frontend, scanner-runner)

## Architecture: 8 Phases of Security Maturity

ForgeScan evolves through 8 deterministic phases, each building on the previous. Every phase is locked in—no overrides, no exceptions.

### Phase 1-4: Foundation (Detection & Audit)
- **Phase 1**: Scanner infrastructure & Go runner
- **Phase 2**: Parser ecosystem (Bandit, Semgrep, etc.)
- **Phase 3**: Canonical vulnerability normalization
- **Phase 4**: Immutable audit logging & RLS enforcement

### Phase 5: Business Logic (Prioritization)
**File**: [docs/PHASE5_BUSINESS_LOGIC.md](docs/PHASE5_BUSINESS_LOGIC.md)

Transforms raw detections into business-impact scores using deterministic formula:
```
priority = base_score + revenue_bonus + compliance_bonus + exposure_multiplier
```

**Example**: RLS_BYPASS (base 100) + REVENUE asset (×1.2) + PCI compliance (×1.3) = **156 (CRITICAL)**

**Components**:
- `backend/app/remediation/business_evaluator.py` (380 lines) - Priority calculation, compliance fines, asset tagging
- `backend/security/business_logic.sql` (450 lines) - Canonical tables, remediation rules
- `backend/tests/test_business_logic.py` (400 lines) - Priority formula validation

### Phase 6: Enforcement Engine (Canonical Ingestion & Gating)
**File**: [docs/PHASE6_ENFORCEMENT.md](docs/PHASE6_ENFORCEMENT.md)

Normalizes scanner output to canonical format, establishes enforcement boundaries:
- Scanner output → Canonical table (normalized fact)
- Canonical table → DPL engine → Priority score
- Priority score → Enforcement decision (block/allow)

**Components**:
- `backend/security/phase6_enforcement.sql` (280 lines) - Canonical vulnerabilities, normalization
- Enforcement function that determines if deployment should be blocked

### Phase 6.1: Inclusive Tiering (Scope-Aware Enforcement)
**File**: [docs/PHASE6_1_TIERING.md](docs/PHASE6_1_TIERING.md)

Tier-based enforcement thresholds—same math, different limits:
- **SOLO**: ≥120 priority (stricter for startups, fair access to enforcement)
- **STARTUP**: ≥100 priority
- **GROWTH**: ≥90 priority
- **ENTERPRISE**: ≥80 priority

**Philosophy**: Free users get real enforcement, just rate-limited. Not crippled.

### Phase 7: CI/CD Enforcement & Monetization
**File**: [docs/PHASE7_ENFORCEMENT.md](docs/PHASE7_ENFORCEMENT.md)

Non-negotiable enforcement gates with immutable audit trail and quota system:

**Enforcement Bands**:
| Priority | Band | Behavior |
|----------|------|----------|
| ≥100 | HARD_FAIL | Block CI/CD (no deploy) |
| 80-99 | SOFT_FAIL | Allow + require acknowledgement |
| 60-79 | WARN | Logged, visible in dashboard |
| <60 | INFO | No enforcement |

**Components**:
- `backend/security/phase7_enforcement_rules.sql` (300+ lines) - Gate function, decision trail, quotas
- `backend/app/services/enforcement_service.py` (300+ lines) - Service layer
- `backend/app/api/v1/enforcement.py` (400+ lines) - 5 endpoints: gate, history, quota, acknowledge, decision lookup
- `backend/tests/test_enforcement.py` (350+ lines) - Gate validation, audit trail, quota tests

**API Endpoints**:
```
GET  /api/v1/enforce/gate              - Check if deployment allowed
GET  /api/v1/enforce/history           - Audit trail of gate decisions
GET  /api/v1/enforce/quota             - Monthly quota usage
POST /api/v1/enforce/acknowledge       - Acknowledge soft fail
GET  /api/v1/enforce/decision/{id}     - Look up specific decision
```

### Phase 8: Trust, Observability & AI-Readiness
**File**: [docs/PHASE8_TRUST_OBSERVABILITY.md](docs/PHASE8_TRUST_OBSERVABILITY.md)

Immutable evidence ledger, business metrics, and AI-safe architectural boundary.

**Core Principle**: Every important event is logged once, hashed (SHA256), and queryable. AI can read and enhance but never override.

**Evidence Types**:
- **SCAN**: What was tested? (scanner confidence, CWE IDs)
- **ENFORCEMENT**: Why was it blocked? (priority score, financial risk)
- **REMEDIATION**: What was fixed? (SLA met/missed, recurrence)
- **CI_DECISION**: What did the gate say? (decision, timestamp)

**Business Metrics**:
- **Revenue at Risk**: Sum of downtime costs for unresolved CRITICAL/HIGH vulns ($/hour)
- **Compliance Exposure**: Frameworks at risk × total records exposed
- **SLA Performance**: % of remediations completed on-time + MTTR
- **Enforcement Effectiveness**: Block rate, soft-fail ack rate, gate quality

**AI-Safe Boundary**:
```
┌─────────────────────────────────────────┐
│  ForgeScan Core (Deterministic)         │
│  Phases 2-7: Detection → Enforcement    │
│  Output: BLOCK or ALLOW (immutable)     │
└─────────────────────────────────────────┘
             ↓ (can't be changed)
┌─────────────────────────────────────────┐
│  Optional AI Layer (Read-Only)          │
│  - Reword explanations                  │
│  - Add context from company knowledge   │
│  - Suggest alternatives                 │
│  CANNOT: Override decision, change      │
│          priority, recommend allow      │
└─────────────────────────────────────────┘
```

**Components**:
- `backend/security/phase8_observability.sql` (330 lines) - Evidence ledger, remediation effectiveness, 4 metrics views
- `backend/app/services/evidence_service.py` (350 lines) - Evidence logging, integrity verification, audit exports
- `backend/app/services/remediation_effectiveness.py` (350 lines) - SLA tracking, recurrence detection
- `backend/app/api/v1/evidence.py` (300+ lines) - 5 endpoints for evidence queries, hash verification, timeline reconstruction
- `backend/app/api/v1/metrics.py` (300+ lines) - 5 endpoints for business metrics

**API Endpoints**:
```
GET  /api/v1/evidence                       - Query immutable ledger
POST /api/v1/evidence/{id}/verify          - Verify integrity (SHA256)
GET  /api/v1/evidence/entity/{entity_id}   - Reconstruct entity timeline
GET  /api/v1/evidence/export/audit-trail   - Compliance export (date range)
GET  /api/v1/evidence/stats                - Summary statistics

GET  /api/v1/metrics/revenue-at-risk       - Financial impact ($/hour)
GET  /api/v1/metrics/compliance-exposure   - Frameworks × records
GET  /api/v1/metrics/sla-performance       - On-time %, MTTR, recurring
GET  /api/v1/metrics/enforcement-effectiveness - Block rate, ack rate
GET  /api/v1/metrics/dashboard             - Executive consolidated view
```

---

## Quick Start
1. Prereqs
   - Docker Desktop (Windows) OR Python 3.11+, Node 18+, Git.
2. Build & run (recommended)
   - From repo root:
     powershell
     docker-compose -f forgescan/docker-compose.yml up -d --build
   - View logs:
     docker-compose -f forgescan/docker-compose.yml logs -f backend
3. Backend local (no Docker)
   powershell
   cd backend
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   Set env vars (see backend/.env.example) and run:
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

## Documentation by Phase

| Phase | Title | File | Purpose |
|-------|-------|------|---------|
| 1-4 | Foundation | [docs/](docs/) | Detection, parsing, normalization, audit logging |
| 5 | Business Logic | [docs/PHASE5_BUSINESS_LOGIC.md](docs/PHASE5_BUSINESS_LOGIC.md) | Deterministic prioritization formula |
| 6 | Enforcement Engine | [docs/PHASE6_ENFORCEMENT.md](docs/PHASE6_ENFORCEMENT.md) | Canonical ingestion, enforcement boundaries |
| 6.1 | Inclusive Tiering | [docs/PHASE6_1_TIERING.md](docs/PHASE6_1_TIERING.md) | Scope-aware thresholds (SOLO/STARTUP/GROWTH/ENTERPRISE) |
| 7 | CI/CD Enforcement | [docs/PHASE7_ENFORCEMENT.md](docs/PHASE7_ENFORCEMENT.md) | Hard gates, immutable audit trail, quota system |
| 8 | Trust & Observability | [docs/PHASE8_TRUST_OBSERVABILITY.md](docs/PHASE8_TRUST_OBSERVABILITY.md) | Evidence ledger, business metrics, AI boundaries |

---

## API Quick Reference

### Business Logic (Phase 5)
```
GET  /api/v1/remediation/plans           - Get remediation plan
GET  /api/v1/remediation/summary         - Priority summary
GET  /api/v1/remediation/assets          - List/tag business assets
GET  /api/v1/remediation/rules           - Get remediation rules
POST /api/v1/remediation/estimate-fine   - Estimate compliance fine
```

### Enforcement (Phase 7)
```
GET  /api/v1/enforce/gate                - Check if deployment allowed
GET  /api/v1/enforce/history             - Audit trail
GET  /api/v1/enforce/quota               - Monthly quota usage
POST /api/v1/enforce/acknowledge         - Acknowledge soft fail
GET  /api/v1/enforce/decision/{id}       - Look up specific decision
```

### Evidence & Metrics (Phase 8)
```
GET  /api/v1/evidence                      - Query immutable ledger
POST /api/v1/evidence/{id}/verify         - Verify integrity
GET  /api/v1/evidence/entity/{entity_id}  - Timeline reconstruction
GET  /api/v1/evidence/export/audit-trail  - Compliance export

GET  /api/v1/metrics/revenue-at-risk      - Financial impact
GET  /api/v1/metrics/compliance-exposure  - Regulatory exposure
GET  /api/v1/metrics/sla-performance      - On-time %
GET  /api/v1/metrics/enforcement-effectiveness - Gate quality
GET  /api/v1/metrics/dashboard            - Executive view
```

---

## Migrations & Database
- Create / update DB schema:
  cd backend
  alembic upgrade head
- Avoid editing applied migrations on production. Prefer new migration scripts for schema changes.

## Testing

### Backend Tests
```bash
cd backend
.\.venv\Scripts\Activate.ps1

# Run all tests
pytest -q

# Run specific test file
pytest tests/test_enforcement.py -v

# Run with coverage
pytest --cov=app tests/ -v
```

**Test Files by Phase**:
- `test_business_logic.py` (Phase 5) - Priority formula, compliance fines
- `test_enforcement.py` (Phase 7) - Gate decisions, audit trail, quotas
- `test_observability.py` (Phase 8) - Evidence logging, metrics calculations (TODO)

### Frontend Tests

## Key Design Principles

### 1. Deterministic, Not Configurable
Every decision uses the same math, same logic, same outcome. No team-by-team exceptions.
- Priority formula: Same for all tenants
- Enforcement levels: Same thresholds
- SLA targets: Consistent expectations

### 2. Transparent, Not Black-Box
Every block has a reason. Every reason is queryable.
```json
{
  "decision": "BLOCK",
  "priority_score": 150,
  "reason": "RLS bypass in payment processing (PCI compliance)",
  "asset_at_risk": "public.orders",
  "financial_risk_usd": 25000.0,
  "required_action": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY"
}
```

### 3. Auditable, Not Overridable
Every decision is logged once, hashed, and immutable.
- Auditors can verify with SHA256: "Proof this wasn't faked"
- Engineers can see full timeline: "Why was I blocked?"
- Executives can quantify impact: "What's our financial risk?"

### 4. Inclusive, Not Predatory
Free tier gets real enforcement, just rate-limited.
- SOLO (free): 1 HARD_FAIL/month + soft gates (fair limits)
- STARTUP: Unlimited enforcement (earn trust early)
- Enterprise: Unlimited + custom SLAs

### 5. AI-Safe, Not AI-Driven
Optional AI enhancement, but deterministic core is immutable.
- AI can explain decisions better: ✅
- AI can suggest alternatives: ✅
- AI can override security decision: ❌ (hard boundary)

---

## Common Workflows

### Auditor: Verify Evidence Integrity
```bash
# Query enforcement decisions
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.forgescan.io/api/v1/evidence?evidence_type=ENFORCEMENT&limit=10"

# Select a record and verify its hash
curl -s -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d @payload.json \
  "https://api.forgescan.io/api/v1/evidence/{evidence_id}/verify"

# Response: {"integrity_verified": true, "message": "No tampering detected"}
```

### Executive: Check Financial Impact
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.forgescan.io/api/v1/metrics/revenue-at-risk"

# Response: {"total_at_risk_per_hour": 45000.00, "breakdown": {...}}
```

### Engineer: Understand Build Block
```bash
# Get enforcement history
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.forgescan.io/api/v1/enforce/history?limit=5"

# Reconstruct full timeline for a vulnerability
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.forgescan.io/api/v1/evidence/entity/vuln%3ARLS_BYPASS%3Aorders"

# Response shows: SCAN → ENFORCEMENT → REMEDIATION timeline
```

### Compliance Officer: Export Audit Trail
```bash
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://api.forgescan.io/api/v1/evidence/export/audit-trail?date_from=2024-11-01&date_to=2024-11-30"

# Response: Full evidence ledger with hashes, ready for legal discovery
```

---
## Troubleshooting

### Database & Migrations
- **Schema issues**: `alembic upgrade head`
- **DB connectivity**: Check `POSTGRES_*` env vars match docker-compose
- **Phase 8 tables missing**: Load `backend/security/phase8_observability.sql` manually

### Enforcement Not Working
- **Gate always allows**: Check tenant tier in `operational_tier` column
- **No audit trail**: Ensure `enforcement_decisions` table has data (check `enforce_release_gate()` function)
- **Quota not enforcing**: Verify `enforcement_quota` row exists for tenant

### Evidence Ledger Issues
- **Evidence not logged**: Check `evidence_service` is injected and async function called
- **Hash verification fails**: Ensure payload JSON is identical (field order, whitespace)
- **Audit export empty**: Verify date range includes evidence records

### Other Issues
- **TypeScript build errors**: Check for stray characters in JSON/TSX files
- **"object is not awaitable"**: Make sure all async service calls are awaited
- **Redis connection**: Verify Redis is running and `REDIS_*` env vars are set

---

## Production Deployment

### Security Hardening
- Keep secrets out of repo (use `.env` and `.env.example`)
- Use non-root users in Docker images
- Use server_default or callable defaults for JSON columns (no shared mutable defaults)
- **Do not expose** DB/Redis ports in production; use internal networking or secrets management
- Enable TLS for all API endpoints
- Use short-lived tokens and rotate secrets regularly

### CI/CD Integration
All major platforms are supported. See [docs/PHASE7_ENFORCEMENT.md](docs/PHASE7_ENFORCEMENT.md) for examples:

**GitHub Actions**:
```yaml
- name: ForgeScan Release Gate
  run: |
    RESPONSE=$(curl -s -H "Authorization: Bearer $FORGESCAN_TOKEN" \
      "https://api.forgescan.io/api/v1/enforce/gate?tenant_id=$TENANT_ID")
    DECISION=$(echo $RESPONSE | jq -r '.decision')
    if [ "$DECISION" = "BLOCK" ]; then exit 1; fi
```

**GitLab CI**:
```yaml
forgescan_gate:
  stage: pre-deploy
  script:
    - RESULT=$(curl -s -H "PRIVATE-TOKEN: $FORGESCAN_TOKEN" 
      "https://api.forgescan.io/api/v1/enforce/gate?tenant_id=$TENANT_ID")
    - if echo $RESULT | jq -e '.decision == "BLOCK"' > /dev/null; then exit 1; fi
```

**Jenkins**:
```groovy
stage('ForgeScan Gate') {
    steps {
        script {
            def response = sh(
                returnStdout: true,
                script: '''curl -s -H "Authorization: Bearer $FORGESCAN_TOKEN" \\
                  "https://api.forgescan.io/api/v1/enforce/gate?tenant_id=$TENANT_ID"'''
            ).trim()
            def decision = readJSON(text: response).decision
            if (decision == "BLOCK") {
                error("Deployment blocked by ForgeScan")
            }
        }
    }
}
```

### Monitoring & Alerting
- Monitor enforcement gate latency: `GET /api/v1/enforce/gate` should respond < 500ms
- Alert on sudden drop in SLA performance: `GET /api/v1/metrics/sla-performance`
- Track revenue at risk trend: `GET /api/v1/metrics/revenue-at-risk`
- Audit evidence integrity regularly: Use `POST /api/v1/evidence/{id}/verify`

---

## Next Steps

### Phase 8 Testing (In Progress)
- [ ] Integration tests: `backend/tests/test_observability.py`
  - Evidence logging and integrity verification
  - Metrics calculations (revenue, compliance, SLA)
  - Audit trail export with date ranges
  - Remediation effectiveness tracking

### Phase 9: Deterministic Recommendations
- [ ] AI-safe recommendation engine (read-only enhancement)
- [ ] Executive dashboard UI (visual metrics)
- [ ] Automated remediation suggestions
- [ ] Integration with Phase 8 evidence layer

### Phase 10+: Ecosystem Integration
- [ ] Slack/Teams notifications for blocks
- [ ] Custom webhook integrations
- [ ] Enterprise SSO (SAML/OIDC)
- [ ] Advanced reporting and trend analysis

---
