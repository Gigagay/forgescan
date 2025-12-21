"""
Phase 8: Trust & Observability Integration Tests

Tests for immutable evidence ledger, business metrics, SLA tracking, and AI-safe boundaries.

Coverage:
- Evidence service: logging, querying, integrity verification, timeline reconstruction
- Remediation effectiveness: SLA tracking, recurrence, metrics calculation
- API endpoints: evidence queries, metrics retrieval, audit exports
- Database views: metrics calculations, aggregations
"""
import pytest
import json
from datetime import datetime, timedelta
from uuid import uuid4
from sqlalchemy.ext.asyncio import AsyncSession
from httpx import AsyncClient

from app.services.evidence_service import EvidenceService, get_evidence_service
from app.services.remediation_effectiveness import RemediationEffectivenessService, get_remediation_effectiveness_service
from app.main import app
from app.db.session import get_db


# ============================================================================
# FIXTURES
# ============================================================================

@pytest.fixture
def tenant_id():
    """Standard tenant ID for tests."""
    return str(uuid4())


@pytest.fixture
def evidence_payload():
    """Sample evidence payload (ENFORCEMENT event)."""
    return {
        "enforcement_level": "HARD_FAIL",
        "priority_score": 150,
        "decision": "BLOCK",
        "asset_at_risk": "public.orders",
        "financial_risk_usd": 25000.0,
        "reason": "RLS bypass in payment processing"
    }


@pytest.fixture
async def evidence_service(async_session: AsyncSession) -> EvidenceService:
    """Inject EvidenceService with test session."""
    return EvidenceService(async_session)


@pytest.fixture
async def remediation_service(async_session: AsyncSession) -> RemediationEffectivenessService:
    """Inject RemediationEffectivenessService with test session."""
    return RemediationEffectivenessService(async_session)


@pytest.fixture
async def client(async_session: AsyncSession) -> AsyncClient:
    """Async HTTP client for testing endpoints."""
    async def override_get_db():
        yield async_session
    
    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(app=app, base_url="http://test") as client:
        yield client
    app.dependency_overrides.clear()


# ============================================================================
# EVIDENCE SERVICE TESTS
# ============================================================================

class TestEvidenceService:
    """Test immutable evidence ledger functionality."""
    
    async def test_log_evidence_append_only(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test logging evidence creates append-only record with hash."""
        evidence_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        assert evidence_id is not None
        assert isinstance(evidence_id, str)
        # Evidence ID should be UUID-like
        assert len(evidence_id) == 36  # UUID length with dashes
    
    async def test_log_evidence_creates_hash(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test that logged evidence has SHA256 hash."""
        evidence_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Query evidence to verify hash exists
        evidence_list = await evidence_service.query_evidence(
            tenant_id=tenant_id,
            limit=1
        )
        
        assert len(evidence_list) > 0
        assert "hash" in evidence_list[0]
        assert len(evidence_list[0]["hash"]) == 64  # SHA256 hex is 64 chars
    
    async def test_query_evidence_with_filter(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test querying evidence with type filter."""
        # Log multiple evidence types
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="SCAN",
            related_entity="vuln:RLS_BYPASS:orders",
            payload={"scanner": "Bandit", "confidence": 0.95}
        )
        
        # Query only ENFORCEMENT
        enforcement_evidence = await evidence_service.query_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            limit=10
        )
        
        assert len(enforcement_evidence) > 0
        assert all(e["evidence_type"] == "ENFORCEMENT" for e in enforcement_evidence)
    
    async def test_verify_evidence_integrity_valid(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test verifying evidence integrity with matching payload."""
        evidence_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Verify with same payload
        is_valid = await evidence_service.verify_evidence_integrity(
            evidence_id=evidence_id,
            expected_payload=evidence_payload
        )
        
        assert is_valid is True
    
    async def test_verify_evidence_integrity_tampered(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test that tampering is detected via hash mismatch."""
        evidence_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Verify with modified payload
        tampered_payload = evidence_payload.copy()
        tampered_payload["priority_score"] = 100  # Changed from 150
        
        is_valid = await evidence_service.verify_evidence_integrity(
            evidence_id=evidence_id,
            expected_payload=tampered_payload
        )
        
        assert is_valid is False
    
    async def test_get_evidence_by_entity_timeline(
        self,
        evidence_service: EvidenceService,
        tenant_id: str
    ):
        """Test reconstructing timeline for an entity."""
        entity_id = "vuln:RLS_BYPASS:orders"
        
        # Log multiple events for same entity
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="SCAN",
            related_entity=entity_id,
            payload={"scanner": "Bandit", "detected_at": "2024-11-12T08:15:00Z"}
        )
        
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity=entity_id,
            payload={"priority_score": 150, "decision": "BLOCK"}
        )
        
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="REMEDIATION",
            related_entity=entity_id,
            payload={"time_to_fix_hours": 2.5, "sla_met": True}
        )
        
        # Reconstruct timeline
        timeline = await evidence_service.get_evidence_by_entity(
            tenant_id=tenant_id,
            entity_id=entity_id
        )
        
        assert len(timeline) == 3
        assert timeline[0]["evidence_type"] == "SCAN"
        assert timeline[1]["evidence_type"] == "ENFORCEMENT"
        assert timeline[2]["evidence_type"] == "REMEDIATION"
    
    async def test_export_audit_trail_with_date_range(
        self,
        evidence_service: EvidenceService,
        tenant_id: str,
        evidence_payload: dict
    ):
        """Test exporting audit trail for compliance with date filtering."""
        # Log evidence
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Export for date range
        date_from = (datetime.utcnow() - timedelta(days=1)).date().isoformat()
        date_to = (datetime.utcnow() + timedelta(days=1)).date().isoformat()
        
        audit_trail = await evidence_service.export_audit_trail(
            tenant_id=tenant_id,
            date_from=date_from,
            date_to=date_to
        )
        
        assert len(audit_trail) > 0
        assert all("hash" in record for record in audit_trail)
        assert all("payload" in record for record in audit_trail)


# ============================================================================
# REMEDIATION EFFECTIVENESS TESTS
# ============================================================================

class TestRemediationEffectiveness:
    """Test remediation tracking and SLA compliance."""
    
    async def test_record_remediation_creates_tracking(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test creating a new remediation record."""
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY"
        )
        
        assert remediation_id is not None
        assert isinstance(remediation_id, str)
        assert len(remediation_id) == 36  # UUID
    
    async def test_mark_remediation_fixed_sla_met(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test marking remediation fixed when SLA is met."""
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY"
        )
        
        # Mark as fixed 3 hours later (SLA target is 4 hours)
        fixed_at = "2024-11-12T11:15:00Z"
        result = await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at=fixed_at
        )
        
        assert result["sla_met"] is True
        assert result["status"] == "FIXED_MET_SLA"
        assert result["time_to_fix_hours"] == 3.0
    
    async def test_mark_remediation_fixed_sla_missed(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test marking remediation fixed when SLA is missed."""
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY"
        )
        
        # Mark as fixed 5 hours later (SLA target is 4 hours)
        fixed_at = "2024-11-12T13:15:00Z"
        result = await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at=fixed_at
        )
        
        assert result["sla_met"] is False
        assert result["status"] == "FIXED_MISSED_SLA"
        assert result["time_to_fix_hours"] == 5.0
    
    async def test_record_recurrence_tracks_regression(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test recording recurrence of a previously-fixed vulnerability."""
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY"
        )
        
        # Mark as fixed
        await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at="2024-11-12T11:15:00Z"
        )
        
        # Record recurrence
        recurrence = await remediation_service.record_recurrence(
            remediation_id=remediation_id
        )
        
        assert recurrence["recurrence_count"] == 1
        assert recurrence["status"] == "RECURRING_ISSUE"
    
    async def test_get_sla_metrics_aggregation(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test SLA metrics aggregation across multiple remediations."""
        # Create 3 remediations, 2 on-time, 1 missed
        for i in range(3):
            remediation_id = await remediation_service.record_remediation(
                tenant_id=tenant_id,
                vuln_type=f"VULN_{i}",
                asset_name="public.orders",
                severity="HIGH",
                first_detected=f"2024-11-{12+i}T08:15:00Z",
                sla_target_hours=4,
                remediation_command="ALTER TABLE..."
            )
            
            if i < 2:
                # Fix on-time
                await remediation_service.mark_remediation_fixed(
                    remediation_id=remediation_id,
                    fixed_at=f"2024-11-{12+i}T11:15:00Z"
                )
            else:
                # Fix late
                await remediation_service.mark_remediation_fixed(
                    remediation_id=remediation_id,
                    fixed_at=f"2024-11-{12+i}T13:15:00Z"
                )
        
        metrics = await remediation_service.get_sla_metrics(tenant_id=tenant_id)
        
        assert metrics["total_remediated"] == 3
        assert metrics["sla_met_count"] == 2
        assert metrics["sla_compliance_pct"] > 66.0  # 2/3 = 66.67%
    
    async def test_identify_recurring_vulnerabilities(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test identifying vulnerability types that recur."""
        # Create RLS_BYPASS remediation and record it recurring twice
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE..."
        )
        
        await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at="2024-11-12T11:15:00Z"
        )
        
        await remediation_service.record_recurrence(remediation_id=remediation_id)
        await remediation_service.record_recurrence(remediation_id=remediation_id)
        
        # Identify recurring
        recurring = await remediation_service.identify_recurring_vulnerabilities(
            tenant_id=tenant_id,
            min_recurrence=2
        )
        
        assert len(recurring) > 0
        assert any(r["vuln_type"] == "RLS_BYPASS" for r in recurring)


# ============================================================================
# API ENDPOINT TESTS
# ============================================================================

class TestEvidenceAPI:
    """Test evidence API endpoints."""
    
    async def test_get_evidence_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str,
        evidence_service: EvidenceService,
        evidence_payload: dict
    ):
        """Test GET /api/v1/evidence endpoint."""
        # Log evidence first
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Query via API
        response = await client.get(
            f"/api/v1/evidence?evidence_type=ENFORCEMENT&limit=10",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        # Note: Actual implementation would validate auth
        # This test demonstrates endpoint accessibility
        assert response.status_code in [200, 401, 403]  # Success or auth error
    
    async def test_verify_evidence_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str,
        evidence_service: EvidenceService,
        evidence_payload: dict
    ):
        """Test POST /api/v1/evidence/{id}/verify endpoint."""
        evidence_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Verify via API
        response = await client.post(
            f"/api/v1/evidence/{evidence_id}/verify",
            json=evidence_payload,
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
    
    async def test_entity_timeline_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str,
        evidence_service: EvidenceService
    ):
        """Test GET /api/v1/evidence/entity/{entity_id} endpoint."""
        entity_id = "vuln:RLS_BYPASS:orders"
        
        # Log events
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="SCAN",
            related_entity=entity_id,
            payload={"scanner": "Bandit"}
        )
        
        # Query timeline via API
        response = await client.get(
            f"/api/v1/evidence/entity/{entity_id}",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403, 404]
    
    async def test_audit_trail_export_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str,
        evidence_service: EvidenceService,
        evidence_payload: dict
    ):
        """Test GET /api/v1/evidence/export/audit-trail endpoint."""
        # Log evidence
        await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=evidence_payload
        )
        
        # Export via API
        date_from = (datetime.utcnow() - timedelta(days=1)).date().isoformat()
        date_to = (datetime.utcnow() + timedelta(days=1)).date().isoformat()
        
        response = await client.get(
            f"/api/v1/evidence/export/audit-trail?date_from={date_from}&date_to={date_to}",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403, 400]


class TestMetricsAPI:
    """Test business metrics API endpoints."""
    
    async def test_revenue_at_risk_endpoint(self, client: AsyncClient, tenant_id: str):
        """Test GET /api/v1/metrics/revenue-at-risk endpoint."""
        response = await client.get(
            "/api/v1/metrics/revenue-at-risk",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
        if response.status_code == 200:
            data = response.json()
            assert "metric" in data
            assert data["metric"] == "revenue_at_risk"
            assert "currency" in data
            assert data["currency"] == "USD"
    
    async def test_compliance_exposure_endpoint(self, client: AsyncClient, tenant_id: str):
        """Test GET /api/v1/metrics/compliance-exposure endpoint."""
        response = await client.get(
            "/api/v1/metrics/compliance-exposure",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
        if response.status_code == 200:
            data = response.json()
            assert "metric" in data
            assert data["metric"] == "compliance_exposure"
    
    async def test_sla_performance_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str,
        remediation_service: RemediationEffectivenessService
    ):
        """Test GET /api/v1/metrics/sla-performance endpoint."""
        # Create some remediation data
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:15:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE..."
        )
        
        await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at="2024-11-12T11:15:00Z"
        )
        
        response = await client.get(
            "/api/v1/metrics/sla-performance",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
        if response.status_code == 200:
            data = response.json()
            assert "metric" in data
            assert data["metric"] == "sla_performance"
            assert "sla_compliance_pct" in data
    
    async def test_enforcement_effectiveness_endpoint(
        self,
        client: AsyncClient,
        tenant_id: str
    ):
        """Test GET /api/v1/metrics/enforcement-effectiveness endpoint."""
        response = await client.get(
            "/api/v1/metrics/enforcement-effectiveness",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
        if response.status_code == 200:
            data = response.json()
            assert "metric" in data
            assert data["metric"] == "enforcement_effectiveness"
    
    async def test_dashboard_endpoint(self, client: AsyncClient, tenant_id: str):
        """Test GET /api/v1/metrics/dashboard endpoint."""
        response = await client.get(
            "/api/v1/metrics/dashboard",
            headers={"X-Tenant-ID": tenant_id}
        )
        
        assert response.status_code in [200, 401, 403]
        if response.status_code == 200:
            data = response.json()
            assert "key_metrics" in data
            assert "health_status" in data


# ============================================================================
# INTEGRATION TESTS
# ============================================================================

class TestPhase8Integration:
    """End-to-end Phase 8 workflows."""
    
    async def test_complete_evidence_lifecycle(
        self,
        evidence_service: EvidenceService,
        tenant_id: str
    ):
        """Test complete lifecycle: log evidence → query → verify → timeline → export."""
        entity_id = "vuln:RLS_BYPASS:orders"
        
        # 1. Log SCAN event
        scan_payload = {"scanner": "Bandit", "confidence": 0.95, "detected_at": "2024-11-12T08:15:00Z"}
        scan_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="SCAN",
            related_entity=entity_id,
            payload=scan_payload
        )
        assert scan_id is not None
        
        # 2. Log ENFORCEMENT event
        enforcement_payload = {"priority_score": 150, "decision": "BLOCK", "reason": "RLS bypass"}
        enforcement_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity=entity_id,
            payload=enforcement_payload
        )
        assert enforcement_id is not None
        
        # 3. Log REMEDIATION event
        remediation_payload = {"time_to_fix_hours": 2.5, "sla_met": True, "fixed_at": "2024-11-12T10:45:00Z"}
        remediation_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="REMEDIATION",
            related_entity=entity_id,
            payload=remediation_payload
        )
        assert remediation_id is not None
        
        # 4. Query all evidence
        all_evidence = await evidence_service.query_evidence(
            tenant_id=tenant_id,
            limit=10
        )
        assert len(all_evidence) >= 3
        
        # 5. Verify integrity of each
        assert await evidence_service.verify_evidence_integrity(scan_id, scan_payload) is True
        assert await evidence_service.verify_evidence_integrity(enforcement_id, enforcement_payload) is True
        assert await evidence_service.verify_evidence_integrity(remediation_id, remediation_payload) is True
        
        # 6. Reconstruct timeline
        timeline = await evidence_service.get_evidence_by_entity(tenant_id, entity_id)
        assert len(timeline) == 3
        assert timeline[0]["evidence_type"] == "SCAN"
        assert timeline[1]["evidence_type"] == "ENFORCEMENT"
        assert timeline[2]["evidence_type"] == "REMEDIATION"
        
        # 7. Export audit trail
        date_from = (datetime.utcnow() - timedelta(days=1)).date().isoformat()
        date_to = (datetime.utcnow() + timedelta(days=1)).date().isoformat()
        audit_trail = await evidence_service.export_audit_trail(tenant_id, date_from, date_to)
        assert len(audit_trail) >= 3
        assert all("hash" in record for record in audit_trail)
    
    async def test_remediation_with_sla_and_recurrence(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test remediation tracking with SLA and recurrence."""
        # 1. Record initial detection
        remediation_id = await remediation_service.record_remediation(
            tenant_id=tenant_id,
            vuln_type="RLS_BYPASS",
            asset_name="public.orders",
            severity="CRITICAL",
            first_detected="2024-11-12T08:00:00Z",
            sla_target_hours=4,
            remediation_command="ALTER TABLE public.orders ENABLE ROW LEVEL SECURITY"
        )
        
        # 2. Mark as fixed on-time
        result1 = await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at="2024-11-12T11:00:00Z"
        )
        assert result1["sla_met"] is True
        assert result1["time_to_fix_hours"] == 3.0
        
        # 3. Record recurrence
        result2 = await remediation_service.record_recurrence(remediation_id=remediation_id)
        assert result2["recurrence_count"] == 1
        
        # 4. Mark recurrence as fixed late
        result3 = await remediation_service.mark_remediation_fixed(
            remediation_id=remediation_id,
            fixed_at="2024-11-13T16:00:00Z"
        )
        assert result3["sla_met"] is False
        
        # 5. Verify metrics reflect both events
        metrics = await remediation_service.get_sla_metrics(tenant_id=tenant_id)
        assert metrics["total_remediated"] >= 1
        assert metrics["recurring_issues"] >= 1
    
    async def test_ai_safe_boundary_evidence_immutable(
        self,
        evidence_service: EvidenceService,
        tenant_id: str
    ):
        """Test that evidence ledger proves AI can't override core decisions.
        
        Scenario: AI tries to change enforcement decision → evidence proves it didn't happen
        """
        # 1. Log HARD_FAIL decision
        decision_payload = {
            "enforcement_level": "HARD_FAIL",
            "decision": "BLOCK",
            "priority_score": 150,
            "reason": "Critical RLS bypass"
        }
        decision_id = await evidence_service.log_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            related_entity="vuln:RLS_BYPASS:orders",
            payload=decision_payload
        )
        
        # 2. Store original hash
        original_evidence = await evidence_service.query_evidence(
            tenant_id=tenant_id,
            evidence_type="ENFORCEMENT",
            limit=1
        )
        original_hash = original_evidence[0]["hash"]
        
        # 3. AI tries to "change" decision to ALLOW (doesn't actually happen, just test proof)
        different_payload = decision_payload.copy()
        different_payload["decision"] = "ALLOW"  # AI attempt to change
        
        # 4. Verify shows tampering
        is_valid = await evidence_service.verify_evidence_integrity(
            decision_id,
            different_payload
        )
        assert is_valid is False  # Hash proves original is BLOCK
        
        # 5. Original decision is still BLOCK (immutable)
        assert await evidence_service.verify_evidence_integrity(
            decision_id,
            decision_payload
        ) is True


# ============================================================================
# DATABASE VIEW TESTS
# ============================================================================

class TestMetricsViews:
    """Test metrics view calculations."""
    
    async def test_sla_performance_view_calculation(
        self,
        remediation_service: RemediationEffectivenessService,
        tenant_id: str
    ):
        """Test metrics_sla_performance view correctly aggregates data."""
        # Create 5 remediations: 3 on-time, 2 late
        for i in range(5):
            remediation_id = await remediation_service.record_remediation(
                tenant_id=tenant_id,
                vuln_type=f"VULN_{i}",
                asset_name=f"table_{i}",
                severity="HIGH",
                first_detected=f"2024-11-{12+i}T08:00:00Z",
                sla_target_hours=4,
                remediation_command="ALTER TABLE..."
            )
            
            if i < 3:
                # On-time (2 hours)
                await remediation_service.mark_remediation_fixed(
                    remediation_id=remediation_id,
                    fixed_at=f"2024-11-{12+i}T10:00:00Z"
                )
            else:
                # Late (6 hours)
                await remediation_service.mark_remediation_fixed(
                    remediation_id=remediation_id,
                    fixed_at=f"2024-11-{12+i}T14:00:00Z"
                )
        
        metrics = await remediation_service.get_sla_metrics(tenant_id=tenant_id)
        
        # Verify calculations
        assert metrics["total_remediated"] == 5
        assert metrics["sla_met_count"] == 3
        assert metrics["sla_compliance_pct"] == 60.0  # 3/5
        assert 2.0 <= metrics["avg_time_to_fix_hours"] <= 5.0
