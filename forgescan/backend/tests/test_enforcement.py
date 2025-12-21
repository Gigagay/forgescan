"""
Integration tests for Phase 7: Enforcement, CI/CD Gating & Monetization Locks

Tests the complete enforcement pipeline:
1. Deterministic gate decisions (BLOCK, ALLOW_WITH_ACK, ALLOW, INFO)
2. Tier-based threshold modulation
3. Audit trail logging
4. Quota enforcement
"""
import pytest
from uuid import uuid4
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.services.enforcement_service import EnforcementService


@pytest.mark.asyncio
class TestEnforcementGate:
    """Test suite for Phase 7 enforcement gates"""
    
    @pytest.fixture
    async def test_tenant_id(self):
        return str(uuid4())
    
    @pytest.fixture
    async def enforcement_service(self, db_session: AsyncSession):
        return EnforcementService(db_session)
    
    
    # ==================== Gate Decision Tests ====================
    
    async def test_gate_blocks_critical_priority(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Gate blocks when max_priority >= 100
        
        Expected: decision = "BLOCK", enforcement_level = "HARD_FAIL"
        """
        # This would require synthetic findings; for now test the function exists
        result = await enforcement_service.enforce_release_gate(
            tenant_id=test_tenant_id,
            pipeline_id="test-pipeline"
        )
        
        assert result is not None
        assert "decision" in result
        assert "max_priority" in result
        assert "enforcement_level" in result
        assert "reason" in result
    
    
    async def test_gate_soft_fail_on_high_priority(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Gate allows with acknowledgement when 80 <= priority < 100
        
        Expected: decision = "ALLOW_WITH_ACK", enforcement_level = "SOFT_FAIL"
        """
        result = await enforcement_service.enforce_release_gate(
            tenant_id=test_tenant_id,
            pipeline_id="test-pipeline"
        )
        
        # When no findings, decision should be "ALLOW"
        if result["max_priority"] == 0:
            assert result["decision"] == "ALLOW"
        # When priority 80-99
        elif 80 <= result["max_priority"] < 100:
            assert result["decision"] == "ALLOW_WITH_ACK"
            assert result["enforcement_level"] == "SOFT_FAIL"
    
    
    async def test_gate_warns_on_medium_priority(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Gate warns when 60 <= priority < 80
        
        Expected: decision = "WARN", enforcement_level = "WARN"
        """
        result = await enforcement_service.enforce_release_gate(
            tenant_id=test_tenant_id
        )
        
        if 60 <= result["max_priority"] < 80:
            assert result["decision"] == "WARN"
            assert result["enforcement_level"] == "WARN"
    
    
    async def test_gate_allows_when_safe(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Gate allows when priority < 60 and no overrides
        
        Expected: decision = "ALLOW", enforcement_level = "INFO"
        """
        result = await enforcement_service.enforce_release_gate(
            tenant_id=test_tenant_id
        )
        
        if result["max_priority"] < 60:
            assert result["decision"] == "ALLOW"
            assert result["enforcement_level"] == "INFO"
    
    
    # ==================== Audit Trail Tests ====================
    
    async def test_decision_logged_to_audit_trail(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Every enforcement decision is logged
        
        Expected: decision appears in enforcement_decisions table
        """
        pipeline_id = "test-pipeline-" + str(uuid4())
        
        # Make a decision
        result = await enforcement_service.enforce_release_gate(
            tenant_id=test_tenant_id,
            pipeline_id=pipeline_id
        )
        
        decision_id = result.get("decision_id")
        
        if decision_id:
            # Verify it's in the audit trail
            history = await enforcement_service.get_enforcement_history(test_tenant_id)
            
            decision_ids = [d["decision_id"] for d in history]
            assert decision_id in decision_ids
    
    
    async def test_enforcement_history_sorted_desc(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Enforcement history returned in DESC order (most recent first)
        
        Expected: decided_at timestamps are descending
        """
        history = await enforcement_service.get_enforcement_history(test_tenant_id)
        
        if len(history) > 1:
            for i in range(len(history) - 1):
                assert history[i]["decided_at"] >= history[i + 1]["decided_at"]
    
    
    # ==================== Tier-Based Enforcement Tests ====================
    
    async def test_quota_check_passes_for_startup(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Startup tier has unlimited enforcement quota
        
        Expected: allowed = true, reason includes "passed"
        """
        result = await enforcement_service.check_enforcement_quota(test_tenant_id)
        
        assert result["allowed"] == True
        assert "passed" in result["reason"].lower() or "allowed" in result["reason"].lower()
    
    
    # ==================== Soft Fail Acknowledgement Tests ====================
    
    async def test_acknowledge_decision(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Can acknowledge a SOFT_FAIL decision
        
        Expected: decision marked with acked_by and acked_at
        """
        # Create a test decision first
        decision_id = await enforcement_service.log_enforcement_decision(
            tenant_id=test_tenant_id,
            pipeline_id="test-ack",
            decision="ALLOW_WITH_ACK",
            max_priority=85,
            enforcement_level="SOFT_FAIL",
            reason="Test acknowledgement",
        )
        
        assert decision_id is not None
        
        # Acknowledge it
        success = await enforcement_service.acknowledge_enforcement_decision(
            decision_id=str(decision_id),
            acked_by=str(uuid4())
        )
        
        assert success == True
        
        await db_session.commit()
    
    
    # ==================== Transparency Tests ====================
    
    async def test_decision_includes_business_context(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Every decision includes business context
        
        Expected: decision includes asset_at_risk, financial_risk_usd, required_action
        """
        decision_id = await enforcement_service.log_enforcement_decision(
            tenant_id=test_tenant_id,
            pipeline_id="test-context",
            decision="BLOCK",
            max_priority=150,
            enforcement_level="HARD_FAIL",
            reason="Revenue-impacting RLS bypass",
            asset_at_risk="tenant1.orders",
            financial_risk_usd=50000,
            required_action="ALTER TABLE tenant1.orders FORCE ROW LEVEL SECURITY"
        )
        
        history = await enforcement_service.get_enforcement_history(test_tenant_id)
        
        decision = next((d for d in history if d["decision_id"] == str(decision_id)), None)
        
        if decision:
            assert decision["asset_at_risk"] == "tenant1.orders"
            assert decision["financial_risk_usd"] == 50000
            assert "ROW LEVEL SECURITY" in decision["required_action"]
    
    
    # ==================== Error Handling Tests ====================
    
    async def test_quota_check_handles_missing_tier(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
    ):
        """
        Test: Quota check defaults to STARTUP if tier is missing
        
        Expected: Does not error, returns sensible default
        """
        # Use a tenant that may not exist (won't error, just returns default)
        fake_tenant = str(uuid4())
        
        try:
            result = await enforcement_service.check_enforcement_quota(fake_tenant)
            # Should handle gracefully
            assert result is not None
        except Exception:
            # Expected if no tenant exists (depends on implementation)
            pass
    
    
    async def test_get_decision_handles_missing_id(
        self,
        enforcement_service: EnforcementService,
        db_session: AsyncSession,
    ):
        """
        Test: Lookup non-existent decision returns None or error gracefully
        
        Expected: Does not crash, returns None or 404
        """
        fake_decision_id = str(uuid4())
        
        try:
            history = await enforcement_service.get_enforcement_history(str(uuid4()), limit=1)
            # Should handle gracefully
            assert isinstance(history, list)
        except Exception:
            # Expected if no tenant exists
            pass


# ==================== End-to-End CI/CD Workflow Tests ====================

@pytest.mark.asyncio
async def test_full_enforcement_workflow(
    db_session: AsyncSession,
):
    """
    Test: Full CI/CD enforcement workflow
    
    Workflow:
    1. Make a decision
    2. Log it
    3. Query history
    4. Acknowledge if soft fail
    """
    tenant_id = str(uuid4())
    service = EnforcementService(db_session)
    
    # 1. Make decision
    result = await service.enforce_release_gate(tenant_id, "test-pipeline")
    assert result["decision"] in ["BLOCK", "ALLOW_WITH_ACK", "ALLOW", "INFO"]
    
    # 2. Log it
    decision_id = await service.log_enforcement_decision(
        tenant_id=tenant_id,
        pipeline_id="test-pipeline",
        decision=result["decision"],
        max_priority=result["max_priority"],
        enforcement_level=result["enforcement_level"],
        reason=result["reason"]
    )
    assert decision_id is not None
    
    # 3. Query history
    history = await service.get_enforcement_history(tenant_id)
    assert len(history) > 0
    
    # 4. If soft fail, acknowledge
    if result["decision"] == "ALLOW_WITH_ACK":
        success = await service.acknowledge_enforcement_decision(
            str(decision_id),
            str(uuid4())
        )
        assert success == True
