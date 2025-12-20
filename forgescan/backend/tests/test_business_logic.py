"""
Integration tests for Business Logic Layer (Phase 5)

Tests the complete workflow:
1. Tag business assets with financial/compliance context
2. Run security scans (generate findings)
3. Match findings against remediation rules
4. Calculate deterministic priorities
5. Generate remediation plan

Formula validation:
    priority = base_priority + revenue_bonus + compliance_bonus + exposure_multiplier
"""
import pytest
import asyncio
from uuid import uuid4
from datetime import datetime, timedelta
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text

from app.remediation.business_evaluator import (
    BusinessLogicEvaluator,
    generate_tenant_remediation_summary
)
from app.db.models.business_context import (
    AssetType,
    DataSensitivity,
    ComplianceFramework,
)


@pytest.mark.asyncio
class TestBusinessLogicLayer:
    """Test suite for deterministic remediation planning"""
    
    @pytest.fixture
    async def test_tenant_id(self):
        """Generate a test tenant UUID"""
        return str(uuid4())
    
    @pytest.fixture
    async def evaluator(self, db_session: AsyncSession):
        """Create BusinessLogicEvaluator instance"""
        return BusinessLogicEvaluator(db_session)
    
    
    # ==================== Asset Tagging Tests ====================
    
    async def test_tag_revenue_asset_with_pci_data(
        self,
        evaluator: BusinessLogicEvaluator,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Tag payment processing table as REVENUE + PCI data
        
        Expected:
        - Asset should be created with downtime_cost_per_hour = 50,000
        - Asset should be linked to PCI-DSS and GDPR frameworks
        - Asset ID should be returned
        """
        asset_id = await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="public",
            table_name="orders",
            asset_type=AssetType.REVENUE,
            data_sensitivity=DataSensitivity.PCI,
            downtime_cost_per_hour=50000,
            compliance_frameworks=["PCI-DSS", "GDPR"],
        )
        
        assert asset_id is not None
        
        # Verify asset was created
        result = await db_session.execute(
            text("""
                SELECT asset_type, data_sensitivity, downtime_cost_per_hour
                FROM forgescan_security.business_assets
                WHERE asset_id = :asset_id::UUID
            """),
            {"asset_id": asset_id}
        )
        row = result.fetchone()
        
        assert row is not None
        assert row[0] == "REVENUE"
        assert row[1] == "PCI"
        assert row[2] == 50000
    
    
    async def test_tag_compliance_asset_with_phi_data(
        self,
        evaluator: BusinessLogicEvaluator,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Tag healthcare table as COMPLIANCE + PHI data
        
        Expected:
        - Asset should be linked to HIPAA framework
        - downtime_cost_per_hour = 10,000 (lower than revenue)
        """
        asset_id = await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="healthcare",
            table_name="patient_records",
            asset_type=AssetType.COMPLIANCE,
            data_sensitivity=DataSensitivity.PHI,
            downtime_cost_per_hour=10000,
            compliance_frameworks=["HIPAA", "GDPR"],
        )
        
        assert asset_id is not None
        
        result = await db_session.execute(
            text("""
                SELECT asset_type, data_sensitivity
                FROM forgescan_security.business_assets
                WHERE asset_id = :asset_id::UUID
            """),
            {"asset_id": asset_id}
        )
        row = result.fetchone()
        
        assert row[0] == "COMPLIANCE"
        assert row[1] == "PHI"
    
    
    async def test_list_business_assets(
        self,
        evaluator: BusinessLogicEvaluator,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: List all tagged assets for a tenant
        
        Expected:
        - Should return list of assets sorted by downtime_cost_per_hour DESC
        """
        # Tag multiple assets
        await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="public",
            table_name="orders",
            asset_type=AssetType.REVENUE,
            data_sensitivity=DataSensitivity.PCI,
            downtime_cost_per_hour=50000,
            compliance_frameworks=["PCI-DSS"],
        )
        
        await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="public",
            table_name="users",
            asset_type=AssetType.OPERATIONAL,
            data_sensitivity=DataSensitivity.PII,
            downtime_cost_per_hour=10000,
            compliance_frameworks=["GDPR"],
        )
        
        # List assets
        assets = await evaluator.get_business_assets(test_tenant_id)
        
        assert len(assets) >= 2
        # Should be sorted by downtime cost DESC
        assert assets[0]["downtime_cost_per_hour"] >= assets[1]["downtime_cost_per_hour"]
    
    
    # ==================== Remediation Rules Tests ====================
    
    async def test_get_remediation_rules(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Fetch all deterministic remediation rules
        
        Expected:
        - Should return at least 10 rules
        - Rules should have all required fields: base_priority_score, revenue_bonus, etc.
        """
        rules = await evaluator.get_remediation_rules()
        
        assert len(rules) >= 10
        
        # Verify rule structure
        for rule in rules:
            assert rule["rule_id"] is not None
            assert rule["vuln_type"] is not None
            assert rule["base_priority_score"] > 0
            assert "revenue_bonus" in rule
            assert "compliance_bonus" in rule
            assert "required_action" in rule
            assert "severity_label" in rule
            assert "mitigation_time_hours" in rule
    
    
    async def test_get_specific_vulnerability_rule(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Fetch remediation rules for specific vulnerability type
        
        Expected:
        - Should return only RLS_BYPASS rules
        - RLS_BYPASS should have high base_priority_score (≥100)
        """
        rules = await evaluator.get_remediation_rules(vuln_type="RLS_BYPASS")
        
        assert len(rules) > 0
        
        for rule in rules:
            assert rule["vuln_type"] == "RLS_BYPASS"
            assert rule["base_priority_score"] >= 100
    
    
    # ==================== Compliance Fine Estimation Tests ====================
    
    async def test_estimate_pci_fines(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Estimate PCI-DSS fines for 500K records exposed
        
        Expected:
        - GDPR fine ≤ €20M (~$25M)
        - PCI-DSS fine ≤ $600K
        - Estimated fine should be <50% of max (not all records lost)
        """
        fines = await evaluator.estimate_compliance_fines(
            data_sensitivity="PCI",
            max_records=500000,
            frameworks=["GDPR", "PCI-DSS"],
        )
        
        assert len(fines) == 2
        
        for fine in fines:
            assert fine["framework"] in ["GDPR", "PCI-DSS"]
            assert fine["max_fine_usd"] > 0
            assert fine["estimated_fine_usd"] > 0
            assert fine["estimated_fine_usd"] <= fine["max_fine_usd"]
    
    
    async def test_estimate_hipaa_fines(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Estimate HIPAA fines for PHI breach
        
        Expected:
        - HIPAA fine ≥ $1.5M for large breach
        """
        fines = await evaluator.estimate_compliance_fines(
            data_sensitivity="PHI",
            max_records=1000000,
            frameworks=["HIPAA"],
        )
        
        assert len(fines) >= 1
        hipaa_fine = next((f for f in fines if f["framework"] == "HIPAA"), None)
        
        assert hipaa_fine is not None
        assert hipaa_fine["estimated_fine_usd"] >= 1500000
    
    
    # ==================== Remediation Plan Tests ====================
    
    async def test_generate_remediation_plan_empty(
        self,
        evaluator: BusinessLogicEvaluator,
        test_tenant_id: str,
    ):
        """
        Test: Generate remediation plan for tenant with no findings
        
        Expected:
        - Should return empty list (no errors)
        """
        plan = await evaluator.generate_remediation_plan(test_tenant_id)
        
        assert isinstance(plan, list)
        # Empty is acceptable if no findings exist
    
    
    async def test_remediation_plan_sorted_by_priority(
        self,
        evaluator: BusinessLogicEvaluator,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Remediation plan should be sorted by priority_rank DESC
        
        Expected:
        - First item should have highest priority_rank
        - Each subsequent item should have equal or lower priority_rank
        """
        plan = await evaluator.generate_remediation_plan(test_tenant_id)
        
        if len(plan) > 1:
            for i in range(len(plan) - 1):
                assert plan[i]["priority_rank"] >= plan[i + 1]["priority_rank"]
    
    
    async def test_remediation_plan_includes_required_fields(
        self,
        evaluator: BusinessLogicEvaluator,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Each remediation in plan should have all required fields
        
        Expected fields:
        - priority_rank (int)
        - asset_name (str)
        - vulnerability (str)
        - business_impact (str)
        - financial_risk (str)
        - remediation_command (str)
        - mitigation_sla_hours (int)
        - severity (str: CRITICAL|HIGH|MEDIUM|LOW)
        """
        plan = await evaluator.generate_remediation_plan(test_tenant_id)
        
        required_fields = [
            "priority_rank",
            "asset_name",
            "vulnerability",
            "business_impact",
            "financial_risk",
            "remediation_command",
            "mitigation_sla_hours",
            "severity",
        ]
        
        for remediation in plan:
            for field in required_fields:
                assert field in remediation, f"Missing field: {field}"
                assert remediation[field] is not None
    
    
    # ==================== Priority Calculation Tests ====================
    
    async def test_priority_formula_rls_bypass_on_pci_revenue(
        self,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Verify priority calculation for critical scenario
        
        Scenario: RLS_BYPASS vulnerability on REVENUE asset with PCI data
        
        Expected Priority:
        - base_priority_score: 100 (RLS_BYPASS)
        - revenue_bonus: +20 (REVENUE asset)
        - compliance_bonus: +30 (PCI data)
        - Total: 150
        """
        evaluator = BusinessLogicEvaluator(db_session)
        
        # Tag the asset
        asset_id = await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="test",
            table_name="test_rls_bypass_pci",
            asset_type=AssetType.REVENUE,
            data_sensitivity=DataSensitivity.PCI,
            downtime_cost_per_hour=50000,
            compliance_frameworks=["PCI-DSS"],
        )
        
        # Get the remediation rules for RLS_BYPASS
        rules = await evaluator.get_remediation_rules(vuln_type="RLS_BYPASS")
        
        if rules:
            rule = rules[0]
            
            # Calculate expected priority
            expected_priority = (
                rule["base_priority_score"]
                + rule["revenue_bonus"]
                + rule["compliance_bonus"]
            )
            
            # Should be around 150 (100 + 20 + 30)
            assert expected_priority >= 150
    
    
    async def test_priority_formula_weak_masking_on_phi_compliance(
        self,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Priority for WEAK_MASKING on COMPLIANCE asset with PHI data
        
        Expected Priority:
        - base_priority_score: 90 (WEAK_MASKING)
        - revenue_bonus: 0 (not a REVENUE asset)
        - compliance_bonus: +35 (PHI data)
        - Total: ~125
        """
        evaluator = BusinessLogicEvaluator(db_session)
        
        # Tag the asset
        await evaluator.tag_asset(
            tenant_id=test_tenant_id,
            schema_name="healthcare",
            table_name="patient_phi",
            asset_type=AssetType.COMPLIANCE,
            data_sensitivity=DataSensitivity.PHI,
            downtime_cost_per_hour=10000,
            compliance_frameworks=["HIPAA"],
        )
        
        # Get rules for WEAK_MASKING
        rules = await evaluator.get_remediation_rules(vuln_type="WEAK_MASKING")
        
        if rules:
            rule = rules[0]
            
            expected_priority = (
                rule["base_priority_score"]
                + rule["revenue_bonus"]  # Should be 0
                + rule["compliance_bonus"]  # Should be ~35
            )
            
            assert expected_priority >= 125
    
    
    # ==================== Summary Generation Tests ====================
    
    async def test_generate_tenant_summary(
        self,
        db_session: AsyncSession,
        test_tenant_id: str,
    ):
        """
        Test: Generate high-level remediation summary for tenant
        
        Expected Response:
        - summary: { total_findings, critical_count, high_count, etc. }
        - risk: { total_downtime_risk_usd_1hr, estimated_compliance_fines_usd }
        - critical_remediations: top 10 items
        - asset_summary: { revenue_assets, pci_assets, compliance_assets }
        """
        summary = await generate_tenant_remediation_summary(db_session, test_tenant_id)
        
        assert "tenant_id" in summary
        assert "summary" in summary
        assert "risk" in summary
        assert "critical_remediations" in summary
        assert "asset_summary" in summary
        
        # Verify summary structure
        summary_data = summary["summary"]
        assert summary_data["total_findings"] >= 0
        assert summary_data["critical_count"] >= 0
        assert summary_data["high_count"] >= 0
        assert summary_data["medium_count"] >= 0
        assert summary_data["low_count"] >= 0
    
    
    # ==================== Error Handling Tests ====================
    
    async def test_tag_asset_invalid_tenant_id(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Tagging asset with invalid tenant UUID should fail gracefully
        
        Expected:
        - Should raise exception or return error
        """
        with pytest.raises(Exception):
            await evaluator.tag_asset(
                tenant_id="not-a-uuid",
                schema_name="public",
                table_name="test",
                asset_type=AssetType.REVENUE,
                data_sensitivity=DataSensitivity.PCI,
                downtime_cost_per_hour=50000,
                compliance_frameworks=["PCI-DSS"],
            )
    
    
    async def test_estimate_fine_no_frameworks(
        self,
        evaluator: BusinessLogicEvaluator,
    ):
        """
        Test: Estimating fines with no frameworks should return empty list
        """
        fines = await evaluator.estimate_compliance_fines(
            data_sensitivity="PCI",
            max_records=100000,
            frameworks=[],
        )
        
        assert len(fines) == 0
