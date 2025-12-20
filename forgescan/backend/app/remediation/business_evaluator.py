"""
Business Logic Evaluator for ForgeScan 2.0

Connects to the database layer to:
1. Fetch remediation plans (vulnerability → business asset → priority)
2. Estimate compliance fines
3. Tag assets with business context
4. Format results for API consumption
"""
from typing import List, Dict, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from app.db.models.business_context import (
    BusinessAsset, RemediationRule, AssetType, DataSensitivity, ComplianceFramework
)
import logging

logger = logging.getLogger(__name__)


class BusinessLogicEvaluator:
    """
    Main evaluator for business-impact-driven remediation.
    
    Workflow:
    1. Load business assets for a tenant
    2. Match vulnerabilities to remediation rules
    3. Calculate priorities using deterministic formula
    4. Return sorted remediation plan
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def generate_remediation_plan(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Generate deterministic remediation plan for a tenant.
        
        Calls the database function:
            forgescan_security.generate_remediation_plan(p_tenant_id UUID)
        
        Returns sorted list of remediations:
        [
            {
                'priority_rank': 150,
                'asset_name': 'tenant1.orders',
                'asset_type': 'REVENUE',
                'data_sensitivity': 'PCI',
                'vulnerability': 'RLS_BYPASS',
                'business_impact': 'Risk to REVENUE. Est. downtime cost: $50000/hr...',
                'financial_risk': 'CRITICAL: REVENUE LOSS',
                'compliance_obligations': 'PCI-DSS, GDPR',
                'downtime_cost_per_hour': 50000,
                'required_action': 'Immediate RLS Enforcement & Audit Review',
                'remediation_command': 'ALTER TABLE tenant1.orders FORCE ROW LEVEL SECURITY;...',
                'mitigation_sla_hours': 1,
                'severity': 'CRITICAL'
            },
            ...
        ]
        """
        try:
            query = text("""
                SELECT 
                    priority_rank,
                    asset_name,
                    asset_type,
                    data_sensitivity,
                    vulnerability,
                    business_impact,
                    financial_risk,
                    compliance_obligations,
                    downtime_cost_per_hour,
                    required_action,
                    remediation_command,
                    mitigation_sla_hours,
                    severity
                FROM forgescan_security.generate_remediation_plan(:tenant_id)
                ORDER BY priority_rank DESC;
            """)
            
            result = await self.session.execute(query, {"tenant_id": str(tenant_id)})
            rows = result.fetchall()
            
            remediations = [
                {
                    "priority_rank": row[0],
                    "asset_name": row[1],
                    "asset_type": row[2],
                    "data_sensitivity": row[3],
                    "vulnerability": row[4],
                    "business_impact": row[5],
                    "financial_risk": row[6],
                    "compliance_obligations": row[7],
                    "downtime_cost_per_hour": row[8],
                    "required_action": row[9],
                    "remediation_command": row[10],
                    "mitigation_sla_hours": row[11],
                    "severity": row[12],
                }
                for row in rows
            ]
            
            logger.info(f"Generated remediation plan for tenant {tenant_id}: {len(remediations)} items")
            return remediations
            
        except Exception as e:
            logger.error(f"Error generating remediation plan: {e}")
            raise
    
    async def estimate_compliance_fines(
        self,
        data_sensitivity: str,
        max_records: int,
        frameworks: List[str]
    ) -> List[Dict[str, Any]]:
        """
        Estimate potential regulatory fines for a data breach.
        
        Args:
            data_sensitivity: 'PII', 'PCI', 'PHI', etc.
            max_records: Number of records exposed
            frameworks: List of compliance frameworks (GDPR, HIPAA, etc.)
        
        Returns:
        [
            {
                'framework': 'GDPR',
                'max_fine_usd': 25000000,
                'estimated_fine_usd': 500000.0
            },
            {
                'framework': 'CCPA',
                'max_fine_usd': 7500000,
                'estimated_fine_usd': 250000.0
            }
        ]
        """
        try:
            query = text("""
                SELECT 
                    framework,
                    max_fine_usd,
                    estimated_fine_usd
                FROM forgescan_security.estimate_compliance_fine(
                    :data_sensitivity,
                    :max_records,
                    :frameworks::TEXT[]
                );
            """)
            
            result = await self.session.execute(query, {
                "data_sensitivity": data_sensitivity,
                "max_records": max_records,
                "frameworks": frameworks
            })
            rows = result.fetchall()
            
            fines = [
                {
                    "framework": row[0],
                    "max_fine_usd": float(row[1]),
                    "estimated_fine_usd": float(row[2]),
                }
                for row in rows
            ]
            
            return fines
            
        except Exception as e:
            logger.error(f"Error estimating compliance fines: {e}")
            raise
    
    async def tag_asset(
        self,
        tenant_id: str,
        schema_name: str,
        table_name: str,
        asset_type: AssetType,
        data_sensitivity: DataSensitivity,
        downtime_cost_per_hour: int,
        compliance_frameworks: List[str]
    ) -> str:
        """
        Tag a database table with business context.
        
        This is the critical step: without asset tagging, the system is blind
        to business impact and cannot calculate proper priorities.
        
        Args:
            tenant_id: UUID of tenant
            schema_name: PostgreSQL schema name
            table_name: PostgreSQL table name
            asset_type: REVENUE, COMPLIANCE, OPERATIONAL, ANALYTICS, ARCHIVE
            data_sensitivity: PUBLIC, INTERNAL, PII, PCI, PHI
            downtime_cost_per_hour: USD/hour loss if breached
            compliance_frameworks: List of frameworks (GDPR, PCI-DSS, HIPAA, etc.)
        
        Returns:
            asset_id (UUID)
        """
        try:
            query = text("""
                SELECT forgescan_security.tag_business_asset(
                    :tenant_id::UUID,
                    :schema_name,
                    :table_name,
                    :asset_type,
                    :data_sensitivity,
                    :downtime_cost_per_hour,
                    :frameworks::TEXT[]
                );
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "schema_name": schema_name,
                "table_name": table_name,
                "asset_type": asset_type.value,
                "data_sensitivity": data_sensitivity.value,
                "downtime_cost_per_hour": downtime_cost_per_hour,
                "frameworks": compliance_frameworks
            })
            
            asset_id = result.scalar()
            logger.info(f"Tagged asset {schema_name}.{table_name} with ID {asset_id}")
            return str(asset_id)
            
        except Exception as e:
            logger.error(f"Error tagging asset: {e}")
            raise
    
    async def get_business_assets(self, tenant_id: str) -> List[Dict[str, Any]]:
        """
        Fetch all business assets for a tenant.
        
        Returns list of tagged assets with their business context.
        """
        try:
            query = text("""
                SELECT 
                    asset_id,
                    schema_name,
                    table_name,
                    asset_type,
                    data_sensitivity,
                    downtime_cost_per_hour,
                    max_exposure_records,
                    criticality_score,
                    compliance_frameworks,
                    data_owner,
                    description
                FROM forgescan_security.business_assets
                WHERE tenant_id = :tenant_id::UUID
                ORDER BY downtime_cost_per_hour DESC;
            """)
            
            result = await self.session.execute(query, {"tenant_id": str(tenant_id)})
            rows = result.fetchall()
            
            assets = [
                {
                    "asset_id": str(row[0]),
                    "schema_name": row[1],
                    "table_name": row[2],
                    "asset_type": row[3],
                    "data_sensitivity": row[4],
                    "downtime_cost_per_hour": row[5],
                    "max_exposure_records": row[6],
                    "criticality_score": row[7],
                    "compliance_frameworks": row[8] or [],
                    "data_owner": row[9],
                    "description": row[10],
                }
                for row in rows
            ]
            
            return assets
            
        except Exception as e:
            logger.error(f"Error fetching business assets: {e}")
            raise
    
    async def get_remediation_rules(self, vuln_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch remediation rules, optionally filtered by vulnerability type.
        
        Returns all deterministic rules that map vulnerability + context → priority + action.
        """
        try:
            if vuln_type:
                query = text("""
                    SELECT 
                        rule_id,
                        vuln_type,
                        context_trigger,
                        base_priority_score,
                        revenue_bonus,
                        compliance_bonus,
                        required_action,
                        severity_label,
                        mitigation_time_hours
                    FROM forgescan_security.remediation_rules
                    WHERE vuln_type = :vuln_type
                    ORDER BY base_priority_score DESC;
                """)
                result = await self.session.execute(query, {"vuln_type": vuln_type})
            else:
                query = text("""
                    SELECT 
                        rule_id,
                        vuln_type,
                        context_trigger,
                        base_priority_score,
                        revenue_bonus,
                        compliance_bonus,
                        required_action,
                        severity_label,
                        mitigation_time_hours
                    FROM forgescan_security.remediation_rules
                    ORDER BY base_priority_score DESC;
                """)
                result = await self.session.execute(query)
            
            rows = result.fetchall()
            
            rules = [
                {
                    "rule_id": str(row[0]),
                    "vuln_type": row[1],
                    "context_trigger": row[2],
                    "base_priority_score": row[3],
                    "revenue_bonus": row[4],
                    "compliance_bonus": row[5],
                    "required_action": row[6],
                    "severity_label": row[7],
                    "mitigation_time_hours": row[8],
                }
                for row in rows
            ]
            
            return rules
            
        except Exception as e:
            logger.error(f"Error fetching remediation rules: {e}")
            raise


async def generate_tenant_remediation_summary(
    session: AsyncSession,
    tenant_id: str
) -> Dict[str, Any]:
    """
    Generate a complete remediation summary for a tenant.
    
    Includes:
    - Top priorities (P0 findings)
    - Asset breakdown
    - Compliance exposure
    - Financial risk estimate
    """
    evaluator = BusinessLogicEvaluator(session)
    
    # Get remediation plan
    remediations = await evaluator.generate_remediation_plan(tenant_id)
    
    # Get business assets
    assets = await evaluator.get_business_assets(tenant_id)
    
    # Split by severity
    critical = [r for r in remediations if r["severity"] == "CRITICAL"]
    high = [r for r in remediations if r["severity"] == "HIGH"]
    medium = [r for r in remediations if r["severity"] == "MEDIUM"]
    low = [r for r in remediations if r["severity"] == "LOW"]
    
    # Calculate total downtime cost at risk
    total_downtime_risk = sum(r["downtime_cost_per_hour"] for r in critical) * 1  # 1 hour SLA
    
    # Estimate compliance exposure
    pci_assets = [a for a in assets if a["data_sensitivity"] == "PCI"]
    compliance_fines = {}
    if pci_assets:
        total_pci_records = sum(a["max_exposure_records"] for a in pci_assets)
        fines = await evaluator.estimate_compliance_fines(
            "PCI",
            total_pci_records,
            ["PCI-DSS", "GDPR"]
        )
        compliance_fines = {f["framework"]: f["estimated_fine_usd"] for f in fines}
    
    return {
        "tenant_id": tenant_id,
        "summary": {
            "total_findings": len(remediations),
            "critical_count": len(critical),
            "high_count": len(high),
            "medium_count": len(medium),
            "low_count": len(low),
            "total_assets": len(assets),
        },
        "risk": {
            "total_downtime_risk_usd_1hr": total_downtime_risk,
            "estimated_compliance_fines_usd": compliance_fines,
        },
        "critical_remediations": critical[:10],  # Top 10
        "asset_summary": {
            "revenue_assets": len([a for a in assets if a["asset_type"] == "REVENUE"]),
            "pci_assets": len(pci_assets),
            "compliance_assets": len([a for a in assets if a["asset_type"] == "COMPLIANCE"]),
        },
    }
