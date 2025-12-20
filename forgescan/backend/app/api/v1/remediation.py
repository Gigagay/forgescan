"""
Remediation Planning API

Deterministic endpoints for retrieving remediation plans based on business context.

Endpoints:
- GET /api/v1/remediation/plans/{tenant_id}
- GET /api/v1/remediation/assets
- POST /api/v1/remediation/assets/tag
- GET /api/v1/remediation/summary/{tenant_id}
- GET /api/v1/remediation/rules
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Dict, Any
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.core.auth import get_current_user
from app.remediation.business_evaluator import (
    BusinessLogicEvaluator,
    generate_tenant_remediation_summary
)
from app.db.models.business_context import (
    AssetType,
    DataSensitivity,
)

router = APIRouter(prefix="/api/v1/remediation", tags=["remediation"])


@router.get("/plans/{tenant_id}")
async def get_remediation_plan(
    tenant_id: UUID,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get the deterministic remediation plan for a tenant.
    
    This is the core endpoint that joins:
    - Findings (from scanners)
    - Business Assets (tagged with financial/compliance context)
    - Remediation Rules (deterministic vulnerability → action mapping)
    
    Returns sorted list by priority_rank DESC (highest risk first).
    
    **Priority Calculation:**
    ```
    priority_rank = base_priority
                  + revenue_bonus (if REVENUE asset)
                  + compliance_bonus (if PCI/PII/PHI data)
                  + exposure_multiplier (records × severity)
    ```
    
    **Example Response:**
    ```json
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
          "financial_risk": "CRITICAL: REVENUE LOSS",
          "compliance_obligations": "PCI-DSS, GDPR",
          "downtime_cost_per_hour": 50000,
          "required_action": "Immediate RLS enforcement and full audit",
          "remediation_command": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;",
          "mitigation_sla_hours": 1,
          "severity": "CRITICAL"
        },
        ...
      ]
    }
    ```
    """
    try:
        evaluator = BusinessLogicEvaluator(db)
        remediations = await evaluator.generate_remediation_plan(str(tenant_id))
        
        return {
            "tenant_id": str(tenant_id),
            "plan": remediations,
            "count": len(remediations),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/summary/{tenant_id}")
async def get_remediation_summary(
    tenant_id: UUID,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Get a high-level remediation summary for a tenant.
    
    Includes:
    - Count breakdown by severity (CRITICAL, HIGH, MEDIUM, LOW)
    - Total financial risk exposure
    - Estimated compliance fines
    - Top 10 critical remediations
    - Asset breakdown
    
    **Example Response:**
    ```json
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
      "critical_remediations": [
        { ... }
      ],
      "asset_summary": {
        "revenue_assets": 15,
        "pci_assets": 8,
        "compliance_assets": 12
      }
    }
    ```
    """
    try:
        summary = await generate_tenant_remediation_summary(db, str(tenant_id))
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/assets")
async def list_business_assets(
    tenant_id: UUID = Query(...),
    asset_type: AssetType = Query(None),
    data_sensitivity: DataSensitivity = Query(None),
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all tagged business assets for a tenant.
    
    Optional filters:
    - asset_type: REVENUE, COMPLIANCE, OPERATIONAL, ANALYTICS, ARCHIVE
    - data_sensitivity: PUBLIC, INTERNAL, PII, PCI, PHI
    
    Assets should be tagged BEFORE scanning to enable proper prioritization.
    Without tagging, all vulnerabilities get equal priority (dangerous!).
    """
    try:
        evaluator = BusinessLogicEvaluator(db)
        assets = await evaluator.get_business_assets(str(tenant_id))
        
        # Apply filters if provided
        if asset_type:
            assets = [a for a in assets if a["asset_type"] == asset_type.value]
        if data_sensitivity:
            assets = [a for a in assets if a["data_sensitivity"] == data_sensitivity.value]
        
        return {
            "tenant_id": str(tenant_id),
            "assets": assets,
            "count": len(assets),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/assets/tag")
async def tag_business_asset(
    tenant_id: UUID,
    schema_name: str,
    table_name: str,
    asset_type: AssetType,
    data_sensitivity: DataSensitivity,
    downtime_cost_per_hour: int,
    compliance_frameworks: List[str],
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Tag a database table with business context.
    
    **CRITICAL:** This is the most important call in ForgeScan 2.0.
    Without tagging, the system is blind to business impact.
    
    Args:
    - tenant_id: UUID of tenant
    - schema_name: PostgreSQL schema (e.g., 'public')
    - table_name: PostgreSQL table name (e.g., 'orders')
    - asset_type: REVENUE, COMPLIANCE, OPERATIONAL, ANALYTICS, ARCHIVE
    - data_sensitivity: PUBLIC, INTERNAL, PII, PCI, PHI
    - downtime_cost_per_hour: USD/hour if this table is down (e.g., 50000 for payment processing)
    - compliance_frameworks: List of frameworks (e.g., ['PCI-DSS', 'GDPR'])
    
    **Example Request:**
    ```json
    {
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "schema_name": "public",
      "table_name": "orders",
      "asset_type": "REVENUE",
      "data_sensitivity": "PCI",
      "downtime_cost_per_hour": 50000,
      "compliance_frameworks": ["PCI-DSS", "GDPR"]
    }
    ```
    
    **Response:**
    ```json
    {
      "asset_id": "550e8400-e29b-41d4-a716-446655440001",
      "message": "Asset tagged successfully"
    }
    ```
    """
    try:
        evaluator = BusinessLogicEvaluator(db)
        asset_id = await evaluator.tag_asset(
            tenant_id=str(tenant_id),
            schema_name=schema_name,
            table_name=table_name,
            asset_type=asset_type,
            data_sensitivity=data_sensitivity,
            downtime_cost_per_hour=downtime_cost_per_hour,
            compliance_frameworks=compliance_frameworks,
        )
        
        await db.commit()
        
        return {
            "asset_id": asset_id,
            "message": f"Asset {schema_name}.{table_name} tagged successfully",
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/rules")
async def list_remediation_rules(
    vuln_type: str = Query(None),
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    List all deterministic remediation rules.
    
    Each rule maps a vulnerability type + context trigger to:
    - base_priority_score: Starting priority (e.g., 100 for RLS_BYPASS)
    - revenue_bonus: Additional priority if asset_type == REVENUE
    - compliance_bonus: Additional priority if data_sensitivity == PCI/PII/PHI
    - required_action: What to do (e.g., "Immediate RLS enforcement")
    - mitigation_time_hours: SLA for fix
    
    Optional filter:
    - vuln_type: RLS_BYPASS, WEAK_MASKING, PERFORMANCE_DEGRADATION, etc.
    
    **Example Response:**
    ```json
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
        },
        ...
      ],
      "count": 13
    }
    ```
    """
    try:
        evaluator = BusinessLogicEvaluator(db)
        rules = await evaluator.get_remediation_rules(vuln_type=vuln_type)
        
        return {
            "rules": rules,
            "count": len(rules),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/estimate-fine")
async def estimate_compliance_fine(
    data_sensitivity: str,
    max_records: int,
    frameworks: str = Query(...),  # CSV: "GDPR,HIPAA,PCI-DSS"
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Estimate potential regulatory fines for a data breach.
    
    Uses statutory maximums (GDPR: €20M or 4% revenue; HIPAA: $1.5M+; CCPA: $7.5M).
    
    Args:
    - data_sensitivity: PII, PCI, PHI, etc.
    - max_records: Number of records exposed
    - frameworks: CSV list of frameworks (e.g., "GDPR,HIPAA,PCI-DSS")
    
    **Example Request:**
    ```
    GET /api/v1/remediation/estimate-fine?data_sensitivity=PCI&max_records=500000&frameworks=PCI-DSS,GDPR
    ```
    
    **Response:**
    ```json
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
    """
    try:
        evaluator = BusinessLogicEvaluator(db)
        framework_list = [f.strip() for f in frameworks.split(",")]
        
        fines = await evaluator.estimate_compliance_fines(
            data_sensitivity=data_sensitivity,
            max_records=max_records,
            frameworks=framework_list,
        )
        
        total_fine = sum(f["estimated_fine_usd"] for f in fines)
        
        return {
            "exposure": {
                "data_sensitivity": data_sensitivity,
                "estimated_records_exposed": max_records,
            },
            "fines": fines,
            "total_fine_usd": total_fine,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
