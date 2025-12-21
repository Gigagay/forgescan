"""
Phase 7: Enforcement API Endpoints

CI/CD integration points for release gating.

Endpoints:
- GET /api/v1/enforce/gate - Main gate decision
- GET /api/v1/enforce/decision/{decision_id} - Lookup decision
- GET /api/v1/enforce/history - Audit trail
- POST /api/v1/enforce/acknowledge - Acknowledge soft fails
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, Any
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.core.auth import get_current_user
from app.services.enforcement_service import EnforcementService

router = APIRouter(prefix="/api/v1/enforce", tags=["enforcement"])


@router.get("/gate")
async def get_release_gate(
    tenant_id: UUID,
    pipeline_id: str = Query(None),
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Main CI/CD gate endpoint.
    
    Determines whether a release should be blocked based on business-impact priorities.
    
    Query Parameters:
    - tenant_id: UUID of tenant
    - pipeline_id: Optional identifier for CI pipeline (Jenkins job ID, GitHub Actions run, etc.)
    
    Returns:
    ```json
    {
      "decision": "BLOCK|ALLOW_WITH_ACK|ALLOW|INFO",
      "max_priority": 120,
      "enforcement_level": "HARD_FAIL|SOFT_FAIL|WARN|INFO",
      "reason": "Critical business risk detected (revenue/compliance impact)",
      "decision_id": "550e8400-e29b-41d4-a716-446655440000"
    }
    ```
    
    Decision Semantics:
    - BLOCK (≥100): Deployment blocked. Requires remediation.
    - ALLOW_WITH_ACK (80-99): Deployment allowed, but requires explicit acknowledgement.
    - WARN (60-79): No block, but visible in dashboard.
    - ALLOW (<60): No action needed.
    
    Example Usage in GitHub Actions:
    ```yaml
    - name: ForgeScan Release Gate
      run: |
        RESPONSE=$(curl -s -H "Authorization: Bearer $FORGESCAN_TOKEN" \\
          "https://api.forgescan.io/enforce/gate?tenant_id=$TENANT_ID&pipeline_id=$GITHUB_RUN_ID")
        DECISION=$(echo $RESPONSE | jq -r '.decision')
        if [ "$DECISION" = "BLOCK" ]; then
          echo "❌ Deployment blocked by ForgeScan"
          exit 1
        fi
    ```
    """
    try:
        enforcement_service = EnforcementService(db)
        result = await enforcement_service.enforce_release_gate(
            tenant_id=str(tenant_id),
            pipeline_id=pipeline_id
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/history")
async def get_enforcement_history(
    tenant_id: UUID,
    limit: int = Query(100, ge=1, le=1000),
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Fetch enforcement decision history for audit/compliance.
    
    Returns recent enforcement decisions (most recent first) with full details.
    
    Query Parameters:
    - tenant_id: UUID of tenant
    - limit: Max results (default 100, max 1000)
    
    Returns:
    ```json
    {
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "decisions": [
        {
          "decision_id": "550e8400-e29b-41d4-a716-446655440001",
          "pipeline_id": "jenkins-build-123",
          "max_priority": 120,
          "enforcement_level": "HARD_FAIL",
          "decision": "BLOCK",
          "reason": "Critical business risk detected",
          "asset_at_risk": "public.orders",
          "financial_risk_usd": 50000,
          "required_action": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;",
          "decided_at": "2025-12-21T10:30:00Z",
          "acked_by": null,
          "acked_at": null
        }
      ],
      "count": 1
    }
    ```
    
    Use Cases:
    - Audit compliance officer verification
    - Post-incident analysis
    - SLA tracking
    """
    try:
        enforcement_service = EnforcementService(db)
        history = await enforcement_service.get_enforcement_history(
            tenant_id=str(tenant_id),
            limit=limit
        )
        
        return {
            "tenant_id": str(tenant_id),
            "decisions": history,
            "count": len(history),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/acknowledge")
async def acknowledge_soft_fail(
    decision_id: UUID,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Record explicit acknowledgement of a SOFT_FAIL enforcement decision.
    
    Used when deploying with high-priority findings (80-99) requires human approval.
    
    Semantics:
    - Soft fails do not block deployment, but require acknowledgement.
    - This creates an audit trail for compliance and SLA tracking.
    - If decision has enforcement_level="SOFT_FAIL", acknowledge before deployment.
    
    Body:
    ```json
    {
      "decision_id": "550e8400-e29b-41d4-a716-446655440001"
    }
    ```
    
    Returns:
    ```json
    {
      "success": true,
      "message": "Decision acknowledged by user@example.com",
      "decision_id": "550e8400-e29b-41d4-a716-446655440001"
    }
    ```
    """
    try:
        enforcement_service = EnforcementService(db)
        success = await enforcement_service.acknowledge_enforcement_decision(
            decision_id=str(decision_id),
            acked_by=current_user
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Decision not found")
        
        await db.commit()
        
        return {
            "success": True,
            "message": f"Decision acknowledged by {current_user}",
            "decision_id": str(decision_id),
        }
    except Exception as e:
        await db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/quota")
async def check_enforcement_quota(
    tenant_id: UUID,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Check if tenant has enforcement quota remaining for this month.
    
    Tier-based rate limiting (free tier = 1 hard fail/month, startup+ = unlimited).
    
    Query Parameters:
    - tenant_id: UUID of tenant
    
    Returns:
    ```json
    {
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "allowed": true,
      "reason": "Quota check passed.",
      "tier": "STARTUP"
    }
    ```
    
    Reasons:
    - "Quota check passed." → Enforce as normal
    - "Hard fail quota exhausted for this month. Upgrade to remove limits." → Tier needs upgrade
    
    Monetization Note:
    - Free tier: 1 HARD_FAIL block per calendar month
    - Startup+: Unlimited enforcement
    - This aligns with "security should be accessible, enforcement should be earned"
    """
    try:
        enforcement_service = EnforcementService(db)
        result = await enforcement_service.check_enforcement_quota(str(tenant_id))
        
        # Fetch tier for additional context
        from sqlalchemy import text
        tier_result = await db.execute(
            text("SELECT operational_tier FROM forgescan_security.tenant_registry WHERE tenant_id = :tenant_id"),
            {"tenant_id": str(tenant_id)}
        )
        tier_row = tier_result.fetchone()
        tier = tier_row[0] if tier_row else "STARTUP"
        
        return {
            "tenant_id": str(tenant_id),
            "allowed": result["allowed"],
            "reason": result["reason"],
            "tier": tier,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/decision/{decision_id}")
async def get_enforcement_decision(
    decision_id: UUID,
    current_user: str = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """
    Lookup a specific enforcement decision by ID.
    
    Path Parameters:
    - decision_id: UUID of the enforcement decision
    
    Returns:
    ```json
    {
      "decision_id": "550e8400-e29b-41d4-a716-446655440001",
      "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
      "pipeline_id": "jenkins-build-123",
      "max_priority": 120,
      "enforcement_level": "HARD_FAIL",
      "decision": "BLOCK",
      "reason": "Critical business risk detected (revenue/compliance impact)",
      "asset_at_risk": "public.orders",
      "financial_risk_usd": 50000,
      "required_action": "ALTER TABLE public.orders FORCE ROW LEVEL SECURITY;",
      "decided_at": "2025-12-21T10:30:00Z",
      "acked_by": null,
      "acked_at": null
    }
    ```
    
    Use Cases:
    - CI system logs decision ID for traceability
    - On-call engineer queries this to understand why build was blocked
    - Compliance auditor verifies decision
    """
    try:
        from sqlalchemy import text
        
        query = text("""
            SELECT 
                decision_id, tenant_id, pipeline_id, max_priority, enforcement_level, decision,
                reason, asset_at_risk, financial_risk_usd, required_action, decided_at, acked_by, acked_at
            FROM forgescan_security.enforcement_decisions
            WHERE decision_id = :decision_id
        """)
        
        result = await db.execute(query, {"decision_id": str(decision_id)})
        row = result.fetchone()
        
        if not row:
            raise HTTPException(status_code=404, detail="Decision not found")
        
        return {
            "decision_id": str(row[0]),
            "tenant_id": str(row[1]),
            "pipeline_id": row[2],
            "max_priority": row[3],
            "enforcement_level": row[4],
            "decision": row[5],
            "reason": row[6],
            "asset_at_risk": row[7],
            "financial_risk_usd": float(row[8]) if row[8] else None,
            "required_action": row[9],
            "decided_at": row[10].isoformat() if row[10] else None,
            "acked_by": str(row[11]) if row[11] else None,
            "acked_at": row[12].isoformat() if row[12] else None,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
