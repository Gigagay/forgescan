"""
Phase 7: Enforcement Service

Bridges database-level enforcement gates to API layer.
All decisions are deterministic and auditable.
"""
from typing import Dict, Any, Optional
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)


class EnforcementService:
    """
    Service layer for CI/CD enforcement decisions.
    
    Philosophy:
    - Database calculates the decision
    - Backend transports it
    - CI tools consume it
    - Audit logs prove it
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def enforce_release_gate(
        self,
        tenant_id: str,
        pipeline_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Determine release gate decision (BLOCK, ALLOW_WITH_ACK, ALLOW, INFO).
        
        This is the core function called by CI/CD systems.
        
        Returns:
        {
            "decision": "BLOCK|ALLOW_WITH_ACK|ALLOW|INFO",
            "max_priority": 120,
            "enforcement_level": "HARD_FAIL|SOFT_FAIL|WARN|INFO",
            "reason": "Critical business risk detected..."
        }
        """
        try:
            query = text("""
                SELECT decision, max_priority, enforcement_level, reason
                FROM forgescan_security.enforce_release_gate(:tenant_id, :pipeline_id)
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "pipeline_id": pipeline_id
            })
            row = result.fetchone()
            
            if not row:
                return {
                    "decision": "ERROR",
                    "max_priority": None,
                    "enforcement_level": "ERROR",
                    "reason": "Failed to evaluate enforcement gate"
                }
            
            decision, max_priority, enforcement_level, reason = row
            
            # Log this decision
            decision_id = await self.log_enforcement_decision(
                tenant_id=tenant_id,
                pipeline_id=pipeline_id,
                decision=decision,
                max_priority=max_priority,
                enforcement_level=enforcement_level,
                reason=reason
            )
            
            logger.info(f"Enforcement gate: tenant={tenant_id}, decision={decision}, priority={max_priority}")
            
            return {
                "decision": decision,
                "max_priority": max_priority,
                "enforcement_level": enforcement_level,
                "reason": reason,
                "decision_id": str(decision_id)
            }
            
        except Exception as e:
            logger.error(f"Error evaluating enforcement gate: {e}")
            raise
    
    async def log_enforcement_decision(
        self,
        tenant_id: str,
        pipeline_id: Optional[str],
        decision: str,
        max_priority: int,
        enforcement_level: str,
        reason: str,
        asset_at_risk: Optional[str] = None,
        financial_risk_usd: Optional[float] = None,
        required_action: Optional[str] = None
    ) -> UUID:
        """
        Audit log the enforcement decision to immutable trail.
        """
        try:
            query = text("""
                SELECT forgescan_security.log_enforcement_decision(
                    :tenant_id::UUID,
                    :pipeline_id,
                    :decision,
                    :max_priority,
                    :enforcement_level,
                    :reason,
                    :asset_at_risk,
                    :financial_risk_usd,
                    :required_action
                )
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "pipeline_id": pipeline_id,
                "decision": decision,
                "max_priority": max_priority,
                "enforcement_level": enforcement_level,
                "reason": reason,
                "asset_at_risk": asset_at_risk,
                "financial_risk_usd": financial_risk_usd,
                "required_action": required_action
            })
            
            decision_id = result.scalar()
            return decision_id
            
        except Exception as e:
            logger.error(f"Error logging enforcement decision: {e}")
            raise
    
    async def check_enforcement_quota(self, tenant_id: str) -> Dict[str, Any]:
        """
        Check if tenant has enforcement quota remaining for this month.
        
        Used for tier-based rate limiting (e.g., free tier = 1 hard fail/month).
        
        Returns:
        {
            "allowed": true,
            "reason": "Quota check passed."
        }
        """
        try:
            query = text("""
                SELECT allowed, reason
                FROM forgescan_security.check_enforcement_quota(:tenant_id::UUID)
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id)
            })
            row = result.fetchone()
            
            if not row:
                return {"allowed": False, "reason": "Failed to check quota"}
            
            allowed, reason = row
            
            logger.info(f"Quota check: tenant={tenant_id}, allowed={allowed}")
            
            return {
                "allowed": bool(allowed),
                "reason": reason
            }
            
        except Exception as e:
            logger.error(f"Error checking enforcement quota: {e}")
            raise
    
    async def get_enforcement_history(
        self,
        tenant_id: str,
        limit: int = 100
    ) -> list:
        """
        Retrieve enforcement decision history for audit/compliance.
        
        Returns recent enforcement decisions in DESC order by timestamp.
        """
        try:
            query = text("""
                SELECT 
                    decision_id,
                    pipeline_id,
                    max_priority,
                    enforcement_level,
                    decision,
                    reason,
                    asset_at_risk,
                    financial_risk_usd,
                    required_action,
                    decided_at,
                    acked_by,
                    acked_at
                FROM forgescan_security.enforcement_decisions
                WHERE tenant_id = :tenant_id::UUID
                ORDER BY decided_at DESC
                LIMIT :limit
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "limit": limit
            })
            
            rows = result.fetchall()
            
            history = [
                {
                    "decision_id": str(row[0]),
                    "pipeline_id": row[1],
                    "max_priority": row[2],
                    "enforcement_level": row[3],
                    "decision": row[4],
                    "reason": row[5],
                    "asset_at_risk": row[6],
                    "financial_risk_usd": float(row[7]) if row[7] else None,
                    "required_action": row[8],
                    "decided_at": row[9].isoformat() if row[9] else None,
                    "acked_by": str(row[10]) if row[10] else None,
                    "acked_at": row[11].isoformat() if row[11] else None,
                }
                for row in rows
            ]
            
            return history
            
        except Exception as e:
            logger.error(f"Error fetching enforcement history: {e}")
            raise
    
    async def acknowledge_enforcement_decision(
        self,
        decision_id: str,
        acked_by: str
    ) -> bool:
        """
        Record acknowledgement of a SOFT_FAIL enforcement decision.
        
        Used when deploying with high-priority findings requires explicit approval.
        """
        try:
            query = text("""
                UPDATE forgescan_security.enforcement_decisions
                SET acked_by = :acked_by::UUID,
                    acked_at = NOW()
                WHERE decision_id = :decision_id::UUID
                RETURNING TRUE
            """)
            
            result = await self.session.execute(query, {
                "decision_id": str(decision_id),
                "acked_by": str(acked_by)
            })
            
            success = result.scalar()
            
            if success:
                logger.info(f"Decision {decision_id} acknowledged by {acked_by}")
            
            return bool(success)
            
        except Exception as e:
            logger.error(f"Error acknowledging decision: {e}")
            raise


async def get_enforcement_service(session: AsyncSession) -> EnforcementService:
    """Dependency for FastAPI to inject enforcement service."""
    return EnforcementService(session)
