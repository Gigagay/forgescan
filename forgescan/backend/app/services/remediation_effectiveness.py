"""
Phase 8: Remediation Effectiveness Service

Tracks remediation outcomes, SLA compliance, and recurrence trends.

Purpose:
- Prove that fixes actually work
- Identify recurring vulnerabilities
- Enable SLA reporting and trend analysis
"""
from typing import Dict, Any, Optional, List
from uuid import UUID
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class RemediationEffectivenessService:
    """
    Service layer for remediation effectiveness tracking.
    
    Metrics tracked:
    - Time to fix (SLA compliance)
    - Recurrence rate (recurring vulns)
    - Trend analysis (improving or regressing)
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def record_remediation(
        self,
        tenant_id: str,
        vuln_type: str,
        asset_name: str,
        severity: str,
        first_detected: str,
        sla_target_hours: int,
        remediation_command: str
    ) -> str:
        """
        Record initial detection of a vulnerability (start of remediation tracking).
        
        Args:
            tenant_id: UUID of tenant
            vuln_type: RLS_BYPASS, WEAK_MASKING, etc.
            asset_name: e.g., public.orders
            severity: CRITICAL, HIGH, MEDIUM, LOW
            first_detected: ISO datetime string
            sla_target_hours: From remediation_rules
            remediation_command: SQL/code to fix
        
        Returns:
            remediation_id (UUID)
        """
        try:
            query = text("""
                INSERT INTO forgescan_security.remediation_effectiveness(
                    tenant_id, vuln_type, asset_name, severity, first_detected, sla_target_hours, remediation_command
                ) VALUES (
                    :tenant_id::UUID, :vuln_type, :asset_name, :severity,
                    :first_detected::TIMESTAMPTZ, :sla_target_hours, :remediation_command
                ) RETURNING remediation_id
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "vuln_type": vuln_type,
                "asset_name": asset_name,
                "severity": severity,
                "first_detected": first_detected,
                "sla_target_hours": sla_target_hours,
                "remediation_command": remediation_command
            })
            
            remediation_id = result.scalar()
            
            logger.info(f"Remediation tracked: {vuln_type} on {asset_name}, SLA={sla_target_hours}h")
            
            return str(remediation_id)
            
        except Exception as e:
            logger.error(f"Error recording remediation: {e}")
            raise
    
    async def mark_remediation_fixed(
        self,
        remediation_id: str,
        fixed_at: str
    ) -> Dict[str, Any]:
        """
        Mark a remediation as fixed and calculate SLA metrics.
        
        Args:
            remediation_id: UUID of remediation record
            fixed_at: ISO datetime string when fix was applied
        
        Returns:
        {
            "remediation_id": "...",
            "time_to_fix_hours": 4.5,
            "sla_target_hours": 4,
            "sla_met": false,
            "status": "FIXED_MISSED_SLA"
        }
        """
        try:
            query = text("""
                UPDATE forgescan_security.remediation_effectiveness
                SET fixed_at = :fixed_at::TIMESTAMPTZ,
                    time_to_fix_hours = EXTRACT(EPOCH FROM (:fixed_at::TIMESTAMPTZ - first_detected)) / 3600,
                    sla_met = EXTRACT(EPOCH FROM (:fixed_at::TIMESTAMPTZ - first_detected)) / 3600 <= sla_target_hours,
                    last_verified_at = NOW()
                WHERE remediation_id = :remediation_id::UUID
                RETURNING remediation_id, time_to_fix_hours, sla_target_hours, sla_met
            """)
            
            result = await self.session.execute(query, {
                "remediation_id": str(remediation_id),
                "fixed_at": fixed_at
            })
            
            row = result.fetchone()
            
            if not row:
                raise ValueError(f"Remediation not found: {remediation_id}")
            
            remediation_id_ret, time_to_fix, sla_target, sla_met = row
            
            status = "FIXED_MET_SLA" if sla_met else "FIXED_MISSED_SLA"
            
            logger.info(
                f"Remediation fixed: {remediation_id} in {time_to_fix:.1f}h "
                f"(SLA {sla_target}h): {status}"
            )
            
            return {
                "remediation_id": str(remediation_id_ret),
                "time_to_fix_hours": float(time_to_fix),
                "sla_target_hours": sla_target,
                "sla_met": bool(sla_met),
                "status": status
            }
            
        except Exception as e:
            logger.error(f"Error marking remediation fixed: {e}")
            raise
    
    async def record_recurrence(
        self,
        remediation_id: str
    ) -> Dict[str, Any]:
        """
        Record that a previously-fixed vulnerability has recurred.
        
        Increments recurrence_count and resets first_detected and fixed_at.
        
        Returns:
        {
            "remediation_id": "...",
            "recurrence_count": 2,
            "severity": "RECURRING_ISSUE"
        }
        """
        try:
            query = text("""
                UPDATE forgescan_security.remediation_effectiveness
                SET recurrence_count = recurrence_count + 1,
                    first_detected = NOW(),
                    fixed_at = NULL,
                    time_to_fix_hours = NULL,
                    sla_met = NULL
                WHERE remediation_id = :remediation_id::UUID
                RETURNING remediation_id, recurrence_count, vuln_type
            """)
            
            result = await self.session.execute(query, {
                "remediation_id": str(remediation_id)
            })
            
            row = result.fetchone()
            
            if not row:
                raise ValueError(f"Remediation not found: {remediation_id}")
            
            remediation_id_ret, recurrence_count, vuln_type = row
            
            logger.warning(
                f"Remediation recurred: {remediation_id} ({vuln_type}) "
                f"- occurrence #{recurrence_count}"
            )
            
            return {
                "remediation_id": str(remediation_id_ret),
                "recurrence_count": recurrence_count,
                "vuln_type": vuln_type,
                "status": "RECURRING_ISSUE"
            }
            
        except Exception as e:
            logger.error(f"Error recording recurrence: {e}")
            raise
    
    async def get_sla_metrics(
        self,
        tenant_id: str
    ) -> Dict[str, Any]:
        """
        Get SLA performance metrics for a tenant.
        
        Returns:
        {
            "tenant_id": "...",
            "total_remediated": 42,
            "sla_met_count": 38,
            "sla_compliance_pct": 90.48,
            "avg_time_to_fix_hours": 2.3,
            "max_time_to_fix_hours": 12.5,
            "recurring_issues": 4
        }
        """
        try:
            query = text("""
                SELECT
                    total_remediated,
                    sla_met_count,
                    sla_compliance_pct,
                    avg_time_to_fix_hours,
                    max_time_to_fix_hours,
                    recurrence_count
                FROM forgescan_security.metrics_sla_performance
                WHERE tenant_id = :tenant_id::UUID
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id)
            })
            
            row = result.fetchone()
            
            if not row:
                return {
                    "tenant_id": str(tenant_id),
                    "total_remediated": 0,
                    "sla_met_count": 0,
                    "sla_compliance_pct": 0.0,
                    "avg_time_to_fix_hours": None,
                    "max_time_to_fix_hours": None,
                    "recurring_issues": 0
                }
            
            total, met, pct, avg_hours, max_hours, recurrence = row
            
            return {
                "tenant_id": str(tenant_id),
                "total_remediated": total or 0,
                "sla_met_count": met or 0,
                "sla_compliance_pct": float(pct) if pct else 0.0,
                "avg_time_to_fix_hours": float(avg_hours) if avg_hours else None,
                "max_time_to_fix_hours": float(max_hours) if max_hours else None,
                "recurring_issues": recurrence or 0
            }
            
        except Exception as e:
            logger.error(f"Error fetching SLA metrics: {e}")
            raise
    
    async def get_remediation_history(
        self,
        tenant_id: str,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Get detailed remediation history for a tenant.
        
        Returns list of all remediation records sorted by first_detected DESC.
        """
        try:
            query = text("""
                SELECT
                    remediation_id, vuln_type, asset_name, severity, first_detected, fixed_at,
                    recurrence_count, time_to_fix_hours, sla_met, sla_target_hours
                FROM forgescan_security.remediation_effectiveness
                WHERE tenant_id = :tenant_id::UUID
                ORDER BY first_detected DESC
                LIMIT :limit
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "limit": limit
            })
            
            rows = result.fetchall()
            
            history = [
                {
                    "remediation_id": str(row[0]),
                    "vuln_type": row[1],
                    "asset_name": row[2],
                    "severity": row[3],
                    "first_detected": row[4].isoformat() if row[4] else None,
                    "fixed_at": row[5].isoformat() if row[5] else None,
                    "recurrence_count": row[6] or 0,
                    "time_to_fix_hours": float(row[7]) if row[7] else None,
                    "sla_met": row[8],
                    "sla_target_hours": row[9],
                }
                for row in rows
            ]
            
            return history
            
        except Exception as e:
            logger.error(f"Error fetching remediation history: {e}")
            raise
    
    async def identify_recurring_vulnerabilities(
        self,
        tenant_id: str,
        min_recurrence: int = 2
    ) -> List[Dict[str, Any]]:
        """
        Identify vulnerability types that recur frequently (regression indicator).
        
        Args:
            tenant_id: UUID of tenant
            min_recurrence: Min recurrence count to flag (default 2)
        
        Returns: List of recurring vuln types with counts
        """
        try:
            query = text("""
                SELECT vuln_type, COUNT(*) as count, SUM(recurrence_count) as total_recurrences
                FROM forgescan_security.remediation_effectiveness
                WHERE tenant_id = :tenant_id::UUID AND recurrence_count >= :min_recurrence
                GROUP BY vuln_type
                ORDER BY total_recurrences DESC
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "min_recurrence": min_recurrence
            })
            
            rows = result.fetchall()
            
            recurring = [
                {
                    "vuln_type": row[0],
                    "issue_count": row[1],
                    "total_recurrences": row[2],
                }
                for row in rows
            ]
            
            if recurring:
                logger.warning(f"Recurring vulnerabilities detected: {recurring}")
            
            return recurring
            
        except Exception as e:
            logger.error(f"Error identifying recurring vulnerabilities: {e}")
            raise


async def get_remediation_effectiveness_service(session: AsyncSession) -> RemediationEffectivenessService:
    """Dependency for FastAPI to inject remediation effectiveness service."""
    return RemediationEffectivenessService(session)
