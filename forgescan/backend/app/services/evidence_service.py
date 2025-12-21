"""
Phase 8: Evidence Service

Manages immutable evidence ledger for audit, compliance, and trust.

Philosophy:
- Everything is logged
- Nothing is deleted
- Evidence hashes provide immutable proof
- Auditors can verify what happened, when, and why
"""
from typing import Dict, Any, Optional, List
from uuid import UUID
import json
import hashlib
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
import logging

logger = logging.getLogger(__name__)


class EvidenceService:
    """
    Service layer for immutable evidence ledger.
    
    Evidence Types:
    - SCAN: Scan evidence (what was tested)
    - ENFORCEMENT: Enforcement decision (why was it blocked)
    - REMEDIATION: Remediation applied (what was fixed)
    - CI_DECISION: CI/CD decision (gate outcome)
    """
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    @staticmethod
    def compute_hash(payload: Dict[str, Any]) -> str:
        """Compute SHA256 hash of payload for immutability proof."""
        payload_json = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(payload_json.encode()).hexdigest()
    
    async def log_evidence(
        self,
        tenant_id: str,
        evidence_type: str,
        related_entity: str,
        payload: Dict[str, Any]
    ) -> str:
        """
        Log evidence to immutable ledger (append-only).
        
        Args:
            tenant_id: UUID of tenant
            evidence_type: SCAN | ENFORCEMENT | REMEDIATION | CI_DECISION
            related_entity: Reference identifier (e.g., "scan_id:123")
            payload: Full context (JSON, immutable)
        
        Returns:
            evidence_id (UUID)
        """
        try:
            # Compute hash for immutability
            payload_hash = self.compute_hash(payload)
            
            query = text("""
                SELECT forgescan_security.log_evidence(
                    :tenant_id::UUID,
                    :evidence_type,
                    :related_entity,
                    :payload::JSONB
                )
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "evidence_type": evidence_type,
                "related_entity": related_entity,
                "payload": json.dumps(payload)
            })
            
            evidence_id = result.scalar()
            
            logger.info(
                f"Evidence logged: type={evidence_type}, entity={related_entity}, "
                f"hash={payload_hash[:16]}..., id={evidence_id}"
            )
            
            return str(evidence_id)
            
        except Exception as e:
            logger.error(f"Error logging evidence: {e}")
            raise
    
    async def query_evidence(
        self,
        tenant_id: str,
        evidence_type: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """
        Query evidence ledger (immutable read-only).
        
        Returns evidence in DESC order by created_at (most recent first).
        
        Args:
            tenant_id: UUID of tenant
            evidence_type: Filter by type (SCAN, ENFORCEMENT, REMEDIATION, CI_DECISION)
            limit: Max results (default 100)
        
        Returns:
            List of evidence records with payload
        """
        try:
            query = text("""
                SELECT evidence_id, evidence_type, related_entity, hash, created_at, payload
                FROM forgescan_security.query_evidence(
                    :tenant_id::UUID,
                    :evidence_type,
                    :limit
                )
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "evidence_type": evidence_type,
                "limit": limit
            })
            
            rows = result.fetchall()
            
            evidence_list = [
                {
                    "evidence_id": str(row[0]),
                    "evidence_type": row[1],
                    "related_entity": row[2],
                    "hash": row[3],
                    "created_at": row[4].isoformat() if row[4] else None,
                    "payload": row[5] or {},
                }
                for row in rows
            ]
            
            return evidence_list
            
        except Exception as e:
            logger.error(f"Error querying evidence: {e}")
            raise
    
    async def verify_evidence_integrity(
        self,
        evidence_id: str,
        expected_payload: Dict[str, Any]
    ) -> bool:
        """
        Verify evidence integrity by comparing computed hash to stored hash.
        
        Used by auditors to prove evidence hasn't been tampered with.
        
        Returns: True if hashes match, False otherwise
        """
        try:
            query = text("""
                SELECT hash FROM forgescan_security.evidence_ledger
                WHERE evidence_id = :evidence_id::UUID
            """)
            
            result = await self.session.execute(query, {"evidence_id": str(evidence_id)})
            row = result.fetchone()
            
            if not row:
                logger.warning(f"Evidence not found: {evidence_id}")
                return False
            
            stored_hash = row[0]
            computed_hash = self.compute_hash(expected_payload)
            
            is_valid = stored_hash == computed_hash
            
            if is_valid:
                logger.info(f"Evidence integrity verified: {evidence_id}")
            else:
                logger.warning(f"Evidence integrity FAILED: {evidence_id}")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Error verifying evidence integrity: {e}")
            raise
    
    async def get_evidence_by_entity(
        self,
        tenant_id: str,
        related_entity: str
    ) -> List[Dict[str, Any]]:
        """
        Get all evidence related to a specific entity (e.g., scan_id:123).
        
        Useful for reconstructing complete history of a single finding.
        """
        try:
            query = text("""
                SELECT evidence_id, evidence_type, related_entity, hash, created_at, payload
                FROM forgescan_security.evidence_ledger
                WHERE tenant_id = :tenant_id::UUID AND related_entity = :related_entity
                ORDER BY created_at DESC
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "related_entity": related_entity
            })
            
            rows = result.fetchall()
            
            evidence_list = [
                {
                    "evidence_id": str(row[0]),
                    "evidence_type": row[1],
                    "related_entity": row[2],
                    "hash": row[3],
                    "created_at": row[4].isoformat() if row[4] else None,
                    "payload": row[5] or {},
                }
                for row in rows
            ]
            
            return evidence_list
            
        except Exception as e:
            logger.error(f"Error querying evidence by entity: {e}")
            raise
    
    async def export_audit_trail(
        self,
        tenant_id: str,
        date_from: Optional[str] = None,
        date_to: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Export complete audit trail for compliance/legal discovery.
        
        Returns:
        {
            "tenant_id": "...",
            "export_date": "2025-12-21T10:30:00Z",
            "date_range": {"from": "...", "to": "..."},
            "evidence_count": 1234,
            "evidence": [...]
        }
        """
        try:
            query = text("""
                SELECT evidence_id, evidence_type, related_entity, hash, created_at, payload
                FROM forgescan_security.evidence_ledger
                WHERE tenant_id = :tenant_id::UUID
                  AND (CAST(:date_from AS TIMESTAMPTZ) IS NULL OR created_at >= CAST(:date_from AS TIMESTAMPTZ))
                  AND (CAST(:date_to AS TIMESTAMPTZ) IS NULL OR created_at <= CAST(:date_to AS TIMESTAMPTZ))
                ORDER BY created_at DESC
            """)
            
            result = await self.session.execute(query, {
                "tenant_id": str(tenant_id),
                "date_from": date_from,
                "date_to": date_to
            })
            
            rows = result.fetchall()
            
            evidence_list = [
                {
                    "evidence_id": str(row[0]),
                    "evidence_type": row[1],
                    "related_entity": row[2],
                    "hash": row[3],
                    "created_at": row[4].isoformat() if row[4] else None,
                    "payload": row[5] or {},
                }
                for row in rows
            ]
            
            from datetime import datetime
            
            return {
                "tenant_id": str(tenant_id),
                "export_date": datetime.utcnow().isoformat() + "Z",
                "date_range": {
                    "from": date_from,
                    "to": date_to
                },
                "evidence_count": len(evidence_list),
                "evidence": evidence_list
            }
            
        except Exception as e:
            logger.error(f"Error exporting audit trail: {e}")
            raise


async def get_evidence_service(session: AsyncSession) -> EvidenceService:
    """Dependency for FastAPI to inject evidence service."""
    return EvidenceService(session)
