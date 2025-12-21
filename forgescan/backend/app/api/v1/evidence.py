"""
Phase 8: Evidence API Endpoints

Provides immutable evidence ledger queries and artifact exports.

Purpose:
- Query audit trail for compliance investigations
- Verify integrity of logged evidence (hash verification)
- Export full audit history for legal discovery
- Reconstruct entity history for forensics
"""
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

from app.db.session import get_db
from app.services.evidence_service import EvidenceService, get_evidence_service
from app.core.auth import verify_token

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/evidence",
    tags=["evidence"],
    dependencies=[Depends(verify_token)]
)


@router.get(
    "",
    summary="Query Evidence Ledger",
    description="""
    Query the immutable evidence ledger with filters.
    
    Returns paginated evidence records with SHA256 hashes for integrity verification.
    
    Typical Flow:
    1. Auditor queries: GET /evidence?evidence_type=ENFORCEMENT
    2. System returns list with hash: hash: "9a3d5c..."
    3. For critical evidence, auditor calls verify endpoint
    4. If hash matches, evidence is proven unaltered
    """
)
async def query_evidence(
    evidence_type: Optional[str] = Query(None, description="Filter by type: SCAN, ENFORCEMENT, REMEDIATION, CI_DECISION"),
    entity_type: Optional[str] = Query(None, description="Filter by entity type: vulnerability, asset, remediation"),
    limit: int = Query(100, ge=1, le=500, description="Max records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    service: EvidenceService = Depends(get_evidence_service),
    session: AsyncSession = Depends(get_db),
    current_tenant: str = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Retrieve evidence ledger entries with optional filtering.
    
    Query Parameters:
    - evidence_type: SCAN (what was scanned), ENFORCEMENT (why blocked), REMEDIATION (what fixed), CI_DECISION (gate outcome)
    - entity_type: vulnerability, asset, remediation
    - limit: 1-500, default 100
    - offset: For pagination
    
    Response:
    {
        "total": 2450,
        "limit": 100,
        "offset": 0,
        "evidence": [
            {
                "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
                "evidence_type": "ENFORCEMENT",
                "related_entity": "vuln:RLS_BYPASS:orders",
                "created_at": "2024-11-12T14:30:45Z",
                "hash": "9a3d5c2b1e8f7d4c...",
                "payload": {
                    "enforcement_level": "HARD_FAIL",
                    "priority_score": 150,
                    "asset_at_risk": "public.orders",
                    "reason": "RLS bypass in payment processing"
                }
            }
        ]
    }
    """
    try:
        evidence_list = await service.query_evidence(
            tenant_id=current_tenant,
            evidence_type=evidence_type,
            limit=limit,
            offset=offset
        )
        
        return {
            "total": len(evidence_list),
            "limit": limit,
            "offset": offset,
            "evidence": evidence_list
        }
    except Exception as e:
        logger.error(f"Error querying evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to query evidence ledger")


@router.post(
    "/{evidence_id}/verify",
    summary="Verify Evidence Integrity",
    description="""
    Verify that logged evidence hasn't been tampered with.
    
    SHA256 hash comparison proves immutability.
    """
)
async def verify_evidence_integrity(
    evidence_id: str,
    payload: Dict[str, Any],
    service: EvidenceService = Depends(get_evidence_service),
    current_tenant: str = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Verify that evidence hasn't been altered by comparing SHA256 hashes.
    
    Request Body:
    {
        "enforcement_level": "HARD_FAIL",
        "priority_score": 150,
        "asset_at_risk": "public.orders",
        "reason": "RLS bypass in payment processing"
    }
    
    Returns:
    {
        "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
        "integrity_verified": true,
        "message": "Evidence hash matches - no tampering detected"
    }
    
    OR (if tampered):
    {
        "evidence_id": "550e8400-e29b-41d4-a716-446655440000",
        "integrity_verified": false,
        "message": "Hash mismatch - evidence may have been altered"
    }
    """
    try:
        is_valid = await service.verify_evidence_integrity(
            evidence_id=evidence_id,
            expected_payload=payload
        )
        
        return {
            "evidence_id": evidence_id,
            "integrity_verified": is_valid,
            "message": "Evidence hash matches - no tampering detected" if is_valid else "Hash mismatch - evidence may have been altered"
        }
    except Exception as e:
        logger.error(f"Error verifying evidence: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify evidence integrity")


@router.get(
    "/entity/{entity_id}",
    summary="Get Entity History",
    description="""
    Reconstruct complete audit history for an entity (vulnerability, asset, remediation).
    
    Useful for forensics and compliance investigations.
    """
)
async def get_entity_history(
    entity_id: str = Query(..., description="Entity ID (e.g., vuln:RLS_BYPASS:orders or asset:public.orders)"),
    service: EvidenceService = Depends(get_evidence_service),
    current_tenant: str = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Retrieve complete audit trail for a specific entity.
    
    Example: GET /evidence/entity/vuln%3ARLS_BYPASS%3Aorders
    
    Returns:
    {
        "entity_id": "vuln:RLS_BYPASS:orders",
        "entity_type": "vulnerability",
        "timeline": [
            {
                "timestamp": "2024-11-12T08:15:00Z",
                "evidence_type": "SCAN",
                "action": "Detected",
                "payload": {"scanner": "SQLMap", "confidence": 0.95}
            },
            {
                "timestamp": "2024-11-12T14:30:45Z",
                "evidence_type": "ENFORCEMENT",
                "action": "Blocked CI/CD",
                "payload": {"enforcement_level": "HARD_FAIL", "priority_score": 150}
            },
            {
                "timestamp": "2024-11-12T16:45:00Z",
                "evidence_type": "REMEDIATION",
                "action": "Fixed",
                "payload": {"time_to_fix_hours": 2.25, "sla_met": true}
            }
        ]
    }
    """
    try:
        history = await service.get_evidence_by_entity(
            tenant_id=current_tenant,
            entity_id=entity_id
        )
        
        if not history:
            raise HTTPException(status_code=404, detail=f"No evidence found for entity: {entity_id}")
        
        return {
            "entity_id": entity_id,
            "entity_type": history[0].get("entity_type", "unknown"),
            "timeline": history
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving entity history: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve entity history")


@router.get(
    "/export/audit-trail",
    summary="Export Audit Trail",
    description="""
    Export full audit trail for compliance and legal discovery.
    
    Includes all evidence types with SHA256 hashes for integrity verification.
    """
)
async def export_audit_trail(
    date_from: str = Query(..., description="ISO date start (e.g., 2024-11-01)"),
    date_to: str = Query(..., description="ISO date end (e.g., 2024-11-30)"),
    service: EvidenceService = Depends(get_evidence_service),
    current_tenant: str = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Export complete audit trail for a date range (for discovery, compliance audits).
    
    Query Parameters:
    - date_from: Start date (ISO format)
    - date_to: End date (ISO format)
    
    Returns:
    {
        "tenant_id": "550e8400-e29b-41d4-a716-446655440000",
        "export_date": "2024-11-15T10:00:00Z",
        "date_range": {"from": "2024-11-01", "to": "2024-11-30"},
        "total_records": 2450,
        "records": [
            {
                "evidence_id": "...",
                "evidence_type": "ENFORCEMENT",
                "created_at": "2024-11-12T14:30:45Z",
                "hash": "9a3d5c...",
                "payload": {...}
            }
        ],
        "integrity_checksum": "sha256:abc123def456..."
    }
    """
    try:
        # Parse dates
        try:
            datetime.fromisoformat(date_from.replace('Z', '+00:00'))
            datetime.fromisoformat(date_to.replace('Z', '+00:00'))
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use ISO format (YYYY-MM-DD)")
        
        audit_trail = await service.export_audit_trail(
            tenant_id=current_tenant,
            date_from=date_from,
            date_to=date_to
        )
        
        return {
            "tenant_id": current_tenant,
            "export_date": datetime.utcnow().isoformat() + "Z",
            "date_range": {
                "from": date_from,
                "to": date_to
            },
            "total_records": len(audit_trail),
            "records": audit_trail,
            "integrity_note": "All records include SHA256 hashes for verification. Use POST /evidence/{id}/verify to validate"
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error exporting audit trail: {e}")
        raise HTTPException(status_code=500, detail="Failed to export audit trail")


@router.get(
    "/stats",
    summary="Evidence Statistics",
    description="""
    Get summary statistics of the evidence ledger.
    """
)
async def get_evidence_stats(
    service: EvidenceService = Depends(get_evidence_service),
    current_tenant: str = Depends(verify_token)
) -> Dict[str, Any]:
    """
    Retrieve summary statistics for the evidence ledger.
    
    Returns:
    {
        "total_evidence": 2450,
        "evidence_by_type": {
            "SCAN": 1200,
            "ENFORCEMENT": 800,
            "REMEDIATION": 350,
            "CI_DECISION": 100
        },
        "date_range": {
            "oldest": "2024-09-01T08:15:00Z",
            "newest": "2024-11-15T14:30:45Z"
        }
    }
    """
    try:
        stats = await service.query_evidence(
            tenant_id=current_tenant,
            limit=0,  # Don't return records, just get stats
            offset=0
        )
        
        # Build stats from evidence list
        by_type = {}
        dates = []
        
        for evidence in stats:
            etype = evidence.get("evidence_type", "unknown")
            by_type[etype] = by_type.get(etype, 0) + 1
            
            if evidence.get("created_at"):
                dates.append(evidence["created_at"])
        
        return {
            "total_evidence": len(stats),
            "evidence_by_type": by_type,
            "date_range": {
                "oldest": min(dates) if dates else None,
                "newest": max(dates) if dates else None
            }
        }
    except Exception as e:
        logger.error(f"Error generating evidence stats: {e}")
        raise HTTPException(status_code=500, detail="Failed to generate statistics")
