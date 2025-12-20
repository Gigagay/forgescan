# backend/app/api/v1/findings.py
from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_
from app.db.session import get_session
from app.db.models.finding import Finding
from app.core.tenant import require_tenant

router = APIRouter()


@router.get("/")
async def list_findings(
    scan_id: str | None = Query(None),
    severity: str | None = Query(None),
    status: str | None = Query(None),
    fingerprint: str | None = Query(None),
    session: AsyncSession = Depends(get_session),
    tenant=Depends(require_tenant),
):
    """
    List findings for current tenant.
    
    RLS ensures tenant_id automatically filters results even if tenant_id
    is not explicitly passed in query.
    
    Query parameters:
    - scan_id: Filter by scan ID
    - severity: Filter by severity (critical, high, medium, low, info)
    - status: Filter by status (open, fixed, false_positive, risk_accepted)
    - fingerprint: Find specific finding by SHA256 fingerprint
    """
    query = select(Finding).where(
        Finding.tenant_id == tenant.id
    )
    
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)
    
    if severity:
        query = query.where(Finding.severity == severity)
    
    if status:
        query = query.where(Finding.status == status)
    
    if fingerprint:
        query = query.where(Finding.fingerprint == fingerprint)
    
    result = await session.execute(query)
    findings = result.scalars().all()
    
    return [
        {
            "id": str(f.id),
            "scan_id": str(f.scan_id),
            "scanner": f.scanner,
            "rule_id": f.rule_id,
            "title": f.title,
            "severity": f.severity,
            "fingerprint": f.fingerprint,
            "file": f.file,
            "line": f.line,
            "status": f.status,
        }
        for f in findings
    ]


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    session: AsyncSession = Depends(get_session),
    tenant=Depends(require_tenant),
):
    """Get a single finding by ID with tenant isolation"""
    result = await session.execute(
        select(Finding).where(
            and_(
                Finding.id == finding_id,
                Finding.tenant_id == tenant.id
            )
        )
    )
    finding = result.scalar_one_or_none()
    
    if not finding:
        return {"error": "Finding not found"}, 404
    
    return {
        "id": str(finding.id),
        "scan_id": str(finding.scan_id),
        "scanner": finding.scanner,
        "rule_id": finding.rule_id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "confidence": finding.confidence,
        "fingerprint": finding.fingerprint,
        "file": finding.file,
        "line": finding.line,
        "status": finding.status,
        "remediation": finding.remediation,
    }