# backend/app/api/v1/scans.py
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.db.database import get_db
from app.db.repositories.scan_repository import ScanRepository
from app.db.repositories.finding_repository import FindingRepository
from app.db.models.user import User
from app.db.models.tenant import Tenant
from app.schemas.scan import Scan, ScanCreate, ScanUpdate
from app.schemas.finding import Finding
from app.api.dependencies import get_current_active_user, check_plan_limits
from app.workers.scanner_worker import execute_scan_task
from app.core.constants import ScannerType

router = APIRouter()


@router.post("/", response_model=Scan, status_code=status.HTTP_201_CREATED)
async def create_scan(
    scan_in: ScanCreate,
    request: Request,
    current_user: User = Depends(get_current_active_user),
    tenant: Tenant = Depends(check_plan_limits),
    db: AsyncSession = Depends(get_db)
):
    """Create and queue a new scan"""
    scan_repo = ScanRepository(db)
    
    # Validate scanner type is allowed for plan
    from app.core.constants import PLAN_LIMITS
    plan_limits = PLAN_LIMITS[tenant.plan]
    
    if scan_in.scanner_type not in plan_limits["scanners"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={
                "error": "scanner_not_available",
                "message": f"{scan_in.scanner_type} scanner not available in {tenant.plan} plan",
                "upgrade_url": "/pricing"
            }
        )
    
    # Create scan record
    scan = await scan_repo.create({
        "tenant_id": current_user.tenant_id,
        "user_id": current_user.id,
        "scanner_type": scan_in.scanner_type,
        "target": scan_in.target,
        "options": scan_in.options,
        "status": "pending",
        "progress": 0,
    })
    
    # Queue scan for processing
    plugin_manager = request.app.state.plugin_manager
    execute_scan_task.delay(
        str(scan.id),
        current_user.tenant_id,
        scan_in.scanner_type,
        scan_in.target,
        scan_in.options
    )
    
    return scan


@router.get("/", response_model=List[Scan])
async def list_scans(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """List scans for current tenant"""
    scan_repo = ScanRepository(db)
    scans = await scan_repo.get_by_tenant(
        current_user.tenant_id,
        skip=skip,
        limit=limit
    )
    return scans


@router.get("/{scan_id}", response_model=Scan)
async def get_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get scan details"""
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_with_tenant_check(scan_id, current_user.tenant_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    return scan


@router.get("/{scan_id}/findings", response_model=List[Finding])
async def get_scan_findings(
    scan_id: UUID,
    skip: int = 0,
    limit: int = 100,
    severity: str = None,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get findings for a scan"""
    # Verify scan exists and belongs to tenant
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_with_tenant_check(scan_id, current_user.tenant_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    # Get findings
    finding_repo = FindingRepository(db)
    filters = {"scan_id": scan_id}
    if severity:
        filters["severity"] = severity
    
    findings = await finding_repo.get_multi(
        skip=skip,
        limit=limit,
        filters=filters
    )
    
    return findings


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: UUID,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Delete a scan"""
    scan_repo = ScanRepository(db)
    scan = await scan_repo.get_with_tenant_check(scan_id, current_user.tenant_id)
    
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )
    
    await scan_repo.delete(scan_id)
    return None
