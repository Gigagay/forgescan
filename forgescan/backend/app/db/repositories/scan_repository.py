# backend/app/db/repositories/scan_repository.py
from typing import Optional, List
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.db.models.scan import Scan
from app.db.repositories.base import BaseRepository


class ScanRepository(BaseRepository[Scan]):
    """Repository for Scan operations"""
    
    def __init__(self, session: AsyncSession):
        super().__init__(Scan, session)
    
    async def get_by_tenant(
        self, 
        tenant_id: str, 
        skip: int = 0, 
        limit: int = 100
    ) -> List[Scan]:
        """Get scans for a tenant"""
        result = await self.session.execute(
            select(Scan)
            .where(Scan.tenant_id == tenant_id)
            .order_by(Scan.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        return result.scalars().all()
    
    async def get_with_tenant_check(self, scan_id: UUID, tenant_id: str) -> Optional[Scan]:
        """Get scan with tenant verification"""
        result = await self.session.execute(
            select(Scan).where(
                and_(
                    Scan.id == scan_id,
                    Scan.tenant_id == tenant_id
                )
            )
        )
        return result.scalar_one_or_none()

