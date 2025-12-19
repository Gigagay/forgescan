# backend/app/db/repositories/finding_repository.py
from typing import List, Optional
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.db.models.finding import Finding
from app.db.repositories.base import BaseRepository


class FindingRepository(BaseRepository[Finding]):
    """Repository for Finding operations"""
    
    def __init__(self, session: AsyncSession):
        super().__init__(Finding, session)
    
    async def get_by_scan(
        self,
        scan_id: UUID,
        tenant_id: str,
        severity: Optional[str] = None
    ) -> List[Finding]:
        """Get findings for a scan"""
        query = select(Finding).where(
            and_(
                Finding.scan_id == scan_id,
                Finding.tenant_id == tenant_id
            )
        )
        
        if severity:
            query = query.where(Finding.severity == severity)
        
        result = await self.session.execute(query)
        return result.scalars().all()
