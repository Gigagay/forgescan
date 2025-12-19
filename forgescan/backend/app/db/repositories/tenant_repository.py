# backend/app/db/repositories/tenant_repository.py
from typing import Optional, Dict, Any
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime, timedelta

from app.db.models.tenant import Tenant
from app.db.models.user import User
from app.db.models.scan import Scan
from app.db.repositories.base import BaseRepository


class TenantRepository(BaseRepository[Tenant]):
    """Repository for Tenant operations"""
    
    def __init__(self, session: AsyncSession):
        super().__init__(Tenant, session)
    
    async def get_by_id(self, tenant_id: str) -> Optional[Tenant]:
        """Get tenant by ID"""
        result = await self.session.execute(
            select(Tenant).where(Tenant.id == tenant_id)
        )
        return result.scalar_one_or_none()
    
    async def count_users(self, tenant_id: str) -> int:
        """Count users in tenant"""
        result = await self.session.execute(
            select(func.count(User.id)).where(User.tenant_id == tenant_id)
        )
        return result.scalar() or 0
    
    async def count_scans_this_month(self, tenant_id: str) -> int:
        """Count scans in current month"""
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        
        result = await self.session.execute(
            select(func.count(Scan.id))
            .where(Scan.tenant_id == tenant_id)
            .where(Scan.created_at >= start_of_month)
        )
        return result.scalar() or 0
    
    async def get_usage_stats(self, tenant_id: str) -> Dict[str, Any]:
        """Get usage statistics for tenant"""
        user_count = await self.count_users(tenant_id)
        scan_count = await self.count_scans_this_month(tenant_id)
        
        return {
            "users_count": user_count,
            "scans_this_month": scan_count,
        }

