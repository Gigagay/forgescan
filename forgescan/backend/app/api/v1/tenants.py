# backend/app/api/v1/tenants.py
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.db.repositories.tenant_repository import TenantRepository
from app.db.models.user import User
from app.api.dependencies import get_current_active_user
from app.schemas.tenant import Tenant as TenantSchema

router = APIRouter()


@router.get("/me", response_model=TenantSchema)
async def get_current_tenant(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
):
    """Get current tenant information"""
    tenant_repo = TenantRepository(db)
    tenant = await tenant_repo.get_by_id(current_user.tenant_id)
    return tenant
