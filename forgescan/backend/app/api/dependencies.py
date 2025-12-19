# backend/app/api/dependencies.py
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
import uuid

from app.core.security import decode_token
from app.core.constants import PLAN_LIMITS
from app.db.database import get_db, set_tenant_context
from app.db.models.user import User
from app.db.models.tenant import Tenant
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.tenant_repository import TenantRepository

security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get current authenticated user"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    try:
        payload = decode_token(credentials.credentials)
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        
        # Set tenant context for RLS
        await set_tenant_context(db, tenant_id)
        
        # Get user from database
        user_repo = UserRepository(db)
        user = await user_repo.get(uuid.UUID(user_id))
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        return user
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """Verify user is active"""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Inactive user"
        )
    return current_user


async def check_plan_limits(
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db)
) -> Tenant:
    """Check and enforce plan limits"""
    tenant_repo = TenantRepository(db)
    tenant = await tenant_repo.get_by_id(current_user.tenant_id)
    
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )
    
    plan_limits = PLAN_LIMITS.get(tenant.plan, PLAN_LIMITS["free"])
    
    # Check scan quota
    scan_count = await tenant_repo.count_scans_this_month(tenant.id)
    max_scans = plan_limits["max_scans_per_month"]
    
    if max_scans != -1 and scan_count >= max_scans:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "error": "quota_exceeded",
                "message": f"Monthly scan limit reached ({scan_count}/{max_scans})",
                "current_plan": tenant.plan,
                "upgrade_url": "/pricing",
            }
        )
    
    return tenant


def require_role(required_role: str):
    """Dependency to check user role"""
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        roles_hierarchy = ["viewer", "analyst", "admin", "owner"]
        
        if current_user.role not in roles_hierarchy:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid role"
            )
        
        user_role_level = roles_hierarchy.index(current_user.role)
        required_role_level = roles_hierarchy.index(required_role)
        
        if user_role_level < required_role_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires {required_role} role or higher"
            )
        
        return current_user
    
    return role_checker

