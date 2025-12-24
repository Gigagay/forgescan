"""Tenant dependency resolver for FastAPI routes."""
from typing import Optional, Any
from fastapi import Header, HTTPException
import uuid


async def require_tenant(
    x_tenant_id: Optional[str] = Header(None),
) -> str:
    """
    FastAPI dependency that extracts and validates the tenant ID from request headers.
    
    Args:
        x_tenant_id: Tenant ID from X-Tenant-ID header
        
    Returns:
        Validated tenant ID
        
    Raises:
        HTTPException: If tenant ID is missing or invalid
    """
    if not x_tenant_id:
        raise HTTPException(status_code=400, detail="X-Tenant-ID header is required")
    
    try:
        # Validate it's a valid UUID
        uuid.UUID(x_tenant_id)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail="Invalid tenant ID format")
    
    return x_tenant_id
