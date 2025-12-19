# backend/app/schemas/tenant.py
from pydantic import BaseModel
from typing import Optional, Dict, Any
from datetime import datetime


class TenantBase(BaseModel):
    name: str


class TenantCreate(TenantBase):
    id: str
    plan: str = "free"


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    settings: Optional[Dict[str, Any]] = None


class TenantInDB(TenantBase):
    id: str
    plan: str
    max_scans: int
    max_users: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class Tenant(TenantInDB):
    pass


