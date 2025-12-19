# backend/app/schemas/user.py
from pydantic import BaseModel, EmailStr, UUID4
from typing import Optional
from datetime import datetime


class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None


class UserCreate(UserBase):
    password: str
    tenant_id: str


class UserCreateOAuth(UserBase):
    oauth_provider: str
    oauth_id: str
    tenant_id: str
    avatar_url: Optional[str] = None


class UserUpdate(BaseModel):
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None


class UserInDB(UserBase):
    id: UUID4
    tenant_id: str
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class User(UserInDB):
    pass

