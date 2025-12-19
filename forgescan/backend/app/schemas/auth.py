# backend/app/schemas/auth.py
from pydantic import BaseModel, EmailStr
from typing import Optional


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenPayload(BaseModel):
    sub: str
    tenant_id: str
    role: str
    exp: int
    type: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class SignupRequest(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None
    tenant_name: str


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class OAuthCallbackRequest(BaseModel):
    code: str
    provider: str