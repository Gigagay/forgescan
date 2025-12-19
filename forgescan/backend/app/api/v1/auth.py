# backend/app/api/v1/auth.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from datetime import datetime

from app.db.database import get_db
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.tenant_repository import TenantRepository
from app.schemas.auth import (
    Token, LoginRequest, SignupRequest, RefreshTokenRequest
)
from app.schemas.user import UserCreate
from app.core.security import (
    verify_password, get_password_hash, create_access_token, create_refresh_token, decode_token
)

router = APIRouter()


@router.post("/signup", response_model=Token)
async def signup(
    request: SignupRequest,
    db: AsyncSession = Depends(get_db)
):
    """Register new user and tenant"""
    user_repo = UserRepository(db)
    tenant_repo = TenantRepository(db)
    
    # Check if user exists
    existing_user = await user_repo.get_by_email(request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create tenant
    tenant_id = str(uuid.uuid4())
    tenant = await tenant_repo.create({
        "id": tenant_id,
        "name": request.tenant_name,
        "plan": "free",
        "max_scans": 5,
        "max_users": 1,
    })
    
    # Create user
    user = await user_repo.create({
        "email": request.email,
        "hashed_password": get_password_hash(request.password),
        "full_name": request.full_name,
        "tenant_id": tenant_id,
        "role": "owner",
        "is_active": True,
        "is_verified": False,
    })
    
    # Generate tokens
    access_token = create_access_token({
        "sub": str(user.id),
        "tenant_id": tenant_id,
        "role": user.role,
    })
    
    refresh_token = create_refresh_token({
        "sub": str(user.id),
        "tenant_id": tenant_id,
    })
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/login", response_model=Token)
async def login(
    request: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    """Login user"""
    user_repo = UserRepository(db)
    
    # Get user
    user = await user_repo.get_by_email(request.email)
    
    if not user or not verify_password(request.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Update last login
    await user_repo.update(user.id, {"last_login": datetime.utcnow()})
    
    # Generate tokens
    access_token = create_access_token({
        "sub": str(user.id),
        "tenant_id": user.tenant_id,
        "role": user.role,
    })
    
    refresh_token = create_refresh_token({
        "sub": str(user.id),
        "tenant_id": user.tenant_id,
    })
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    request: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token"""
    try:
        payload = decode_token(request.refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id = payload.get("sub")
        tenant_id = payload.get("tenant_id")
        
        # Verify user still exists and is active
        user_repo = UserRepository(db)
        user = await user_repo.get(uuid.UUID(user_id))
        
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive"
            )
        
        # Generate new tokens
        access_token = create_access_token({
            "sub": user_id,
            "tenant_id": tenant_id,
            "role": user.role,
        })
        
        refresh_token = create_refresh_token({
            "sub": user_id,
            "tenant_id": tenant_id,
        })
        
        return Token(
            access_token=access_token,
            refresh_token=refresh_token,
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


@router.post("/logout")
async def logout():
    """Logout user (client should discard tokens)"""
    return {"message": "Successfully logged out"}