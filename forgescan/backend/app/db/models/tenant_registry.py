"""
Tenant Registry Model for ForgeScan 2.0

Manages multi-tenant isolation, tier-based access, and rate limiting configuration.
"""
from sqlalchemy import Column, String, Boolean, DateTime, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
import uuid
from app.db.base import BaseModel


class TenantRegistry(BaseModel):
    """
    Core tenant registration and metadata.
    
    Used for:
    - Tenant isolation via RLS (tenant_id in session context)
    - Rate limiting configuration per tenant
    - Tier-based feature access (free, pro, enterprise)
    - Audit trail filtering
    """
    __tablename__ = "tenant_registry"
    __table_args__ = {"schema": "forgescan_security"}
    
    tenant_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_name = Column(String(255), nullable=False, unique=True, index=True)
    domain = Column(String(255), unique=True, nullable=True)
    tier = Column(String(32), default="free", nullable=False)  # free, pro, enterprise
    is_active = Column(Boolean, default=True, nullable=False, index=True)
    
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    metadata = Column(JSON, default=dict, nullable=False)
    
    class Config:
        use_enum_values = True


class RateLimit(BaseModel):
    """
    Token Bucket Rate Limiting Configuration.
    
    Implements O(1) rate limiting with:
    - bucket_size: Maximum tokens available
    - tokens: Current token count
    - refill_rate: Tokens added per second
    - last_update: Timestamp of last refill
    
    Algorithm:
        tokens_available = min(bucket_size, tokens + (now - last_update) * refill_rate)
        if tokens_available >= 1:
            allow_request()
            tokens_available -= 1
        else:
            reject_request()
    """
    __tablename__ = "rate_limits"
    __table_args__ = {"schema": "forgescan_security"}
    
    tenant_id = Column(UUID(as_uuid=True), primary_key=True, index=True)
    bucket_size = Column(Integer, nullable=False, default=1000)
    tokens = Column(Integer, nullable=False, default=1000)
    refill_rate = Column(Integer, nullable=False, default=10)  # tokens per second
    last_update = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    class Config:
        use_enum_values = True


class UserRole(BaseModel):
    """
    Role-Based Access Control (RBAC) with Clearance Levels.
    
    Clearance levels (0-100):
    - 0: viewer (read-only)
    - 25: analyst (view + comment)
    - 50: engineer (remediate findings)
    - 75: auditor (unmasked data access)
    - 90: compliance_officer (full audit access)
    - 100: admin (full system access)
    """
    __tablename__ = "user_roles"
    __table_args__ = {"schema": "forgescan_security"}
    
    role_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    role_name = Column(String(64), nullable=False, unique=True, index=True)
    clearance_level = Column(Integer, nullable=False, default=0)  # 0-100
    description = Column(String(500), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    class Config:
        use_enum_values = True
