# backend/app/db/models/user.py
from sqlalchemy import Column, String, Boolean, ForeignKey, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class User(BaseModel):
    """User model with OAuth support"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable for OAuth users
    
    # Profile
    full_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # Tenant relationship
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=False, index=True)
    role = Column(String(50), default="viewer", nullable=False)  # owner, admin, analyst, viewer
    
    # OAuth
    oauth_provider = Column(String(50), nullable=True)  # google, github, etc.
    oauth_id = Column(String(255), nullable=True)
    
    # MFA
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(255), nullable=True)
    
    # API Keys
    api_key_hash = Column(String(255), nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=False, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Backwards-compatible alias for test fixtures
    @property
    def email_verified(self):
        return self.is_verified

    @email_verified.setter
    def email_verified(self, value: bool):
        self.is_verified = value
    
    # Relationships
    tenant = relationship("Tenant", back_populates="users")
    scans = relationship("Scan", back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
