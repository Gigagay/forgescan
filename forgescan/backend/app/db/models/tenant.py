# backend/app/db/models/tenant.py
from sqlalchemy import Column, String, Integer, Boolean, JSON, DateTime
from sqlalchemy.orm import relationship
from app.db.base import BaseModel


class Tenant(BaseModel):
    """Tenant model for multi-tenancy"""
    __tablename__ = "tenants"
    
    id = Column(String(100), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    plan = Column(String(50), default="free", nullable=False, index=True)
    # Backwards-compatible alias used in tests
    subscription_tier = Column(String(50), default="free", nullable=False, index=True)

    # Plan limits
    max_scans = Column(Integer, default=5)
    max_users = Column(Integer, default=1)
    
    # Settings
    settings = Column(JSON, default={})
    
    # Peach Payments fields
    peach_registration_id = Column(String(255), unique=True, nullable=True)
    peach_transaction_id = Column(String(255), nullable=True)
    subscription_status = Column(String(50), nullable=True)  # active, cancelled, expired
    trial_ends_at = Column(DateTime, nullable=True)

    
    # Status
    is_active = Column(Boolean, default=True, nullable=False)
    
    # Relationships
    users = relationship("User", back_populates="tenant", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="tenant", cascade="all, delete-orphan")
    usage_records = relationship("UsageRecord", back_populates="tenant", cascade="all, delete-orphan")
