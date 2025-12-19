# backend/app/db/models/usage.py
from sqlalchemy import Column, String, ForeignKey, Integer, Date, JSON
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class UsageRecord(BaseModel):
    """Usage tracking for billing"""
    __tablename__ = "usage_records"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=False, index=True)
    
    # Usage data
    date = Column(Date, nullable=False, index=True)
    scans_count = Column(Integer, default=0)
    api_requests_count = Column(Integer, default=0)
    
    # Breakdown
    usage_by_scanner = Column(JSON, default={})
    usage_by_user = Column(JSON, default={})
    
    # Relationships
    tenant = relationship("Tenant", back_populates="usage_records")
