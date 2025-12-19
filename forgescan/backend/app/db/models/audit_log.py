# backend/app/db/models/audit_log.py
from sqlalchemy import Column, String, ForeignKey, JSON, Text
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class AuditLog(BaseModel):
    """Audit log for tracking all actions"""
    __tablename__ = "audit_logs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=True, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    
    # Action details
    action = Column(String(100), nullable=False, index=True)  # login, scan_create, etc.
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    
    # Request details
    ip_address = Column(INET, nullable=True)
    user_agent = Column(Text, nullable=True)
    
    # Additional details
    details = Column(JSON, default={})
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")