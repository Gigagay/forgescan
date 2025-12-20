from sqlalchemy import Column, String, DateTime, JSON, ForeignKey, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel

class Scan(BaseModel):
    """
    Scan model with strict typing and RLS protection.
    
    Represents a security scan execution with multi-tenant isolation.
    Status must be one of: pending, running, completed, failed
    ScanType must be one of: web, sast, sca, dast
    """
    __tablename__ = "scans"
    __table_args__ = (
        CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name='scans_status_check'
        ),
        CheckConstraint(
            "scan_type IN ('web', 'sast', 'sca', 'dast')",
            name='scans_scan_type_check'
        ),
    )

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(32), nullable=False, default='web')
    status = Column(String(20), nullable=False, default='pending', index=True)
    findings_summary = Column(JSON, nullable=True, default=dict)
    started_at = Column(DateTime(timezone=True), nullable=True)
    completed_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())

    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tenant = relationship("Tenant", back_populates="scans")
    user = relationship("User", back_populates="scans")