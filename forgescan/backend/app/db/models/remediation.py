from sqlalchemy import Column, String, ForeignKey, Text, CheckConstraint, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.base import BaseModel


class Remediation(BaseModel):
    """
    Remediation model for business-impact-driven vulnerability remediation.
    
    Links findings to prioritized remediation actions with business context.
    Priority must be P0-P4 based on combined severity/business impact score.
    """
    __tablename__ = "remediations"
    __table_args__ = (
        CheckConstraint(
            "priority IN ('P0', 'P1', 'P2', 'P3', 'P4')",
            name='remediations_priority_check'
        ),
        CheckConstraint(
            "status IN ('open', 'in_progress', 'completed', 'deferred')",
            name='remediations_status_check'
        ),
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey("findings.id"), nullable=False, index=True)
    
    # Remediation details
    priority = Column(String(3), nullable=False, index=True)  # P0, P1, P2, P3, P4
    action = Column(Text, nullable=False)
    timeframe = Column(String(100), nullable=False)
    business_risk = Column(Text, nullable=True)
    technical_risk = Column(Text, nullable=True)
    justification = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=True)  # High, Medium, Low
    
    # Remediation status
    status = Column(String(20), default="open", nullable=False, index=True)  # open, in_progress, completed, deferred
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    # Relationships
    finding = relationship("Finding", back_populates="remediations")
