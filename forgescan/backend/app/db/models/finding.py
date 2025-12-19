# backend/app/db/models/finding.py
from sqlalchemy import Column, String, ForeignKey, Text, Integer, JSON, Boolean
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class Finding(BaseModel):
    """Finding model for security vulnerabilities"""
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=False, index=True)
    
    # Finding details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    
    # Location
    url = Column(String(1000), nullable=True)
    method = Column(String(10), nullable=True)  # GET, POST, etc.
    parameter = Column(String(255), nullable=True)
    
    # Technical details
    cwe_id = Column(String(50), nullable=True)
    owasp_category = Column(String(100), nullable=True, index=True)
    evidence = Column(Text, nullable=True)
    request = Column(Text, nullable=True)
    response = Column(Text, nullable=True)
    
    # Remediation
    remediation = Column(Text, nullable=True)
    references = Column(JSON, default=[])
    
    # Risk assessment
    risk_score = Column(Integer, nullable=True)
    exploitability = Column(String(20), nullable=True)  # easy, medium, hard
    
    # Status
    status = Column(String(20), default="open", nullable=False, index=True)  # open, fixed, false_positive, risk_accepted
    false_positive = Column(Boolean, default=False)
    
    # Additional metadata
    meta = Column(JSON, default={})
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


