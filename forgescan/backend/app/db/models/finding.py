# backend/app/db/models/finding.py
from sqlalchemy import Column, String, ForeignKey, Text, Integer, JSON, Boolean, Float, CheckConstraint, DateTime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid
from app.db.base import BaseModel


class Finding(BaseModel):
    """
    Finding model for security vulnerabilities with RLS protection.
    
    Strict typing enforced at database level with check constraints.
    Status and severity values are restricted to known enums.
    """
    __tablename__ = "findings"
    __table_args__ = (
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name='findings_severity_check'
        ),
        CheckConstraint(
            "status IN ('open', 'fixed', 'false_positive', 'risk_accepted')",
            name='findings_status_check'
        ),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1",
            name='findings_confidence_range'
        ),
    )
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    
    # Normalized finding details
    scanner = Column(String(32), nullable=False, index=True)  # bandit, semgrep, zap, sqlmap
    rule_id = Column(String(64), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.85)  # 0-1
    fingerprint = Column(String(64), nullable=False, index=True)  # SHA256 for deduplication
    
    # Location
    file = Column(String(1000), nullable=True)
    line = Column(Integer, nullable=True)
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
    references = Column(JSON, default=list, nullable=False)
    
    # Risk assessment
    impact_score = Column(Integer, nullable=True, default=0)
    exploitability = Column(String(20), nullable=True)  # easy, medium, hard
    
    # Status
    status = Column(String(20), default="open", nullable=False, index=True)  # open, fixed, false_positive, risk_accepted
    false_positive = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    # Additional metadata
    meta = Column(JSON, default=dict, nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    remediations = relationship("Remediation", back_populates="finding", cascade="all, delete-orphan")


