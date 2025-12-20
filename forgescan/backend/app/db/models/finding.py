# backend/app/db/models/finding.py
from sqlalchemy import Column, String, ForeignKey, Text, Integer, JSON, Boolean, Float
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class Finding(BaseModel):
    """Finding model for security vulnerabilities with RLS protection"""
    __tablename__ = "findings"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("tenants.id"), nullable=False, index=True)
    
    # Normalized finding details
    scanner = Column(String(32), nullable=False, index=True)  # bandit, semgrep, zap, sqlmap
    rule_id = Column(String(64), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, index=True)  # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=0.85)
    fingerprint = Column(String(64), nullable=False, index=True, unique=True)  # SHA256 for deduplication
    
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
    risk_score = Column(Integer, nullable=True)
    exploitability = Column(String(20), nullable=True)  # easy, medium, hard
    
    # Status
    status = Column(String(20), default="open", nullable=False, index=True)  # open, fixed, false_positive, risk_accepted
    false_positive = Column(Boolean, default=False)
    
    # Additional metadata
    meta = Column(JSON, default=dict, nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")


