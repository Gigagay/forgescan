# ------------------------------------------------------------------------------
# FILE 3: Database Models
# Save as: backend/app/db/models/ci_integration.py
# ------------------------------------------------------------------------------
"""
CI/CD Integration Models
Tracks GitHub, GitLab, and other CI/CD integrations
"""

from sqlalchemy import Column, String, Boolean, JSON, DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
import uuid

from app.db.base_class import Base


class CIIntegration(Base):
    """CI/CD integration configuration"""
    __tablename__ = "ci_integrations"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=False)
    
    provider = Column(String(50), nullable=False)  # github, gitlab, etc.
    repo_full_name = Column(String(255), nullable=False)  # owner/repo
    github_token = Column(String(255))  # Encrypted in production
    
    scanner_types = Column(JSON, default=["web"])
    scan_options = Column(JSON, default={})
    fail_on_severity = Column(JSON, default=["critical"])
    
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class CIScanRun(Base):
    """Individual CI/CD scan run"""
    __tablename__ = "ci_scan_runs"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ci_integration_id = Column(UUID, ForeignKey("ci_integrations.id"))
    tenant_id = Column(String(100), ForeignKey("tenants.id"))
    
    event_type = Column(String(50))  # pull_request, push, schedule
    pr_number = Column(Integer)
    branch = Column(String(255))
    commit_sha = Column(String(255))
    
    scan_id = Column(UUID)  # Link to actual scan
    status = Column(String(50), default="pending")  # pending, running, completed, failed, error
    findings_summary = Column(JSON)
    error_message = Column(String(500))
    
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    created_at = Column(DateTime, default=datetime.utcnow)