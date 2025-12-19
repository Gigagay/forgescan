# backend/app/db/models/dependency.py
"""Database models for SCA (dependency tracking)"""

from sqlalchemy import Column, String, ForeignKey, Text, Boolean, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
import uuid

from app.db.base import BaseModel


class Dependency(BaseModel):
    """Dependency model for SCA"""
    __tablename__ = "dependencies"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String(100), ForeignKey("tenants.id"), nullable=False, index=True)
    
    # Dependency details
    name = Column(String(255), nullable=False, index=True)
    version = Column(String(100), nullable=False)
    ecosystem = Column(String(50), nullable=False, index=True)  # npm, pypi, maven, etc.
    purl = Column(String(500), nullable=False)  # Package URL
    
    # Metadata
    license = Column(String(100))
    direct = Column(Boolean, default=True)  # Direct vs transitive dependency
    depth = Column(Integer, default=0)  # Dependency tree depth
    
    # Vulnerability info
    has_vulnerabilities = Column(Boolean, default=False, index=True)
    vulnerability_count = Column(Integer, default=0)
    max_severity = Column(String(20))  # Highest severity found
    
    metadata = Column(JSON, default={})
