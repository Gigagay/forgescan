from sqlalchemy import Column, String, Float, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel

class Scan(BaseModel):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(String(100), ForeignKey("tenants.id"))
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True, index=True)
    target = Column(String(1024))
    status = Column(String(50), index=True)
    risk_score = Column(Float, nullable=True)
    findings_summary = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    tenant = relationship("Tenant", back_populates="scans")
    user = relationship("User", back_populates="scans")