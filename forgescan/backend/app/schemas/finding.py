# backend/app/schemas/finding.py
from pydantic import BaseModel, UUID4
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.core.constants import SeverityLevel


class FindingBase(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    references: Optional[List[str]] = []


class FindingCreate(FindingBase):
    scan_id: UUID4
    tenant_id: str


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    false_positive: Optional[bool] = None


class FindingInDB(FindingBase):
    id: UUID4
    scan_id: UUID4
    tenant_id: str
    status: str
    false_positive: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class Finding(FindingInDB):
    pass
