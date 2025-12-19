# backend/app/schemas/scan.py
from pydantic import BaseModel, UUID4, HttpUrl
from typing import Optional, Dict, Any
from datetime import datetime
from app.core.constants import ScannerType, ScanStatus


class ScanBase(BaseModel):
    scanner_type: ScannerType
    target: str
    options: Optional[Dict[str, Any]] = {}


class ScanCreate(ScanBase):
    pass


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    progress: Optional[int] = None
    findings_summary: Optional[Dict[str, Any]] = None
    risk_score: Optional[float] = None
    error_message: Optional[str] = None


class ScanInDB(ScanBase):
    id: UUID4
    tenant_id: str
    user_id: UUID4
    status: ScanStatus
    progress: int
    findings_summary: Dict[str, Any]
    risk_score: Optional[float]
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class Scan(ScanInDB):
    pass

