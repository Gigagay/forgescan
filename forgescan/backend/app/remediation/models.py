from enum import Enum
from pydantic import BaseModel
from typing import Optional


class Priority(str, Enum):
    """Remediation priority levels mapped to P0-P4"""
    P0 = "P0"  # Critical - immediate action required
    P1 = "P1"  # High - within 24 hours
    P2 = "P2"  # Medium - within 48-72 hours
    P3 = "P3"  # Low - within sprint
    P4 = "P4"  # Informational - best effort


class BusinessImpact(str, Enum):
    """Business impact classification"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Remediation(BaseModel):
    """
    Structured remediation recommendation with business context.
    
    Combines technical severity with business impact for
    decision-making by security and product teams.
    """
    priority: Priority
    action: str
    timeframe: str
    business_risk: str
    technical_risk: str
    justification: str
    confidence: str

    class Config:
        use_enum_values = True
