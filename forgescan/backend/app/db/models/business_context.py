"""
Business Context Models for ForgeScan 2.0

Maps technical vulnerabilities to business impact using:
- Asset financial value (downtime cost)
- Compliance obligations (GDPR, PCI-DSS, HIPAA, SOC2)
- Data sensitivity classification (PII, PCI, PHI)

Result: Deterministic, audit-proof remediation priorities.
"""
from enum import Enum
from sqlalchemy import Column, String, Integer, Float, DateTime, JSON, ARRAY, Boolean, ForeignKey, Text, CheckConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import uuid
from app.db.base import BaseModel


class AssetType(str, Enum):
    """Business classification of data assets"""
    REVENUE = "REVENUE"         # Customer data, payment info, orders
    COMPLIANCE = "COMPLIANCE"   # Audit trails, logs, regulatory data
    OPERATIONAL = "OPERATIONAL" # User preferences, settings, cache
    ANALYTICS = "ANALYTICS"     # Anonymized analysis data
    ARCHIVE = "ARCHIVE"         # Historical data, backups


class DataSensitivity(str, Enum):
    """Data classification per sensitivity level"""
    PUBLIC = "PUBLIC"           # No PII, safe to expose
    INTERNAL = "INTERNAL"       # Employee/internal use only
    PII = "PII"                # Personally Identifiable Information (GDPR)
    PCI = "PCI"                # Payment Card Industry data
    PHI = "PHI"                # Protected Health Information (HIPAA)


class ComplianceFramework(str, Enum):
    """Regulatory and compliance standards"""
    GDPR = "GDPR"              # EU: 4% revenue or €20M fine
    CCPA = "CCPA"              # California: 2.5% revenue
    HIPAA = "HIPAA"            # Healthcare: $1.5M+ fines
    PCI_DSS = "PCI-DSS"        # Payment cards
    SOC2 = "SOC2"              # Service organization controls
    NIST = "NIST"              # National standards
    ISO27001 = "ISO27001"      # Information security management


class VulnerabilityType(str, Enum):
    """Technical vulnerability categories"""
    RLS_BYPASS = "RLS_BYPASS"
    WEAK_MASKING = "WEAK_MASKING"
    PERFORMANCE_DEGRADATION = "PERFORMANCE_DEGRADATION"
    AUDIT_LOG_GAP = "AUDIT_LOG_GAP"
    ENCRYPTION_FAILURE = "ENCRYPTION_FAILURE"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    UNLOGGED_WRITES = "UNLOGGED_WRITES"
    PARTITION_FAILURE = "PARTITION_FAILURE"
    RATE_LIMIT_BYPASS = "RATE_LIMIT_BYPASS"
    COMPLIANCE_GAP = "COMPLIANCE_GAP"


class SeverityLabel(str, Enum):
    """Severity classification for remediations"""
    CRITICAL = "CRITICAL"      # Fix immediately (1 hour SLA)
    HIGH = "HIGH"              # Fix urgently (4-24 hours)
    MEDIUM = "MEDIUM"          # Fix soon (48 hours)
    LOW = "LOW"                # Fix in next sprint


class BusinessAsset(BaseModel):
    """
    Registry of business-critical data assets.
    
    Maps database tables to:
    - Business value (downtime cost)
    - Compliance obligations
    - Data sensitivity
    
    Used to calculate deterministic remediation priorities.
    """
    __tablename__ = "business_assets"
    __table_args__ = (
        CheckConstraint(
            "asset_type IN ('REVENUE', 'COMPLIANCE', 'OPERATIONAL', 'ANALYTICS', 'ARCHIVE')",
            name='business_assets_type_check'
        ),
        CheckConstraint(
            "data_sensitivity IN ('PUBLIC', 'INTERNAL', 'PII', 'PCI', 'PHI')",
            name='business_assets_sensitivity_check'
        ),
        {"schema": "forgescan_security"}
    )
    
    asset_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("forgescan_security.tenant_registry.tenant_id"), 
                      nullable=False, index=True)
    schema_name = Column(String(255), nullable=False)
    table_name = Column(String(255), nullable=False)
    
    # Business Classification
    asset_type = Column(String(32), nullable=False)  # REVENUE, COMPLIANCE, OPERATIONAL, etc.
    data_sensitivity = Column(String(32), nullable=False)  # PUBLIC, INTERNAL, PII, PCI, PHI
    
    # Quantified Impact
    downtime_cost_per_hour = Column(Integer, default=0)  # USD/hour if breached
    max_exposure_records = Column(Integer, default=0)    # Number of records at risk
    criticality_score = Column(Integer, default=50)      # 1-100 importance scale
    
    # Compliance Obligations
    compliance_frameworks = Column(ARRAY(String(32)), default=list)  # GDPR, PCI-DSS, HIPAA, etc.
    
    # Metadata
    data_owner = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now(), onupdate=func.now())
    
    class Config:
        use_enum_values = True


class ComplianceFrameworkRegistry(BaseModel):
    """
    Reference table for regulatory frameworks.
    
    Stores fine amounts, regulatory bodies, and description.
    Used to estimate breach impact.
    """
    __tablename__ = "compliance_frameworks"
    __table_args__ = {"schema": "forgescan_security"}
    
    framework_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    framework_name = Column(String(64), nullable=False, unique=True, index=True)
    regulatory_body = Column(String(64), nullable=True)
    max_fine_percent_revenue = Column(Float, nullable=True)  # % of annual revenue
    fine_per_record_usd = Column(Float, nullable=True)       # Fixed amount per record
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    class Config:
        use_enum_values = True


class VulnerabilityTypeRegistry(BaseModel):
    """
    Reference table for vulnerability types.
    
    Maps scanner findings to remediation rules.
    """
    __tablename__ = "vulnerability_types"
    __table_args__ = {"schema": "forgescan_security"}
    
    vuln_type_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    vuln_type = Column(String(64), nullable=False, unique=True, index=True)
    cve_pattern = Column(String(255), nullable=True)
    technical_category = Column(String(64), nullable=True)  # access_control, data_integrity, performance
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    class Config:
        use_enum_values = True


class RemediationRule(BaseModel):
    """
    Deterministic Rule: Vulnerability Type + Context = Priority + Action.
    
    For a given vulnerability type (e.g., RLS_BYPASS) and asset context (e.g., PCI),
    this rule specifies:
    - Base priority score (0-100)
    - Bonuses for REVENUE/COMPLIANCE assets
    - Required remediation action
    - SQL template for fix
    - SLA for remediation
    
    Example:
    - RLS_BYPASS on PCI asset: Priority 100 + 20 (revenue) + 30 (compliance) = 150
    - RLS_BYPASS on ARCHIVE asset: Priority 75 (base only)
    """
    __tablename__ = "remediation_rules"
    __table_args__ = (
        CheckConstraint(
            "severity_label IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW')",
            name='remediation_rules_severity_check'
        ),
        {"schema": "forgescan_security"}
    )
    
    rule_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True)
    vuln_type = Column(String(64), nullable=False, index=True)  # RLS_BYPASS, WEAK_MASKING, etc.
    context_trigger = Column(String(64), nullable=False, index=True)  # REVENUE, PCI, GDPR, ALL
    
    # Deterministic Priority Calculation
    base_priority_score = Column(Integer, nullable=False)
    revenue_bonus = Column(Integer, default=20)        # +20 if REVENUE asset
    compliance_bonus = Column(Integer, default=30)     # +30 if compliance framework matches
    exposure_multiplier = Column(Float, default=1.0)   # Scale by record exposure
    
    # Output: Required Remediation
    required_action = Column(String(255), nullable=False)
    technical_fix_template = Column(Text, nullable=True)  # SQL with %I placeholders
    
    # SLA & Severity
    severity_label = Column(String(16), nullable=True)
    mitigation_time_hours = Column(Integer, default=24)
    created_at = Column(DateTime(timezone=True), nullable=False, server_default=func.now())
    
    class Config:
        use_enum_values = True
