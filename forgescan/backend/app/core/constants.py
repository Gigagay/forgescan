# backend/app/core/constants.py
from enum import Enum
from typing import Dict, Any, List


class PlanType(str, Enum):
    FREE = "free"
    DEVELOPER = "developer"
    STARTUP = "startup"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class ScannerType(str, Enum):
    WEB = "web"
    API = "api"
    SCA = "sca"

class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class UserRole(str, Enum):
    OWNER = "owner"
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Plan Limits Configuration
PLAN_LIMITS: Dict[str, Dict[str, Any]] = {
    PlanType.FREE: {
        "max_scans_per_month": 5,
        "max_users": 1,
        "scanners": [ScannerType.WEB],
        "retention_days": 7,
        "api_requests_per_day": 0,
        "features": ["basic_reports"],
        "max_scan_targets": 1,
        "concurrent_scans": 1,
    },
    PlanType.DEVELOPER: {
        "max_scans_per_month": 50,
        "max_users": 1,
        "scanners": [ScannerType.WEB, ScannerType.API,ScannerType.SCA],
        "retention_days": 30,
        "api_requests_per_day": 100,
        "features": [
            "basic_reports",
            "pdf_export",
            "ci_webhook",
            "api_access",
            "email_notifications",
        ],
        "max_scan_targets": 3,
        "concurrent_scans": 2,
    },
    PlanType.STARTUP: {
        "max_scans_per_month": 200,
        "max_users": 5,
        "scanners": [ScannerType.WEB, ScannerType.API,ScannerType.SCA],
        "retention_days": 90,
        "api_requests_per_day": 1000,
        "features": [
            "advanced_reports",
            "integrations",
            "scheduled_scans",
            "team_collaboration",
            "priority_support",
        ],
        "max_scan_targets": 10,
        "concurrent_scans": 3,
    },
    PlanType.PROFESSIONAL: {
        "max_scans_per_month": 1000,
        "max_users": 25,
        "scanners": [ScannerType.WEB, ScannerType.API,ScannerType.SCA],
        "retention_days": 180,
        "api_requests_per_day": 10000,
        "features": [
            "custom_branding",
            "sso",
            "compliance_reports",
            "webhook_automation",
            "dedicated_support",
        ],
        "max_scan_targets": 50,
        "concurrent_scans": 5,
    },
    PlanType.ENTERPRISE: {
        "max_scans_per_month": -1,  # Unlimited
        "max_users": -1,  # Unlimited
        "scanners": [ScannerType.WEB, ScannerType.API,ScannerType.SCA],
        "retention_days": 1825,  # 5 years
        "api_requests_per_day": -1,  # Unlimited
        "features": [
            "white_label",
            "on_premise",
            "custom_integrations",
            "audit_package",
            "account_manager",
            "sla_999",
        ],
        "max_scan_targets": -1,  # Unlimited
        "concurrent_scans": 10,
    },
}

# Stripe Price IDs (to be set after creating products in Stripe)
STRIPE_PRICES: Dict[str, Dict[str, str]] = {
    PlanType.DEVELOPER: {
        "monthly": "price_developer_monthly",
        "yearly": "price_developer_yearly",
    },
    PlanType.STARTUP: {
        "monthly": "price_startup_monthly",
        "yearly": "price_startup_yearly",
    },
    PlanType.PROFESSIONAL: {
        "monthly": "price_professional_monthly",
        "yearly": "price_professional_yearly",
    },
}

# Role Permissions
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    UserRole.OWNER: [
        "user:create",
        "user:read",
        "user:update",
        "user:delete",
        "scan:create",
        "scan:read",
        "scan:update",
        "scan:delete",
        "tenant:update",
        "tenant:delete",
        "billing:manage",
    ],
    UserRole.ADMIN: [
        "user:create",
        "user:read",
        "user:update",
        "scan:create",
        "scan:read",
        "scan:update",
        "scan:delete",
    ],
    UserRole.ANALYST: [
        "scan:create",
        "scan:read",
        "scan:update",
    ],
    UserRole.VIEWER: [
        "scan:read",
    ],
}

# OWASP Top 10 Web Vulnerabilities
OWASP_WEB_TOP_10 = [
    "A01:2021-Broken Access Control",
    "A02:2021-Cryptographic Failures",
    "A03:2021-Injection",
    "A04:2021-Insecure Design",
    "A05:2021-Security Misconfiguration",
    "A06:2021-Vulnerable and Outdated Components",
    "A07:2021-Identification and Authentication Failures",
    "A08:2021-Software and Data Integrity Failures",
    "A09:2021-Security Logging and Monitoring Failures",
    "A10:2021-Server-Side Request Forgery",
]

# OWASP API Security Top 10
OWASP_API_TOP_10 = [
    "API1:2023-Broken Object Level Authorization",
    "API2:2023-Broken Authentication",
    "API3:2023-Broken Object Property Level Authorization",
    "API4:2023-Unrestricted Resource Consumption",
    "API5:2023-Broken Function Level Authorization",
    "API6:2023-Unrestricted Access to Sensitive Business Flows",
    "API7:2023-Server Side Request Forgery",
    "API8:2023-Security Misconfiguration",
    "API9:2023-Improper Inventory Management",
    "API10:2023-Unsafe Consumption of APIs",
]
