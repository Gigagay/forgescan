# backend/app/core/audit_log.py
"""
Lightweight audit logging stub for test environment
Provides minimal types so imports succeed during tests and startup.
"""
from enum import Enum
from typing import Optional, Dict
from fastapi import Request

class AuditEventType(str, Enum):
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    SCAN_CREATED = "scan.created"
    SCAN_DELETED = "scan.deleted"
    API_REQUEST = "api.request"

class AuditLogger:
    """Minimal no-op audit logger used in testing/dev environments."""
    def __init__(self):
        pass

    async def log_event(self, event_type: AuditEventType, **kwargs):
        # Intentionally no-op for tests
        return None


async def audit_log_middleware(request: Request, call_next):
    """Middleware that logs request metadata (no-op in test/dev)."""
    # Attach a request id if needed
    response = await call_next(request)
    return response