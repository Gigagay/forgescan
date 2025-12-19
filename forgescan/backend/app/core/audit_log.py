# backend/app/core/audit_log.py
"""
Lightweight audit logging stub for test environment
Provides minimal types so imports succeed during tests and startup.
"""
from enum import Enum
from typing import Optional, Dict, Any
from fastapi import Request
import asyncio
import functools

class AuditEventType(str, Enum):
    LOGIN_SUCCESS = "auth.login.success"
    LOGIN_FAILURE = "auth.login.failure"
    LOGOUT = "auth.logout"
    SCAN_CREATED = "scan.created"
    SCAN_DELETED = "scan.deleted"
    API_REQUEST = "api.request"

class AuditLogger:
    """Minimal no-op audit logger used in testing/dev environments."""
    def __init__(self, *args, **kwargs):
        pass

    async def log_event(self, *, event_type: str, user_id: str | None = None, tenant_id: str | None = None, details: dict | None = None, ip_address: str | None = None, user_agent: str | None = None, request_id: str | None = None) -> None:
        """Async audit log inserter. Implementations should use async DB client or run blocking IO in executor."""
        try:
            # If the underlying implementation is async (e.g. async DB client), call it directly
            if hasattr(self, "_log_event_async_impl"):
                await self._log_event_async_impl(event_type=event_type, user_id=user_id, tenant_id=tenant_id, details=details, ip_address=ip_address, user_agent=user_agent, request_id=request_id)
                return

            # Fallback: run blocking sync implementation in threadpool
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, functools.partial(self._log_event_sync_impl, event_type, user_id, tenant_id, details, ip_address, user_agent, request_id))
        except Exception:
            # swallow here — callers should decide how to handle
            raise

    # backward-compatible sync wrapper
    def log_event_sync(self, *args, **kwargs):
        """Sync wrapper kept for backwards compatibility."""
        return self._log_event_sync_impl(*args, **kwargs)

    # internal sync implementation (existing code path)
    def _log_event_sync_impl(self, event_type: str, user_id: str | None, tenant_id: str | None, details: dict | None, ip_address: str | None, user_agent: str | None, request_id: str | None):
        # ...existing sync code that writes to DB / external systems...
        pass

    # optional async implementation hook (if you want to implement directly)
    async def _log_event_async_impl(self, *args, **kwargs):
        # existing async implementation could be placed here if present
        raise NotImplementedError


async def audit_log_middleware(request: Request, call_next):
    """Middleware that logs request metadata (no-op in test/dev)."""
    # Attach a request id if needed
    response = await call_next(request)
    return response