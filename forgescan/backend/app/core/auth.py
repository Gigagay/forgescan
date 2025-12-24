# backend/app/core/auth.py
"""Compatibility shim for authentication helpers used in tests and other modules."""
from app.core.security import create_access_token, get_password_hash as hash_password, decode_token
from typing import Dict, Any

__all__ = ["create_access_token", "hash_password", "verify_token", "get_current_active_user"]


def verify_token(token: str) -> Dict[str, Any]:
    """Verify and decode a JWT token."""
    try:
        return decode_token(token)
    except Exception:
        return {}


async def get_current_active_user(token: str = None):
    """
    Dependency function to get current active user from token.
    This is a placeholder for compatibility.
    """
    if not token:
        return None
    
    try:
        payload = decode_token(token)
        return payload.get("sub")
    except Exception:
        return None
