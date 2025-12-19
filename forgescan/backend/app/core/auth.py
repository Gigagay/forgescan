# backend/app/core/auth.py
"""Compatibility shim for authentication helpers used in tests."""
from app.core.security import create_access_token, get_password_hash as hash_password

__all__ = ["create_access_token", "hash_password"]
