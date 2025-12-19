# backend/app/db/session.py
"""Compatibility shim: expose get_db where tests expect it."""
from app.db.database import get_db

__all__ = ["get_db"]
