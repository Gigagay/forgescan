# scripts/seed-data.py
"""Seed database with test data"""
import asyncio
import sys
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent.parent / "backend"))

from app.db.database import async_session_local
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.tenant_repository import TenantRepository
from app.core.security import get_password_hash


async def seed_data():
    """Seed database with test data"""
    async with async_session_local() as session:
        tenant_repo = TenantRepository(session)
        user_repo = UserRepository(session)

        # Create test tenant
        tenant = await tenant_repo.create({
            "id": "test-tenant-001",
            "name": "Test Company",
            "plan": "developer",
            "max_scans": 50,
            "max_users": 1,
        })

        print(f"Created tenant: {tenant.name}")

        # Create test user
        user = await user_repo.create({
            "email": "demo@forgescan.io",
            "hashed_password": get_password_hash("Demo123!"),
            "full_name": "Demo User",
            "tenant_id": tenant.id,
            "role": "owner",
            "is_active": True,
            "is_verified": True,
        })

        print(f"Created user: {user.email}")
        print("\nLogin credentials:")
        print("Email: demo@forgescan.io")
        print("Password: Demo123!")


if __name__ == "__main__":
    asyncio.run(seed_data())

