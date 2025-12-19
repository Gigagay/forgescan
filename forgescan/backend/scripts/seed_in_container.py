import asyncio
from app.db.database import async_session_local
from app.db.repositories.user_repository import UserRepository
from app.db.repositories.tenant_repository import TenantRepository
from app.core.security import get_password_hash

async def seed_data():
    async with async_session_local() as session:
        tenant_repo = TenantRepository(session)
        user_repo = UserRepository(session)

        # Create or get test tenant
        existing_tenant = await tenant_repo.get_by_id("test-tenant-001")
        if existing_tenant:
            tenant = existing_tenant
            print(f"Tenant already exists: {tenant.name}")
        else:
            tenant = await tenant_repo.create({
                "id": "test-tenant-001",
                "name": "Test Company",
                "plan": "developer",
                "max_scans": 50,
                "max_users": 1,
            })
            print(f"Created tenant: {tenant.name}")

        # Create or get test user
        existing_user = await user_repo.get_by_email("demo@forgescan.io")
        if existing_user:
            user = existing_user
            print(f"User already exists: {user.email}")
        else:
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
