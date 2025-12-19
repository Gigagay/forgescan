"""
Pytest configuration and fixtures
Shared test setup for all test modules
"""

import pytest
import asyncio
from typing import AsyncGenerator, Generator
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from httpx import AsyncClient
import redis
from datetime import datetime, timedelta

from app.main import app
from app.db.base import Base
from app.db.session import get_db
from app.core.config import settings
from app.db.models.user import User
from app.db.models.tenant import Tenant
from app.core.auth import create_access_token, hash_password

# Test database URL
# Use the postgres service in docker-compose when running inside the backend container
TEST_DATABASE_URL = "postgresql+asyncpg://forgescan:password@postgres:5432/forgescan"

# Create test engine
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    poolclass=NullPool,
    echo=True
)

TestSessionLocal = async_sessionmaker(
    test_engine,
    class_=AsyncSession,
    expire_on_commit=False
)


@pytest.fixture(scope="session")
def event_loop() -> Generator:
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Create clean database for each test"""
    
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    
    async with TestSessionLocal() as session:
        yield session
        await session.rollback()


@pytest.fixture(scope="function")
def client(db_session: AsyncSession) -> TestClient:
    """Create test client with database override"""
    
    def override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    app.dependency_overrides.clear()


@pytest.fixture
async def test_tenant(db_session: AsyncSession) -> Tenant:
    """Create test tenant"""
    
    tenant = Tenant(
        id="test-tenant-123",
        name="Test Company",
        subscription_tier="professional",
        created_at=datetime.utcnow()
    )
    
    db_session.add(tenant)
    await db_session.commit()
    await db_session.refresh(tenant)
    
    return tenant


@pytest.fixture
async def test_user(db_session: AsyncSession, test_tenant: Tenant) -> User:
    """Create test user"""
    
    user = User(
        email="test@example.com",
        full_name="Test User",
        hashed_password=hash_password("TestPassword123!"),
        tenant_id=test_tenant.id,
        role="admin",
        is_active=True,
        email_verified=True
    )
    
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest.fixture
def auth_headers(test_user: User) -> dict:
    """Generate auth headers for test user"""
    
    access_token = create_access_token(
        data={"sub": test_user.email, "user_id": str(test_user.id)}
    )
    
    return {"Authorization": f"Bearer {access_token}"}


@pytest.fixture
def redis_client():
    """Redis client for testing"""
    
    client = redis.Redis(
        host='localhost',
        port=6379,
        db=1,  # Use separate DB for tests
        decode_responses=True
    )
    
    yield client
    
    # Cleanup
    client.flushdb()
