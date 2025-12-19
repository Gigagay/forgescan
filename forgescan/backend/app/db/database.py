# backend/app/db/database.py
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from app.core.config import settings

# Create async engine
engine = create_async_engine(
    settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    echo=settings.DEBUG,
)

# Create async session factory
async_session_local = sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Database session dependency"""
    async with async_session_local() as session:
        try:
            yield session
        finally:
            await session.close()


async def set_tenant_context(session: AsyncSession, tenant_id: str):
    """Set tenant context for Row Level Security"""
    await session.execute(f"SET app.current_tenant = '{tenant_id}'")


async def init_db():
    """Initialize database (create tables)"""
    from app.db.base import Base
    
    async with engine.begin() as conn:
        # Import all models to ensure they're registered
        from app.db.models import user, tenant, scan, finding, audit_log, usage
        
        # Create tables
        await conn.run_sync(Base.metadata.create_all)


async def close_db():
    """Close database connections"""
    await engine.dispose()

