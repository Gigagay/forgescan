# backend/app/db/repositories/user_repository.py
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models.user import User
from app.db.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository for User operations"""
    
    def __init__(self, session: AsyncSession):
        super().__init__(User, session)
    
    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()
    
    async def get_by_oauth(self, provider: str, oauth_id: str) -> Optional[User]:
        """Get user by OAuth provider and ID"""
        result = await self.session.execute(
            select(User)
            .where(User.oauth_provider == provider)
            .where(User.oauth_id == oauth_id)
        )
        return result.scalar_one_or_none()

