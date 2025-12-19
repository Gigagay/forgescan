# backend/app/db/repositories/base.py
from typing import Generic, TypeVar, Type, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update, delete
from sqlalchemy.sql import Select

ModelType = TypeVar("ModelType")


class BaseRepository(Generic[ModelType]):
    """Base repository with common CRUD operations"""
    
    def __init__(self, model: Type[ModelType], session: AsyncSession):
        self.model = model
        self.session = session
    
    async def get(self, id: any) -> Optional[ModelType]:
        """Get by ID"""
        result = await self.session.execute(
            select(self.model).where(self.model.id == id)
        )
        return result.scalar_one_or_none()
    
    async def get_multi(
        self, 
        skip: int = 0, 
        limit: int = 100,
        filters: Optional[dict] = None
    ) -> List[ModelType]:
        """Get multiple records"""
        query = select(self.model)
        
        if filters:
            for key, value in filters.items():
                query = query.where(getattr(self.model, key) == value)
        
        query = query.offset(skip).limit(limit)
        result = await self.session.execute(query)
        return result.scalars().all()
    
    async def create(self, obj_in: dict) -> ModelType:
        """Create new record"""
        db_obj = self.model(**obj_in)
        self.session.add(db_obj)
        await self.session.commit()
        await self.session.refresh(db_obj)
        return db_obj
    
    async def update(self, id: any, obj_in: dict) -> Optional[ModelType]:
        """Update record"""
        await self.session.execute(
            update(self.model).where(self.model.id == id).values(**obj_in)
        )
        await self.session.commit()
        return await self.get(id)
    
    async def delete(self, id: any) -> bool:
        """Delete record"""
        result = await self.session.execute(
            delete(self.model).where(self.model.id == id)
        )
        await self.session.commit()
        return result.rowcount > 0


