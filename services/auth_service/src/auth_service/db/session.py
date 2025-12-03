from curses import echo
from math import e
from sqlalchemy import future
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from auth_service.core.config import settings

# base class for models
Base = declarative_base()

# async engine definition
engine = create_async_engine(
    url=settings.DATABASE_URL,
    echo=True,
)

# session factory
async_session_local = async_sessionmaker(
    engine,
    expire_on_commit=False
)

# db connections
async def get_db():
    async with async_session_local() as session:
        yield session
