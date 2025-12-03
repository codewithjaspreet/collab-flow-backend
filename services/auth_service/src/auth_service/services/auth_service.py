import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth_service.models.user import User
from auth_service.utils.password import hashed_password,verify_password

from auth_service.schemas.user import RegisterRequest,LoginRequest
from auth_service.core.security import (
    create_access_token,
    create_refresh_token
)
from fastapi import HTTPException,status


async def get_user_by_email(db:AsyncSession, email:str) -> User | None:

    stmt = select(User).where(User.email == email)
    result = await db.execute(statement=stmt)
    return result.scalars().one_or_none()


async def create_user(db:AsyncSession , payload: RegisterRequest):
    existing = await get_user_by_email(db, payload.email)

    if existing:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    new_user = User(
        email = payload.email,
        hash_password = hashed_password(payload.password),
        full_name = payload.full_name,
        role = 'user',
        is_active = True,

    )

    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    return new_user


async def authenticate_user(db:AsyncSession, email:str , password:str) -> User | None:

    user = await get_user_by_email(db,email=email)
    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


async def login_user(db:AsyncSession, payload: LoginRequest):
    user = await authenticate_user(db, payload.email, payload.password)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    access = create_access_token(subject=user.id.toint() , extra={"role" : user.role})
    refresh = create_refresh_token(subject=user.id.toint())

    return {
        "access_token" : access,
        "refresh_token" : refresh,
        "token_type" : "bearer"
    }
