from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from auth_service.db.session import get_db
from auth_service.schemas.user import (
    RegisterRequest,
    LoginRequest,
    UserPublic,
    TokenResponse
)
from auth_service.services.auth_service import (
    create_user,
    login_user
)
from auth_service.core.security import get_current_user
from auth_service.models.user import User


router = APIRouter(prefix="/auth", tags=["Auth"])



@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
async def register(payload: RegisterRequest, db:AsyncSession =Depends(get_db)):
    """
      Register a new user
    """
    user = await create_user(db, payload=payload)
    return user

@router.post("/login" , response_model= TokenResponse)
async def login(payload: LoginRequest, db:AsyncSession = Depends(get_db)):

    """
        Login user using email + password
        Returns access and refresh tokens
    """

    tokens = await login_user(db, payload=payload)
    return tokens

@router.get("/me", response_model=UserPublic)
async def get_me(current_user: User = Depends(get_current_user)):
    """
        Get profile of the currently authenticated user
    """

    return current_user
