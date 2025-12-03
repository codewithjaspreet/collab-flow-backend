from typing import Any, Dict, Optional
from jose import jwt, JWTError
from datetime import datetime,timedelta

from fastapi import Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from auth_service.db.session import get_db
from auth_service.models.user import User
from auth_service.core.config import settings


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
ALGORITHM = "HS256"

ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
REFRESH_TOKEN_EXPIRE_MINUTES = settings.REFRESH_TOKEN_EXPIRE_MINUTES


def _now_utc() -> datetime:
    return datetime.utcnow()

def create_access_token(subject:str | int , extra: Optional[Dict[str,Any]] = None) -> str:

    """
    Create a signed JWT access token
    - subject : typically user id ( can be int or str)
    - extra : optional dict for extra claims ( like role )

    """

    now = _now_utc()
    expire = now + timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    payload: Dict[str,Any] = {

        "sub" : str(subject),
        "iat" : int(now.timestamp()),
        "exp" : int(expire.timestamp()),
        "type" : "access",
    }

    if extra:
        payload.update(extra)

    secret = settings.JWT_SECRET.get_secret_value() if isinstance(settings.JWT_SECRET,SecretStr) else settings.JWT_SECRET

    token = jwt.encode(payload,secret,algorithm=ALGORITHM)

    return token

def create_refresh_token(subject: str | int) -> str:

    """
     Create a refresh token with longer expiry.
     Typically stored server-side if you need revocation
    """

    now = _now_utc()
    expire = now + timedelta(minutes=int(REFRESH_TOKEN_EXPIRE_MINUTES))
    payload: Dict[str,Any] = {

        "sub" : str(subject),
        "iat" : int(now.timestamp()),
        "exp" : int(expire.timestamp()),
        "type" : "refresh",
    }

    secret = settings.JWT_SECRET.get_secret_value() if isinstance(settings.JWT_SECRET,SecretStr) else settings.JWT_SECRET

    token = jwt.encode(payload,secret,algorithm=ALGORITHM)

    return token


def decode_token(token:str):
    """
     Decode and validate a JWT. Raises HTTPException 401 if invalid or expired.

     Returns the decoded payload as a dict.
    """

    secret = settings.JWT_SECRET.get_secret_value() if isinstance(settings.JWT_SECRET, SecretStr) else settings.JWT_SECRET

    try:
        payload = jwt.decode(token, secret, algorithms=[ALGORITHM])


    except JWTError as e:

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate" : "Bearer"}
        ) from e

    if "sub" not in payload or "exp" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"WWW-Authenticate" : "Bearer"}
        )

    return payload



async def get_current_user(token:str = Depends(oauth2_scheme), db:AsyncSession = Depends(get_db)) -> User:

    payload = decode_token(token)

    token_type = payload.get("type")

    if token_type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:

        user_id_int = int(user_id)

    except(TypeError,ValueError):
        user_id_int = None

    if user_id_int is None:
       raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user id in token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    stmt = select(User).where(User.id == user_id_int)
    result = await db.execute(statement=stmt)
    user: Optional[User] = result.scalars().one_or_none()

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user




def get_current_active_user(current_user:User = Depends(get_current_user)) -> User:
    """
    Additional dependency that ensures the user is active.
    Use in routes where inactive users should be blocked.
    """

    if not getattr(current_user, "is_active" , False):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,detail="Inactive user")
    return current_user

