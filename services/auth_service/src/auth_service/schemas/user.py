from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from datetime import datetime

class RegisterRequest(BaseModel):
    email:EmailStr
    password:str = Field(..., min_length=8, description='Plain-text password (will be hashed)')
    full_name: Optional[str] = None

class LoginRequest(BaseModel):
    email: EmailStr
    password:str

class UserPublic(BaseModel):
    id:int
    email:EmailStr
    full_name:Optional[str] = None
    role:str = "user"
    is_active:bool = True
    created_at:Optional[datetime] = None

    model_config={"from_attributes" : True}

class TokenResponse(BaseModel):
    access_token:str
    refresh_token:str
    token_type:str = "bearer"


