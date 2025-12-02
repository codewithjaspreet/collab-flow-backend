from src.auth_service.db.session import Base
from sqlalchemy import Column, Integer,String,Boolean,func,DateTime, null

class User(Base):
    __tablename__ = "users"

    id = Column[int](Integer, primary_key=True,index=True)
    full_name = Column(String(100), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role  = Column(String(50), default="user")
    is_active = Column(Boolean , default=True)
    created_at = Column(DateTime(timezone=True),server_default=func.now())






