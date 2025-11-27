from pydantic_settings import BaseSettings
from pydantic import Field, SecretStr


class Settings(BaseSettings):

    PROJECT_NAME: str = 'Collab Flow Backend'
    DATABASE_URL: str = Field(default=..., validation_alias="DATABASE_URL")
    REDIS_URL: str = Field(default=... , validation_alias="REDIS_URL")
    JWT_SECRET : SecretStr = Field(default=... , validation_alias="JWT_SECRET")
    ACCESS_TOKEN_EXPIRE_MINUTES: int  = 15
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24


    model_config = {
        "env_file": ".env",
        "env_file_encoding" :"utf-8"
    }


settings = Settings()
    