from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str
    DEBUG: bool = True
    JWT_SECRET: str
    REDIS_URL: str
    DATABASE_URL: str

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
    )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
