from enum import Enum

from pydantic import BaseModel, Field


class UserRole(str, Enum):
    """Роли пользователей."""

    ADMIN = "admin"
    STAFF = "staff"
    CLIENT = "client"


class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=3, max_length=128)


class UserLogin(BaseModel):
    username: str
    password: str


class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshIn(BaseModel):
    refresh_token: str


class LogoutIn(BaseModel):
    refresh_token: str
