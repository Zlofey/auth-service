from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.enums import UserRole
from app.utils import hash_password


class UserService:
    """Сервис работы с пользователями."""

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
        """Возвращает пользователя по id и проверяет, что он активен."""
        user = await db.get(User, user_id)
        if user is not None and not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or inactive",
            )
        return user

    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> User | None:
        """Возвращает пользователя по имени."""
        return await db.scalar(select(User).where(User.username == username))

    @staticmethod
    async def create_user(
        db: AsyncSession, username: str, password: str, role: UserRole = UserRole.CLIENT
    ) -> User:
        """Создаёт нового пользователя."""
        existing = await UserService.get_user_by_username(db, username)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, detail="Username already exists"
            )

        user = User(
            username=username,
            password_hash=hash_password(password),
            role=role,
        )
        db.add(user)
        await db.flush()
        return user
