from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Session, User


class SessionService:
    """Сервис работы с сессиями в БД."""

    @staticmethod
    async def get_active_session_by_jti(
        db: AsyncSession, user_id: UUID, refresh_jti: str
    ) -> Session | None:
        """Возвращает активную (не отозванную) сессию по `refresh_jti`.

        Сессия считается активной, если `is_revoked = False`.
        """
        return await db.scalar(
            select(Session).where(
                Session.user_id == user_id,
                Session.refresh_jti == refresh_jti,
                Session.is_revoked.is_(False),
            )
        )

    @staticmethod
    async def get_user_by_id(db: AsyncSession, user_id: UUID) -> User | None:
        """Возвращает пользователя по id и проверяет, что он активен."""
        user = await db.get(User, user_id)
        if user is not None and not user.is_active:
            raise HTTPException(
                status_code=401, detail="Пользователь не найден или неактивен"
            )
        return user

    @staticmethod
    async def revoke_session(db: AsyncSession, session: Session) -> None:
        """Отзывает сессию (ставит `is_revoked = True`)."""
        session.is_revoked = True
        await db.commit()

    @staticmethod
    async def update_session_refresh_jti(
        db: AsyncSession, session: Session, new_jti: str, new_exp: int
    ) -> None:
        """Обновляет `refresh_jti` и срок жизни сессии."""
        session.refresh_jti = new_jti
        session.expires_at = datetime.fromtimestamp(new_exp, tz=timezone.utc)
        await db.commit()
