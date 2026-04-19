from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import blacklist_jti
from app.db.models import Session, User
from app.schemas import TokenOut
from app.services.token_service import TokenService
from app.utils import verify_password


class SessionService:
    """Сервис работы с сессиями."""

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

    @staticmethod
    async def create_session_with_tokens(
        user: User,
        db: AsyncSession,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> TokenOut:
        """Создаёт токены и сохраняет сессию в базе данных."""
        token_payload = TokenService.user_token_data(user)

        access_token, refresh_token, refresh_jti, exp = (
            TokenService.create_token_pair_with_metadata(token_payload)
        )

        expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)

        session = Session(
            user_id=user.id,
            refresh_jti=refresh_jti,
            user_agent=user_agent,
            ip=ip,
            expires_at=expires_at,
        )

        db.add(session)
        await db.commit()

        return TokenOut(access_token=access_token, refresh_token=refresh_token)

    @staticmethod
    async def login(
        db: AsyncSession,
        username: str,
        password: str,
        user_agent: str | None = None,
        ip: str | None = None,
    ) -> TokenOut:
        """Логин пользователя: проверяет пароль и создаёт сессию."""
        user = await db.scalar(select(User).where(User.username == username))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        if not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="User is inactive"
            )

        return await SessionService.create_session_with_tokens(user, db, user_agent, ip)

    @staticmethod
    async def logout(db: AsyncSession, refresh_token: str) -> None:
        """Логаут: blacklist refresh-токена и отзыв сессии в БД (если найдём)."""
        payload = TokenService.decode_token(refresh_token)
        TokenService.validate_token_type(payload, "refresh")

        jti = TokenService.get_jti(payload)
        exp = payload.get("exp")
        user_id_str = TokenService.get_user_id(payload)

        if not exp:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        await blacklist_jti(jti, int(exp))

        user_id = UUID(user_id_str)
        session = await SessionService.get_active_session_by_jti(db, user_id, jti)
        if session:
            await SessionService.revoke_session(db, session)
