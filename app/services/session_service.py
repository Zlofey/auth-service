from datetime import datetime, timezone
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import blacklist_jti
from app.db.models import Session, User
from app.schemas import TokenOut
from app.services.token_service import TokenService
from app.services.user_service import UserService
from app.utils import hash_password, verify_password


class SessionService:
    """Сервис работы с сессиями."""

    @staticmethod
    def _parse_refresh_token(refresh_token: str) -> tuple[str, int, UUID]:
        """Валидирует refresh-токен и возвращает (jti, exp, user_id)."""
        payload = TokenService.decode_token(refresh_token)
        TokenService.validate_token_type(payload, "refresh")

        jti = TokenService.get_jti(payload)
        exp = payload.get("exp")
        if not exp:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user_id = UUID(TokenService.get_user_id(payload))
        return jti, int(exp), user_id

    @staticmethod
    async def _blacklist_refresh_token(jti: str, exp: int) -> None:
        """Отзывает refresh-токен в Redis blacklist до его expiry."""
        await blacklist_jti(jti, exp)

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
    async def get_active_sessions_by_user_id(
        db: AsyncSession, user_id: UUID
    ) -> list[Session]:
        """Возвращает все активные сессии пользователя."""
        result = await db.scalars(
            select(Session).where(
                Session.user_id == user_id,
                Session.is_revoked.is_(False),
            )
        )
        return list(result.all())

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
        jti, exp, user_id = SessionService._parse_refresh_token(refresh_token)
        await SessionService._blacklist_refresh_token(jti, exp)

        session = await SessionService.get_active_session_by_jti(db, user_id, jti)
        if session:
            await SessionService.revoke_session(db, session)

    @staticmethod
    async def _revoke_all_user_sessions(db: AsyncSession, user_id: UUID) -> None:
        """Отзывает все активные refresh-сессии пользователя и blacklists их JTI."""
        sessions = await SessionService.get_active_sessions_by_user_id(db, user_id)
        for session in sessions:
            exp_dt = session.expires_at
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)

            await SessionService._blacklist_refresh_token(
                session.refresh_jti, int(exp_dt.timestamp())
            )
            session.is_revoked = True

        await db.commit()

    @staticmethod
    async def logout_all(db: AsyncSession, refresh_token: str) -> None:
        """Разлогинивает пользователя на всех устройствах."""
        jti, exp, user_id = SessionService._parse_refresh_token(refresh_token)
        await SessionService._blacklist_refresh_token(jti, exp)
        await SessionService._revoke_all_user_sessions(db, user_id)

    @staticmethod
    async def change_password(
        db: AsyncSession,
        refresh_token: str,
        current_password: str,
        new_password: str,
    ) -> None:
        """Меняет пароль пользователя и отзывает все активные refresh-сессии."""
        jti, exp, user_id = SessionService._parse_refresh_token(refresh_token)
        user = await UserService.get_user_by_id(db, user_id)

        if not verify_password(current_password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials",
            )

        user.password_hash = hash_password(new_password)
        await SessionService._blacklist_refresh_token(jti, exp)
        await SessionService._revoke_all_user_sessions(db, user_id)
