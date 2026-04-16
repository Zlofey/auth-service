from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import blacklist_jti, is_blacklisted
from app.schemas import TokenOut
from app.services.race_condition_service import RaceConditionService
from app.services.session_service import SessionService
from app.services.token_service import TokenService


class RefreshRotationService:
    """Сервис ротации refresh-токенов.

    Реализует Refresh Token Rotation с защитой от гонки запросов:
    - Для одного `old_jti` одновременно выполняется только одна ротация (Redis lock).
    - Параллельные запросы получают готовый результат из grace-кэша.
    """

    @staticmethod
    def _create_token_payload(user) -> dict:
        """Собирает payload для JWT из данных пользователя."""
        return {
            "sub": str(user.id),
            "username": user.username,
            "role": user.role,
        }

    @staticmethod
    async def _validate_refresh_token(refresh_token: str) -> tuple[str, int, str]:
        """Валидирует refresh-токен и достаёт ключевые поля.

        Возвращает:
        - `old_jti`: идентификатор refresh-токена
        - `old_exp`: время истечения (unix)
        - `user_id`: строковый UUID пользователя (claim `sub`)
        """
        payload = TokenService.decode_token(refresh_token)
        TokenService.validate_token_type(payload, "refresh")

        old_jti = TokenService.get_jti(payload)
        old_exp = payload.get("exp")
        user_id = TokenService.get_user_id(payload)

        if old_exp is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        return old_jti, int(old_exp), user_id

    @staticmethod
    async def _check_blacklist(old_jti: str) -> None:
        """Проверяет, не отозван ли refresh-токен."""
        if await is_blacklisted(old_jti):
            raise HTTPException(status_code=401, detail="Token revoked")

    @staticmethod
    async def _handle_race_condition(old_jti: str) -> TokenOut | None:
        """Обрабатывает гонку запросов при refresh.

        Если lock не удалось взять, значит другой запрос уже делает rotation.
        Тогда пытаемся быстро получить готовый ответ из grace-кэша.
        """
        lock_acquired = await RaceConditionService.acquire_refresh_lock(old_jti)

        if not lock_acquired:
            # Другой запрос уже в процессе — ждём результат короткое время.
            cached = await RaceConditionService.wait_for_grace_period(old_jti)
            if cached:
                return cached
            raise HTTPException(status_code=409, detail="Refresh in progress, retry")

        # Lock взят — можно выполнять rotation.
        return None

    @staticmethod
    def _generate_new_tokens(user) -> tuple[str, str, str, int]:
        """Генерирует новую пару (access/refresh) и метаданные нового refresh."""
        token_payload = RefreshRotationService._create_token_payload(user)
        return TokenService.create_token_pair_with_metadata(token_payload)

    @staticmethod
    async def _get_session_and_user(db: AsyncSession, user_id_str: str, old_jti: str):
        """Загружает сессию и пользователя, валидирует их состояние."""
        user_id = UUID(user_id_str)

        session = await SessionService.get_active_session_by_jti(db, user_id, old_jti)
        if not session:
            raise HTTPException(status_code=401, detail="Session not found or revoked")

        user = await SessionService.get_user_by_id(db, user_id)
        if not user:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        return session, user

    @staticmethod
    async def _apply_rotation(
        db: AsyncSession,
        *,
        session,
        user,
        old_jti: str,
        old_exp: int,
    ) -> TokenOut:
        """Делает rotation: blacklist старого refresh, обновление session, выдача новой пары."""
        new_access, new_refresh, new_jti, new_exp = (
            RefreshRotationService._generate_new_tokens(user)
        )

        await blacklist_jti(old_jti, old_exp)
        await SessionService.update_session_refresh_jti(db, session, new_jti, new_exp)

        result = TokenOut(
            access_token=new_access,
            refresh_token=new_refresh,
            token_type="bearer",
        )
        await RaceConditionService.store_grace_result(old_jti, result)
        return result

    @staticmethod
    async def refresh_tokens(db: AsyncSession, refresh_token: str) -> TokenOut:
        """Обновляет токены по refresh-токену (Refresh Token Rotation)."""
        old_jti, old_exp, user_id_str = (
            await RefreshRotationService._validate_refresh_token(refresh_token)
        )
        await RefreshRotationService._check_blacklist(old_jti)

        cached = await RefreshRotationService._handle_race_condition(old_jti)
        if cached:
            return cached

        session, user = await RefreshRotationService._get_session_and_user(
            db, user_id_str, old_jti
        )
        return await RefreshRotationService._apply_rotation(
            db,
            session=session,
            user=user,
            old_jti=old_jti,
            old_exp=old_exp,
        )

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

        # Сразу отзываем refresh в Redis (stateless invalidation).
        await blacklist_jti(jti, int(exp))

        # Если сессия есть в БД — помечаем revoked.
        user_id = UUID(user_id_str)
        session = await SessionService.get_active_session_by_jti(db, user_id, jti)
        if session:
            await SessionService.revoke_session(db, session)
