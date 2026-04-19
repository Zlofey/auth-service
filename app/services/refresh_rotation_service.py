import asyncio
import time
from uuid import UUID

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.redis import (
    acquire_refresh_lock,
    blacklist_jti,
    get_refresh_grace,
    is_blacklisted,
    set_refresh_grace,
)
from app.schemas import TokenOut
from app.services.session_service import SessionService
from app.services.token_service import TokenService
from app.services.user_service import UserService


class RefreshRotationService:
    """Сервис ротации refresh-токенов.

    Реализует Refresh Token Rotation с защитой от гонки запросов:
    - Для одного `old_jti` одновременно выполняется только одна ротация (Redis lock).
    - Параллельные запросы получают готовый результат из grace-кэша.
    """

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
        """Сериализует параллельные refresh с одним и тем же `old_jti`.

        Redis SET NX на ключ `lock:refresh:{old_jti}`: только один запрос проходит
        дальше и выполняет rotation; остальные не должны дублировать работу.

        Если lock не взят — другой инстанс уже крутит rotation. Тогда коротко
        опрашиваем grace-кэш: победитель кладёт туда готовую пару токенов, чтобы
        «опоздавшие» могли вернуть тот же ответ без повторной ротации.

        Возвращает `TokenOut` из кэша или `None`, если мы держим lock и должны
        выполнить rotation сами. Если кэш так и не заполнился — 409 (клиент
        может безопасно повторить запрос).
        """
        lock_acquired = await acquire_refresh_lock(old_jti)

        if not lock_acquired:
            # Другой запрос уже в процессе — ждём результат короткое время.
            cached = await RefreshRotationService.wait_for_grace_period(old_jti)
            if cached:
                return cached
            raise HTTPException(status_code=409, detail="Refresh in progress, retry")

        # Lock взят — можно выполнять rotation.
        return None

    @staticmethod
    def _generate_new_tokens(user) -> tuple[str, str, str, int]:
        """Генерирует новую пару (access/refresh) и метаданные нового refresh."""
        token_payload = TokenService.user_token_data(user)
        return TokenService.create_token_pair_with_metadata(token_payload)

    @staticmethod
    async def _get_session_and_user(db: AsyncSession, user_id_str: str, old_jti: str):
        """Загружает сессию и пользователя, валидирует их состояние."""
        user_id = UUID(user_id_str)

        session = await SessionService.get_active_session_by_jti(db, user_id, old_jti)
        if not session:
            raise HTTPException(status_code=401, detail="Session not found or revoked")

        user = await UserService.get_user_by_id(db, user_id)

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
        await RefreshRotationService.store_grace_result(old_jti, result)
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
    async def wait_for_grace_period(
        old_jti: str, max_wait_seconds: float = 3.0
    ) -> TokenOut | None:
        """Ждёт результат ротации другого параллельного запроса."""
        deadline = time.monotonic() + max_wait_seconds
        while time.monotonic() < deadline:
            cached = await get_refresh_grace(old_jti)
            if cached:
                return TokenOut(**cached)
            await asyncio.sleep(0.25)
        return None

    @staticmethod
    async def store_grace_result(old_jti: str, tokens: TokenOut) -> None:
        """Кладёт результат refresh в grace-кэш для других параллельных запросов."""
        await set_refresh_grace(old_jti, tokens.model_dump(), ttl_seconds=10)
