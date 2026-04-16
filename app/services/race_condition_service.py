import asyncio
import time

from app.core.redis import acquire_refresh_lock, get_refresh_grace, set_refresh_grace
from app.schemas import TokenOut


class RaceConditionService:
    """Сервис защиты от гонки запросов при refresh."""

    @staticmethod
    async def wait_for_grace_period(
        old_jti: str, max_wait_seconds: float = 3.0
    ) -> TokenOut | None:
        """
        Ждёт результат ротации другого параллельного запроса.

        Сценарий:
        - вкладка A взяла lock и делает rotation
        - вкладка B lock не взяла и должна получить уже готовую пару токенов

        Для этого A кладёт результат в grace-кэш, а B читает его оттуда.
        """
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

    @staticmethod
    async def acquire_refresh_lock(old_jti: str, ttl_seconds: int = 10) -> bool:
        """Пытается взять lock на `old_jti`.

        Возвращает `True`, если lock взяли (мы "первый" запрос), иначе `False`.
        """
        return await acquire_refresh_lock(old_jti, ttl_seconds)
