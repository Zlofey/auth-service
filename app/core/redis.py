import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()

# Создаём клиент, но НЕ подключаемся сразу
redis_client = redis.from_url(
    settings.REDIS_URL,
    decode_responses=True,  # Автоматически декодирует байты в строки
    encoding="utf-8",
)


async def connect_redis() -> None:
    await redis_client.ping()
    print("Redis connected")


async def close_redis() -> None:
    await redis_client.close()
    print("Redis closed")
