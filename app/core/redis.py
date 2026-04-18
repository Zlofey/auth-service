import json
from datetime import datetime, timezone

import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()

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


def _seconds_until(exp_unix: int) -> int:
    now = int(datetime.now(timezone.utc).timestamp())
    ttl = exp_unix - now
    return max(ttl, 1)


async def is_blacklisted(jti: str) -> bool:
    key = f"bl:{jti}"
    return await redis_client.exists(key) == 1


async def blacklist_jti(jti: str, exp_unix: int) -> None:
    key = f"bl:{jti}"
    ttl = _seconds_until(exp_unix)
    await redis_client.set(key, "1", ex=ttl)


async def acquire_refresh_lock(old_jti: str, ttl_seconds: int = 10) -> bool:
    key = f"lock:refresh:{old_jti}"
    result = await redis_client.set(key, "1", nx=True, ex=ttl_seconds)
    return result is True


async def set_refresh_grace(old_jti: str, tokens: dict, ttl_seconds: int = 10) -> None:
    key = f"grace:refresh:{old_jti}"
    await redis_client.set(key, json.dumps(tokens), ex=ttl_seconds)


async def get_refresh_grace(old_jti: str) -> dict | None:
    key = f"grace:refresh:{old_jti}"
    raw = await redis_client.get(key)
    if not raw:
        return None
    return json.loads(raw)
