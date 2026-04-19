from fastapi import FastAPI

from app.api.auth import router as auth_router
from app.core.config import get_settings
from app.core.redis import close_redis, connect_redis
from app.middleware.logging import LoggingMiddleware

settings = get_settings()

app = FastAPI(
    title=settings.PROJECT_NAME,
    debug=settings.DEBUG,
    on_startup=[connect_redis],
    on_shutdown=[close_redis],
)

app.add_middleware(LoggingMiddleware)

app.include_router(auth_router)


@app.get("/health")
async def health_check() -> dict:
    return {"status": "ok", "service": "auth"}
