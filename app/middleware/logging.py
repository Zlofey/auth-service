import logging
import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.utils import get_client_ip

logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware для логирования HTTP-запросов и ответов."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Обрабатывает запрос и логирует время/детали."""
        start_time = time.perf_counter()

        client_ip = get_client_ip(request) or "unknown"
        user_agent = request.headers.get("user-agent", "unknown")
        log_ts = time.strftime("%Y-%m-%d %H:%M:%S")

        logger.info(
            "[%s] %s %s - IP: %s - UA: %s",
            log_ts,
            request.method,
            request.url.path,
            client_ip,
            user_agent[:50],
        )

        response = await call_next(request)

        process_time = time.perf_counter() - start_time

        logger.info(
            "[%s] Response %s - Duration: %.3fs",
            time.strftime("%Y-%m-%d %H:%M:%S"),
            response.status_code,
            process_time,
        )

        response.headers["X-Process-Time"] = f"{process_time:.6f}"

        return response
