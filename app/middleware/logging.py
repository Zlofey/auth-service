import time
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for logging HTTP requests and responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log timing/details."""
        start_time = time.time()

        # Extract client information
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")

        # Log request
        print(
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{request.method} {request.url.path} - "
            f"IP: {client_ip} - UA: {user_agent[:50]}"
        )

        # Process request
        response = await call_next(request)

        # Calculate processing time
        process_time = time.time() - start_time

        # Log response
        print(
            f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"Response {response.status_code} - "
            f"Duration: {process_time:.3f}s"
        )

        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)

        return response

    @staticmethod
    def _get_client_ip(request: Request) -> str:
        """Extract real client IP from request headers."""
        # Check for forwarded IP (proxy/load balancer)
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        # Check for real IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip

        # Fall back to direct connection
        return request.client.host if request.client else "unknown"
