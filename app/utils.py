from typing import TYPE_CHECKING

import bcrypt

if TYPE_CHECKING:
    from fastapi import Request


def get_client_ip(request: "Request") -> str | None:
    """Извлекает реальный IP клиента из запроса.

    Проверяет заголовки x-forwarded-for и x-real-ip для прокси/балансировщиков.
    """
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip

    return request.client.host if request.client else None


def get_client_info(request: "Request") -> tuple[str | None, str | None]:
    """Извлекает user-agent и IP из запроса."""
    user_agent = request.headers.get("user-agent")
    ip = get_client_ip(request)
    return user_agent, ip


def hash_password(password: str) -> str:
    password = password[:72]
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    plain_password = plain_password[:72]
    return bcrypt.checkpw(
        plain_password.encode("utf-8"), hashed_password.encode("utf-8")
    )
