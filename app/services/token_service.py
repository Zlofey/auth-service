from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import jwt
from fastapi import HTTPException, status

from app.core.config import get_settings

settings = get_settings()
ALGORITHM = "HS256"


class TokenService:
    """Сервис для работы с JWT токенами.

    Этот класс инкапсулирует все операции с JWT:
    - Создание access и refresh токенов
    - Декодирование и валидация токенов
    - Извлечение метаданных токенов

    Использование класса упрощает мокинг в тестах и обеспечивает
    лучшую организацию кода по сравнению с отдельными функциями.
    """

    @staticmethod
    def _create_token(
        data: dict[str, Any], expires_delta: timedelta, token_type: str
    ) -> str:
        """Создаёт JWT токен со стандартными claims.

        Args:
            data: Данные для кодирования в payload
            expires_delta: Время жизни токена
            token_type: "access" или "refresh"

        Returns:
            Закодированная строка JWT токена
        """
        payload = data.copy()
        now = datetime.now(timezone.utc)

        payload.update(
            {
                "exp": now + expires_delta,
                "iat": now,
                "jti": str(uuid.uuid4()),  # Уникальный ID токена
                "type": token_type,
            }
        )
        return jwt.encode(payload, settings.JWT_SECRET, algorithm=ALGORITHM)

    @classmethod
    def create_access_token(
        cls, data: dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        """Создаёт access токен.

        Args:
            data: Данные пользователя для кодирования (sub, username, role)
            expires_delta: Кастомный TTL, по умолчанию 15 минут

        Returns:
            Строка access токена
        """
        ttl = expires_delta or timedelta(minutes=15)
        return cls._create_token(data=data, expires_delta=ttl, token_type="access")

    @classmethod
    def create_refresh_token(
        cls, data: dict[str, Any], expires_delta: Optional[timedelta] = None
    ) -> str:
        """Создаёт refresh токен.

        Args:
            data: Данные пользователя для кодирования (sub, username, role)
            expires_delta: Кастомный TTL, по умолчанию 7 дней

        Returns:
            Строка refresh токена
        """
        ttl = expires_delta or timedelta(days=7)
        return cls._create_token(data=data, expires_delta=ttl, token_type="refresh")

    @staticmethod
    def decode_token(token: str) -> dict[str, Any]:
        """Валидирует и декодирует JWT токен.

        Args:
            token: Строка JWT токена

        Returns:
            Декодированный payload токена

        Raises:
            HTTPException: Если токен невалиден, истёк или malformed
        """
        try:
            payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[ALGORITHM])
            return payload
        except jwt.PyJWTError as exc:
            # PyJWTError включает: неверная подпись, истёкший токен, malformed и т.д.
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
            ) from exc

    @staticmethod
    def get_jti(payload: dict[str, Any]) -> str:
        """Извлекает JTI (JWT ID) из payload токена.

        Args:
            payload: Декодированный JWT payload

        Returns:
            Строка JTI

        Raises:
            HTTPException: Если JTI отсутствует в payload
        """
        jti = payload.get("jti")
        if not jti:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail="Token jti missing"
            )
        return str(jti)

    @staticmethod
    def get_user_id(payload: dict[str, Any]) -> str:
        """Извлекает ID пользователя (claim sub) из payload токена.

        Args:
            payload: Декодированный JWT payload

        Returns:
            Строка ID пользователя

        Raises:
            HTTPException: Если claim sub отсутствует
        """
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token sub claim missing",
            )
        return str(user_id)

    @staticmethod
    def validate_token_type(payload: dict[str, Any], expected_type: str) -> None:
        """Валидирует, что токен имеет ожидаемый тип.

        Args:
            payload: Декодированный JWT payload
            expected_type: "access" или "refresh"

        Raises:
            HTTPException: Если тип токена не совпадает
        """
        token_type = payload.get("type")
        if token_type != expected_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Wrong token type. Expected {expected_type}, got {token_type}",
            )

    @staticmethod
    def create_token_pair_with_metadata(
        data: dict[str, Any],
        expires_delta: timedelta | None = None,
    ) -> tuple[str, str, str, int]:
        """Создаёт пару токенов и возвращает их с метаданными refresh-токена.

        Возвращает:
        - access_token: JWT access токен
        - refresh_token: JWT refresh токен
        - refresh_jti: идентификатор refresh-токена
        - refresh_exp: время истечения refresh-токена (unix timestamp)
        """
        access_token = TokenService.create_access_token(data, expires_delta)
        refresh_token = TokenService.create_refresh_token(data)

        refresh_payload = TokenService.decode_token(refresh_token)
        refresh_jti = TokenService.get_jti(refresh_payload)
        refresh_exp = refresh_payload.get("exp")

        if not refresh_exp:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Refresh token missing exp",
            )

        return access_token, refresh_token, refresh_jti, int(refresh_exp)
