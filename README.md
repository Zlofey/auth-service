# auth-service

Сервис аутентификации с JWT токенами, refresh token rotation и защитой от race conditions.

## Возможности

- Регистрация, логин, логаут
- Refresh token rotation с защитой от race conditions
- Blacklist отозванных токенов в Redis
- Поддержка ролей: admin, staff, client
- Логирование запросов

## Запуск через Docker Compose

```bash
# Копируем .env.example в .env (если нужно настроить переменные)
cp .env.example .env

# Запускаем все сервисы
docker compose up -d

# Останавливаем сервисы
docker compose down

# Смотрим логи
docker compose logs -f app
```

Сервис доступен по адресу (по умолчанию):

- API документация: http://localhost:${APP_PORT:-8000}/docs

При запуске контейнера автоматически применяются все миграции базы данных через Alembic.

## API эндпоинты

- `POST /auth/register` - регистрация нового пользователя
- `POST /auth/login` - логин
- `POST /auth/refresh` - обновление токена
- `POST /auth/logout` - логаут
