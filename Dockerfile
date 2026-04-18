FROM python:3.14-slim

WORKDIR /app

RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./

RUN uv sync --frozen --no-dev

COPY . .

COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ARG APP_PORT=8000
ENV APP_PORT=${APP_PORT}

ENTRYPOINT ["docker-entrypoint.sh"]
