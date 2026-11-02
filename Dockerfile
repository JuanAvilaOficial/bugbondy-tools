FROM python:3.11-slim

ENV PYTHONPATH=/app/src
WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

COPY src ./src
COPY config ./config
COPY state ./state

CMD ["uv", "run", "bbp", "migrate"]
