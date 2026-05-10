FROM python:3.12-slim

ARG VERSION=dev
ARG GIT_COMMIT=unknown

ENV APP_VERSION=${VERSION}

LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" structlog prometheus-client redis

COPY common/ ./common/
RUN pip install --no-cache-dir ./common/

COPY services/auth/ ./service/
RUN pip install --no-cache-dir ./service/

# Root alembic tree (creates the four logical schemas + service roles).
# Baked in so this image can also run as the one-shot root-migrate container
# in docker-compose.yml. The auth service itself does not import from these.
COPY alembic.ini ./alembic.ini
COPY alembic/ ./alembic/

EXPOSE 8000

CMD ["uvicorn", "auth_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
