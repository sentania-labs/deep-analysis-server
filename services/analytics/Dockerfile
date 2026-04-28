FROM python:3.12-slim

ARG VERSION=dev
ARG GIT_COMMIT=unknown

ENV APP_VERSION=${VERSION}

LABEL org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${GIT_COMMIT}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir fastapi "uvicorn[standard]" structlog prometheus-client

COPY common/ ./common/
RUN pip install --no-cache-dir ./common/

COPY services/analytics/ ./service/
RUN pip install --no-cache-dir ./service/

EXPOSE 8000

CMD ["uvicorn", "analytics_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
