FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi \
    "uvicorn[standard]" \
    structlog \
    prometheus-client \
    pydantic-settings \
    "pyjwt[crypto]" \
    jinja2 \
    python-multipart \
    httpx

COPY common/ ./common/
RUN pip install --no-cache-dir ./common/

COPY services/web/ ./service/
RUN pip install --no-cache-dir ./service/

EXPOSE 8000

CMD ["uvicorn", "web_service.main:app", "--host", "0.0.0.0", "--port", "8000"]
