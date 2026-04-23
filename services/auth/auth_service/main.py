from fastapi import FastAPI

from common.logging import configure_logging
from common.metrics import mount_metrics

SERVICE_NAME = "auth"
configure_logging(SERVICE_NAME)
app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}")
mount_metrics(app, SERVICE_NAME)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
