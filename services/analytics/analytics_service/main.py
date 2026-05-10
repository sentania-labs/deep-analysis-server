from fastapi import FastAPI

from analytics_service.archetypes import router as archetypes_router
from analytics_service.stats import router as stats_router
from common.logging import configure_logging
from common.metrics import mount_metrics

SERVICE_NAME = "analytics"
configure_logging(SERVICE_NAME)
app = FastAPI(title=f"deep-analysis-{SERVICE_NAME}")
mount_metrics(app, SERVICE_NAME)
app.include_router(archetypes_router)
app.include_router(stats_router)


@app.get("/healthz")
@app.get("/analytics/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": SERVICE_NAME}
