import os
from pathlib import Path


def _ensure_import_env() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    os.environ.setdefault("DA_JWT_PRIVATE_KEY_PATH", str(repo_root / ".nonexistent-jwt-priv"))
    os.environ.setdefault("DA_JWT_PUBLIC_KEY_PATH", str(repo_root / ".nonexistent-jwt-pub"))
    os.environ.setdefault("DA_DATABASE_URL", "postgresql+asyncpg://stub:stub@localhost/stub")
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")


_ensure_import_env()

import httpx  # noqa: E402
import pytest  # noqa: E402
from analytics_service.main import app as analytics_app  # noqa: E402
from auth_service.main import app as auth_app  # noqa: E402
from httpx import AsyncClient  # noqa: E402
from ingest_service.main import app as ingest_app  # noqa: E402
from parser_service.main import app as parser_app  # noqa: E402
from web_service.main import app as web_app  # noqa: E402

pytestmark = pytest.mark.asyncio

SERVICES = [
    ("analytics", analytics_app),
    ("ingest", ingest_app),
    ("web", web_app),
    ("auth", auth_app),
    ("parser", parser_app),
]


@pytest.mark.parametrize("service_name, app", SERVICES)
async def test_liveness_readiness_with_db_unreachable(service_name, app, monkeypatch):
    import common.health

    async def mock_check_db(*args, **kwargs):
        return common.health.CheckResult(name="db", ok=False, detail="error")

    async def mock_check_redis(*args, **kwargs):
        return common.health.CheckResult(name="redis", ok=False, detail="error")

    async def mock_check_object_store(*args, **kwargs):
        return common.health.CheckResult(name="object_store", ok=False, detail="error")

    async def mock_check_http(*args, **kwargs):
        return common.health.CheckResult(name="http", ok=False, detail="error")

    monkeypatch.setattr("common.health.check_db", mock_check_db)
    monkeypatch.setattr("common.health.check_redis", mock_check_redis)
    monkeypatch.setattr("common.health.check_object_store", mock_check_object_store)
    monkeypatch.setattr("common.health.check_http", mock_check_http)

    transport = httpx.ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Liveness should be 200
        response = await client.get("/livez")
        assert response.status_code == 200

        # Readiness should be 503
        response = await client.get("/healthz")
        assert response.status_code == 503
