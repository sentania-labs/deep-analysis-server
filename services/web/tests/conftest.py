"""Web service test fixtures.

The web service is a thin HTTP shim — it doesn't open Postgres or
Redis connections itself. We only need a JWT public key on disk so
``BaseServiceSettings`` validates, plus placeholder DB/Redis URLs the
settings model requires by type but the code never dials.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@pytest.fixture(scope="session", autouse=True)
def _web_test_env(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    out = tmp_path_factory.mktemp("web-jwt-keys")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path = out / "jwt_public.pem"
    pub_path.write_bytes(pub_pem)

    os.environ["DA_JWT_PUBLIC_KEY_PATH"] = str(pub_path)
    os.environ.setdefault(
        "DA_DATABASE_URL",
        "postgresql+asyncpg://x:x@localhost:5432/x",
    )
    os.environ.setdefault("DA_REDIS_URL", "redis://localhost:6379/0")

    yield pub_path
