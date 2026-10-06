"""Verify MinIO images use quay.io registry and pytest namespace config.

Regression guard: MinIO moved off Docker Hub in 2025-04.  This test
asserts that every MinIO image in docker-compose.yml comes from
quay.io/minio and that pyproject.toml's pytest options include
consider_namespace_packages (needed to avoid conftest collisions when
running services/parser/tests/ and services/web/tests/ in the same
pytest invocation).
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_docker_compose_minio_images_on_quay_io() -> None:
    """Every minio image in docker-compose.yml must be on quay.io."""
    compose_path = REPO_ROOT / "docker-compose.yml"
    content = compose_path.read_text()

    # Find all image: lines that mention minio
    minio_images: list[str] = [
        m.group(1) for m in re.finditer(r"(?:^|\s)image:\s*(\S*minio\S*)", content)
    ]

    assert minio_images, "docker-compose.yml must contain at least one minio image"

    for img in minio_images:
        assert img.startswith("quay.io/minio/"), (
            f"MinIO image {img} must be on quay.io, not Docker Hub"
        )


def test_pytest_consider_namespace_packages() -> None:
    """pyproject.toml must set consider_namespace_packages under [tool.pytest]."""
    pyproject_path = REPO_ROOT / "pyproject.toml"
    data = tomllib.loads(pyproject_path.read_text())

    pytest_opts = data.get("tool", {}).get("pytest", {}).get("ini_options", {})
    assert pytest_opts.get("consider_namespace_packages"), (
        "pytest ini_options must set consider_namespace_packages = true"
    )
