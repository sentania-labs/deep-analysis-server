"""Regression checks for the Compose MinIO fixtures and pytest configuration."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = REPO_ROOT / "docker-compose.yml"


def test_minio_images_use_pinned_bitnami_legacy_images() -> None:
    """Every MinIO image uses the frozen Bitnami archive with a digest."""
    compose = COMPOSE_PATH.read_text()
    images = re.findall(r"^\s*image:\s*(\S*minio\S*)\s*$", compose, re.MULTILINE)

    assert images, "docker-compose.yml must contain at least one MinIO image"
    assert not re.search(r"^\s*image:\s*(?:minio/|quay\.io/minio/)", compose, re.MULTILINE)
    for image in images:
        assert re.fullmatch(
            r"docker\.io/bitnamilegacy/minio(?:-client)?@sha256:[0-9a-f]{64}", image
        ), f"MinIO image must use a digest-pinned Bitnami legacy reference: {image}"


def test_pytest_considers_namespace_packages() -> None:
    """Pytest must distinguish conftests in namespace package test trees."""
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())

    assert pyproject["tool"]["pytest"]["ini_options"]["consider_namespace_packages"] is True
