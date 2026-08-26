"""Shared pydantic-settings base for all services."""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from common.storage import S3Config


class BaseServiceSettings(BaseSettings):
    service_name: str
    log_level: str = "INFO"
    database_url: str
    redis_url: str
    jwt_public_key_path: Path
    jwt_issuer: str = "deep-analysis-auth"
    jwt_audience: str = "deep-analysis"
    metrics_port: int = 9000

    model_config = SettingsConfigDict(env_prefix="DA_", env_nested_delimiter="__")


class S3StorageSettings(BaseServiceSettings):
    """Mixin for services that touch the raw object archive.

    Only ``ingest`` (writes) and ``parser`` (reads) inherit this. There
    is no backend selector: S3 is the only archive backend, so the
    only questions left are where the bucket is and how to reach it.
    Defaults match the MinIO service shipped in docker-compose.yml so
    the stack works from ``docker compose up`` with nothing to fill in.
    """

    s3_endpoint_url: str = "http://minio:9000"
    s3_access_key: str = "deep-analysis"
    s3_secret_key: str = "deep-analysis-dev-secret"
    s3_bucket: str = "deep-analysis-raw"
    s3_region: str = "us-east-1"
    # MinIO needs path-style addressing; AWS S3 does not.
    s3_force_path_style: bool = True
    # Bounded so a storage outage fails fast instead of blocking.
    s3_connect_timeout_seconds: float = 3.0
    s3_read_timeout_seconds: float = 10.0
    s3_max_attempts: int = 3
    s3_key_prefix: str = "raw"

    def s3_config(self) -> S3Config:
        return S3Config(
            endpoint_url=self.s3_endpoint_url,
            access_key=self.s3_access_key,
            secret_key=self.s3_secret_key,
            bucket=self.s3_bucket,
            region=self.s3_region,
            force_path_style=self.s3_force_path_style,
            connect_timeout_seconds=self.s3_connect_timeout_seconds,
            read_timeout_seconds=self.s3_read_timeout_seconds,
            max_attempts=self.s3_max_attempts,
            key_prefix=self.s3_key_prefix,
        )
