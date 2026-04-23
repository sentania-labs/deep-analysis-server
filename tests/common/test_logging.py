"""Tests for common.logging."""

import structlog

from common.logging import configure_logging


def test_configure_logging_does_not_raise() -> None:
    configure_logging("test-service")
    assert structlog.is_configured()


def test_emit_log_line() -> None:
    configure_logging("test-service", level="DEBUG")
    logger = structlog.get_logger()
    logger.info("hello", extra_key="extra_value")
