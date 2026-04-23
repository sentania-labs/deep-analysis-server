"""Regression guard: topic constants must not drift."""

from common.events import FILE_INGESTED, INSIGHT_REQUESTED, MATCH_PARSED


def test_file_ingested() -> None:
    assert FILE_INGESTED == "file.ingested"


def test_match_parsed() -> None:
    assert MATCH_PARSED == "match.parsed"


def test_insight_requested() -> None:
    assert INSIGHT_REQUESTED == "insight.requested"
