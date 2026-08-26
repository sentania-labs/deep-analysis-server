"""Unit tests for the filter-preserving URL helper (#131).

Issues #133 and #124 reuse ``filter_url`` for the Match History opponent
links, so its contract is pinned here rather than only through templates.
"""

from __future__ import annotations

from web_service.urls import filter_url


def test_no_filters_gives_a_clean_path() -> None:
    assert filter_url("/admin/matches", {}, {"review_status": ""}) == "/admin/matches"
    assert filter_url("/admin/matches") == "/admin/matches"


def test_empty_filter_values_are_dropped() -> None:
    filters = {"format": "Pauper", "opponent": "", "result": None}
    assert filter_url("/matches", filters) == "/matches?format=Pauper"


def test_replace_overrides_a_single_key_and_keeps_the_rest() -> None:
    filters = {"format": "Pauper", "opponent": "alice", "review_status": "normal"}
    url = filter_url("/admin/matches", filters, {"review_status": "rejected"})
    assert url == "/admin/matches?format=Pauper&opponent=alice&review_status=rejected"


def test_replace_with_empty_value_clears_only_that_key() -> None:
    filters = {"format": "Pauper", "opponent": "alice", "review_status": "normal"}
    url = filter_url("/admin/matches", filters, {"review_status": ""})
    assert url == "/admin/matches?format=Pauper&opponent=alice"


def test_replace_can_add_a_key_that_was_not_active() -> None:
    url = filter_url("/matches", {"format": "Pauper"}, {"opponent": "alice"})
    assert url == "/matches?format=Pauper&opponent=alice"


def test_pagination_is_reset_and_page_never_carried() -> None:
    filters = {"format": "Pauper", "page": 7, "per_page": 50}
    url = filter_url("/admin/matches", filters, {"review_status": "rejected"})
    assert "page=7" not in url
    assert "per_page" not in url


def test_per_page_is_kept_when_passed() -> None:
    url = filter_url("/admin/matches", {"format": "Pauper"}, per_page=50)
    assert url == "/admin/matches?format=Pauper&per_page=50"


def test_per_page_is_omitted_when_falsy() -> None:
    assert filter_url("/admin/matches", {}, per_page=None) == "/admin/matches"
    assert filter_url("/admin/matches", {}, per_page=0) == "/admin/matches"


def test_values_are_url_encoded() -> None:
    url = filter_url("/matches", {"opponent": "a b&c"})
    assert url == "/matches?opponent=a+b%26c"


def test_zero_is_a_real_filter_value() -> None:
    assert filter_url("/matches", {"wins": 0}) == "/matches?wins=0"
