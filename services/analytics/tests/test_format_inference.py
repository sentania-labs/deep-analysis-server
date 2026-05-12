"""Unit tests for format inference from card legalities."""

from common.format_inference import infer_format_from_cards

_ALL_LEGAL = {
    "standard": "legal",
    "pioneer": "legal",
    "modern": "legal",
    "legacy": "legal",
    "vintage": "legal",
}


def _legs(**overrides: str) -> dict[str, str]:
    return {**_ALL_LEGAL, **overrides}


def test_all_standard_legal() -> None:
    cards = {
        "Lightning Strike": _legs(),
        "Opt": _legs(),
    }
    assert infer_format_from_cards(cards) == "standard"


def test_pioneer_not_standard() -> None:
    cards = {
        "Thoughtseize": _legs(standard="not_legal"),
        "Opt": _legs(),
    }
    assert infer_format_from_cards(cards) == "pioneer"


def test_modern_card_pool() -> None:
    cards = {
        "Lightning Bolt": _legs(standard="not_legal", pioneer="not_legal"),
        "Goblin Guide": _legs(standard="not_legal", pioneer="not_legal"),
    }
    assert infer_format_from_cards(cards) == "modern"


def test_legacy_card_pool() -> None:
    cards = {
        "Force of Will": _legs(
            standard="not_legal",
            pioneer="not_legal",
            modern="not_legal",
        ),
        "Brainstorm": _legs(
            standard="not_legal",
            pioneer="not_legal",
            modern="not_legal",
        ),
    }
    assert infer_format_from_cards(cards) == "legacy"


def test_vintage_restricted() -> None:
    cards = {
        "Black Lotus": _legs(
            standard="not_legal",
            pioneer="not_legal",
            modern="not_legal",
            legacy="banned",
            vintage="restricted",
        ),
        "Ancestral Recall": _legs(
            standard="not_legal",
            pioneer="not_legal",
            modern="not_legal",
            legacy="banned",
            vintage="restricted",
        ),
    }
    assert infer_format_from_cards(cards) == "vintage"


def test_banned_in_all_returns_none() -> None:
    cards = {
        "Fake Broken Card": {
            "standard": "banned",
            "pioneer": "banned",
            "modern": "banned",
            "legacy": "banned",
            "vintage": "banned",
        },
    }
    assert infer_format_from_cards(cards) is None


def test_empty_returns_none() -> None:
    assert infer_format_from_cards({}) is None


def test_mixed_pool_picks_narrowest() -> None:
    cards = {
        "Opt": _legs(),
        "Tarmogoyf": _legs(standard="not_legal", pioneer="not_legal"),
    }
    assert infer_format_from_cards(cards) == "modern"
