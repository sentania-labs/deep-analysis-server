"""Tests for the canonical-event merger (issue #74).

The merger reconciles ``analytics.mtgtop8_events`` and ``analytics.mtgo_events``
into a single canonical list. mtgtop8 wins on metadata (it carries
archetype labels); MTGO supplements participants when its decklist
coverage runs deeper.

These are pure-logic tests — no DB, no HTTP. They feed synthetic event
dicts through :func:`merge_events` and :func:`merge_results` and check
the output shape.
"""

from __future__ import annotations

from datetime import date
from typing import Any

from analytics_service.event_merger import (
    MatchKey,
    event_signature,
    find_supplements_for,
    match_key,
    merge_events,
    merge_results,
    normalize_format,
)

# --------------------------------------------------------------------------- #
# Signature + key extraction
# --------------------------------------------------------------------------- #


def test_normalize_format_lowercases() -> None:
    assert normalize_format("Pauper") == "pauper"
    assert normalize_format("PAUPER") == "pauper"
    assert normalize_format("  modern  ") == "modern"


def test_normalize_format_handles_blank_and_none() -> None:
    assert normalize_format(None) is None
    assert normalize_format("") is None
    assert normalize_format("   ") is None


def test_event_signature_strips_format_words() -> None:
    assert event_signature("Pauper League") == "league"
    assert event_signature("Modern Challenge") == "challenge"
    assert event_signature("Vintage Super Qualifier") == "super qualifier"


def test_event_signature_strips_dates_iso() -> None:
    """YYYY-MM-DD dates inside the name vanish from the signature."""
    assert event_signature("Modern Challenge 2026-05-08") == "challenge"
    assert event_signature("Pauper League 2026-05-21") == "league"


def test_event_signature_strips_dates_slash() -> None:
    """mtgtop8-style DD/MM/YY dates vanish too."""
    assert event_signature("Modern Challenge 08/05/26") == "challenge"


def test_event_signature_strips_human_dates() -> None:
    """Mixed human formats land on the same signature."""
    assert event_signature("Pauper League May 21, 2026") == "league"
    assert event_signature("Pauper League May212026") == "league"
    assert event_signature("Pauper League 21st May 2026") == "league"


def test_event_signature_strips_numeric_suffixes() -> None:
    """Player-count suffixes like 'Challenge 32' shouldn't differentiate."""
    assert event_signature("Modern Challenge 32") == "challenge"
    assert event_signature("Modern Challenge 64") == "challenge"


def test_event_signature_keeps_showcase_qualifier_tokens() -> None:
    """Multi-word event types survive — the signature preserves order."""
    assert event_signature("Modern Showcase Challenge") == "showcase challenge"
    assert event_signature("Modern Showcase Qualifier") == "showcase qualifier"


def test_event_signature_blank_returns_none() -> None:
    assert event_signature(None) is None
    assert event_signature("") is None
    # All format + date — nothing left.
    assert event_signature("Modern 2026-05-08") is None


def test_match_key_full() -> None:
    key = match_key(
        {
            "event_name": "Pauper League — May 21, 2026",
            "event_date": date(2026, 5, 21),
            "format": "Pauper",
        }
    )
    assert key == MatchKey(format="pauper", event_date=date(2026, 5, 21), signature="league")


def test_match_key_two_names_one_event() -> None:
    """The MTGO and mtgtop8 names for the same event share a match key."""
    mtgo_key = match_key(
        {
            "event_name": "Pauper League May212026",
            "event_date": date(2026, 5, 21),
            "format": "Pauper",
        }
    )
    mtgtop8_key = match_key(
        {
            "event_name": "Pauper League",
            "event_date": date(2026, 5, 21),
            "format": "Pauper",
        }
    )
    assert mtgo_key is not None
    assert mtgo_key == mtgtop8_key


def test_match_key_missing_pieces_returns_none() -> None:
    base = {
        "event_name": "Modern Challenge",
        "event_date": date(2026, 5, 8),
        "format": "Modern",
    }
    assert match_key(base) is not None
    assert match_key({**base, "format": None}) is None
    assert match_key({**base, "event_date": None}) is None
    assert match_key({**base, "event_name": "Modern 2026-05-08"}) is None  # no type token


# --------------------------------------------------------------------------- #
# merge_events
# --------------------------------------------------------------------------- #


def _mtgtop8(
    id_: int,
    name: str,
    *,
    event_date: date | None = None,
    fmt: str | None = "Pauper",
    player_count: int | None = None,
) -> dict[str, Any]:
    return {
        "id": id_,
        "event_name": name,
        "event_date": event_date,
        "format": fmt,
        "player_count": player_count,
    }


def _mtgo(
    id_: int,
    name: str,
    *,
    event_date: date | None = None,
    fmt: str | None = "Pauper",
) -> dict[str, Any]:
    return {
        "id": id_,
        "event_name": name,
        "event_date": event_date,
        "format": fmt,
        "player_count": None,
    }


def test_merge_events_overlap_picks_mtgtop8_primary() -> None:
    """When both sources have the same logical event, mtgtop8 wins."""
    mtgtop8 = [
        _mtgtop8(
            10,
            "Pauper League",
            event_date=date(2026, 5, 21),
            player_count=128,
        )
    ]
    mtgo = [
        _mtgo(
            7,
            "Pauper League May212026",
            event_date=date(2026, 5, 21),
        )
    ]
    canonical = merge_events(mtgtop8, mtgo)
    assert len(canonical) == 1
    [merged] = canonical
    assert merged.primary_source == "mtgtop8"
    assert merged.primary_event_id == 10
    assert merged.event_name == "Pauper League"
    assert merged.player_count == 128  # mtgtop8 metadata wins
    assert merged.sources == ["mtgtop8", "mtgo"]
    assert merged.supplement_events == [("mtgo", 7)]


def test_merge_events_only_mtgtop8_kept_as_is() -> None:
    mtgtop8 = [_mtgtop8(1, "Vintage Challenge", event_date=date(2026, 5, 8), fmt="Vintage")]
    canonical = merge_events(mtgtop8, [])
    assert len(canonical) == 1
    [c] = canonical
    assert c.primary_source == "mtgtop8"
    assert c.sources == ["mtgtop8"]
    assert c.supplement_events == []


def test_merge_events_only_mtgo_kept_as_is() -> None:
    mtgo = [
        _mtgo(1, "Modern Showcase Challenge 2026-05-10", event_date=date(2026, 5, 10), fmt="Modern")
    ]
    canonical = merge_events([], mtgo)
    assert len(canonical) == 1
    [c] = canonical
    assert c.primary_source == "mtgo"
    assert c.sources == ["mtgo"]
    assert c.supplement_events == []


def test_merge_events_mixed_overlap_and_unique() -> None:
    """End-to-end shape check: overlap + mtgtop8-only + MTGO-only.

    Three logical events:
    - Pauper League on 2026-05-21 appears in both feeds → merged
    - Modern Challenge on 2026-05-08 appears only in mtgtop8 → kept
    - Vintage League on 2026-05-15 appears only in MTGO → kept
    """
    mtgtop8 = [
        _mtgtop8(10, "Pauper League", event_date=date(2026, 5, 21), fmt="Pauper"),
        _mtgtop8(11, "Modern Challenge", event_date=date(2026, 5, 8), fmt="Modern"),
    ]
    mtgo = [
        _mtgo(7, "Pauper League May212026", event_date=date(2026, 5, 21), fmt="Pauper"),
        _mtgo(8, "Vintage League 2026-05-15", event_date=date(2026, 5, 15), fmt="Vintage"),
    ]
    canonical = merge_events(mtgtop8, mtgo)
    assert len(canonical) == 3
    by_name = {c.event_name: c for c in canonical}
    # Overlap merged.
    assert by_name["Pauper League"].sources == ["mtgtop8", "mtgo"]
    assert by_name["Pauper League"].supplement_events == [("mtgo", 7)]
    # mtgtop8-only.
    assert by_name["Modern Challenge"].sources == ["mtgtop8"]
    # mtgo-only.
    assert by_name["Vintage League 2026-05-15"].sources == ["mtgo"]
    assert by_name["Vintage League 2026-05-15"].primary_source == "mtgo"


def test_merge_events_orders_by_date_desc() -> None:
    """Newer events come first; date-less events come last."""
    mtgo = [
        _mtgo(1, "Modern Challenge", event_date=date(2026, 5, 8), fmt="Modern"),
        _mtgo(2, "Modern Challenge", event_date=date(2026, 5, 15), fmt="Modern"),
        _mtgo(3, "Modern Challenge", event_date=None, fmt="Modern"),
    ]
    canonical = merge_events([], mtgo)
    dates = [c.event_date for c in canonical]
    assert dates == [date(2026, 5, 15), date(2026, 5, 8), None]


def test_merge_events_no_signature_stands_alone() -> None:
    """Events the matcher can't key get emitted one-each instead of merged."""
    mtgo = [_mtgo(1, "Modern 2026-05-08", event_date=date(2026, 5, 8), fmt="Modern")]
    mtgtop8 = [_mtgtop8(2, "Modern 2026-05-08", event_date=date(2026, 5, 8), fmt="Modern")]
    canonical = merge_events(mtgtop8, mtgo)
    # Neither has a signature — both stand alone.
    assert len(canonical) == 2
    assert {c.primary_source for c in canonical} == {"mtgtop8", "mtgo"}


def test_merge_events_format_case_insensitive() -> None:
    """Format strings differ in case between feeds but still match."""
    mtgtop8 = [_mtgtop8(1, "Pauper League", event_date=date(2026, 5, 21), fmt="Pauper")]
    mtgo = [_mtgo(2, "Pauper League 2026-05-21", event_date=date(2026, 5, 21), fmt="pauper")]
    canonical = merge_events(mtgtop8, mtgo)
    assert len(canonical) == 1
    assert canonical[0].sources == ["mtgtop8", "mtgo"]


# --------------------------------------------------------------------------- #
# merge_results — participant union
# --------------------------------------------------------------------------- #


def _result(
    name: str,
    placement: int | None,
    *,
    deck_name: str | None = None,
    main: dict[str, int] | None = None,
    side: dict[str, int] | None = None,
) -> dict[str, Any]:
    return {
        "player_name": name,
        "placement": placement,
        "deck_name": deck_name,
        "decklist_main": main or {},
        "decklist_sideboard": side or {},
    }


def test_merge_results_keeps_archetype_labels_on_collision() -> None:
    """When both sources have the same player, mtgtop8's row wins —
    so the archetype label survives."""
    primary = [_result("Alice", 1, deck_name="Boros Energy")]
    supplement = [_result("Alice", 5, deck_name=None, main={"Mountain": 20})]
    merged = merge_results(primary, supplement)
    assert len(merged) == 1
    assert merged[0]["deck_name"] == "Boros Energy"
    assert merged[0]["placement"] == 1  # primary's placement wins too


def test_merge_results_top8_plus_top32_union() -> None:
    """The acceptance test from the brief: mtgtop8 publishes the top 8
    (with archetype labels), MTGO publishes all 32 players. The merge
    should yield all 32 with archetype labels on the top 8.
    """
    # mtgtop8 has the top 8, with archetype labels.
    primary = [_result(f"Player{i:02d}", i, deck_name=f"Deck{i}") for i in range(1, 9)]
    # MTGO has all 32 — top 8 with the same names (would collide),
    # the rest are MTGO-only.
    supplement = [
        _result(f"Player{i:02d}", i, deck_name=None, main={"Card": 4}) for i in range(1, 33)
    ]
    merged = merge_results(primary, supplement)
    # All 32 distinct players in the union.
    assert len(merged) == 32
    # Top 8 keep their archetype labels.
    for i in range(1, 9):
        entry = next(r for r in merged if r["player_name"] == f"Player{i:02d}")
        assert entry["deck_name"] == f"Deck{i}", f"top-8 #{i} lost its archetype"
    # Positions 9-32 came from MTGO with deck_name=None.
    for i in range(9, 33):
        entry = next(r for r in merged if r["player_name"] == f"Player{i:02d}")
        assert entry["deck_name"] is None
        assert entry["decklist_main"] == {"Card": 4}


def test_merge_results_no_collision_simple_union() -> None:
    primary = [_result("Alice", 1, deck_name="Burn")]
    supplement = [_result("Bob", 2, deck_name=None)]
    merged = merge_results(primary, supplement)
    assert len(merged) == 2
    # Sorted by placement ascending.
    assert [r["player_name"] for r in merged] == ["Alice", "Bob"]


def test_merge_results_player_name_match_is_case_insensitive() -> None:
    """A player who appears under slightly different casing isn't duplicated."""
    primary = [_result("Alice", 1, deck_name="Burn")]
    supplement = [_result("alice", 5)]
    merged = merge_results(primary, supplement)
    assert len(merged) == 1
    assert merged[0]["deck_name"] == "Burn"


def test_merge_results_ordering_nulls_last() -> None:
    """Players with no placement are sorted after ranked ones."""
    primary = [
        _result("Bob", None),
        _result("Alice", 2),
        _result("Charlie", 1),
    ]
    merged = merge_results(primary, [])
    assert [r["player_name"] for r in merged] == ["Charlie", "Alice", "Bob"]


def test_merge_results_input_not_mutated() -> None:
    """Function must not edit caller's dicts — they often back DB rows
    cached upstream."""
    primary = [_result("Alice", 1, deck_name="Burn")]
    supplement = [_result("Bob", 2, deck_name=None)]
    snapshot_primary = [dict(r) for r in primary]
    snapshot_supplement = [dict(r) for r in supplement]
    merge_results(primary, supplement)
    assert primary == snapshot_primary
    assert supplement == snapshot_supplement


# --------------------------------------------------------------------------- #
# find_supplements_for
# --------------------------------------------------------------------------- #


def test_find_supplements_for_matches_on_key() -> None:
    """Given a primary mtgtop8 event, the function returns the MTGO sibling(s)."""
    primary = _mtgtop8(10, "Pauper League", event_date=date(2026, 5, 21))
    candidates = [
        _mtgo(7, "Pauper League May212026", event_date=date(2026, 5, 21)),
        _mtgo(8, "Modern Challenge", event_date=date(2026, 5, 21), fmt="Modern"),
        _mtgo(9, "Pauper League", event_date=date(2026, 5, 14)),  # wrong date
    ]
    found = find_supplements_for(
        primary_source="mtgtop8",
        primary_event=primary,
        candidate_events=candidates,
    )
    assert [c["id"] for c in found] == [7]


def test_find_supplements_for_returns_empty_when_primary_unkeyable() -> None:
    """If the primary has no signature/date/format, we can't match siblings."""
    primary = _mtgtop8(10, "Modern 2026-05-08", event_date=date(2026, 5, 8), fmt="Modern")
    candidates = [_mtgo(7, "Modern Challenge", event_date=date(2026, 5, 8), fmt="Modern")]
    assert (
        find_supplements_for(
            primary_source="mtgtop8",
            primary_event=primary,
            candidate_events=candidates,
        )
        == []
    )
