"""Unit tests for the metagame router.

Tests focus on the tier calculation logic and schema validation.
No DB or HTTP needed — we exercise the pure-logic paths and Pydantic
schemas directly.
"""

from __future__ import annotations

from analytics_service.schemas import (
    ArchetypeTier,
    EventDetail,
    EventResultEntry,
    MetagameEvent,
    MetagameEventList,
    MetagameFormat,
    MetagameFormatList,
    MetagameTierList,
    MetagameTrends,
    TrendDataset,
)

# --------------------------------------------------------------------------- #
# Schema validation
# --------------------------------------------------------------------------- #


def test_metagame_format_schema() -> None:
    fmt = MetagameFormat(format="Legacy", event_count=45, latest_event_date=None)
    assert fmt.format == "Legacy"
    assert fmt.event_count == 45


def test_metagame_format_list_schema() -> None:
    fmts = MetagameFormatList(
        formats=[
            MetagameFormat(format="Legacy", event_count=10),
            MetagameFormat(format="Modern", event_count=20),
        ]
    )
    assert len(fmts.formats) == 2


def test_archetype_tier_schema() -> None:
    tier = ArchetypeTier(
        deck_name="Boros Energy",
        popularity_pct=23.5,
        avg_placement=2.3,
        sample_count=47,
    )
    assert tier.deck_name == "Boros Energy"
    assert tier.popularity_pct == 23.5
    assert tier.avg_placement == 2.3
    assert tier.sample_count == 47


def test_metagame_tier_list_schema() -> None:
    tl = MetagameTierList(
        format="Modern",
        window="30d",
        tiers=[
            ArchetypeTier(deck_name="Burn", popularity_pct=15.0, sample_count=30),
            ArchetypeTier(deck_name="Jund", popularity_pct=10.0, sample_count=20),
        ],
        total_results=200,
    )
    assert tl.format == "Modern"
    assert tl.window == "30d"
    assert len(tl.tiers) == 2
    assert tl.total_results == 200


def test_metagame_event_schema() -> None:
    ev = MetagameEvent(
        event_id=1,
        event_name="Modern Challenge",
        source="mtgo",
    )
    assert ev.source == "mtgo"
    assert ev.player_count is None


def test_metagame_event_list_pagination() -> None:
    el = MetagameEventList(events=[], total=100, page=3, per_page=20)
    assert el.total == 100
    assert el.page == 3


def test_event_detail_schema() -> None:
    ed = EventDetail(
        event_id=42,
        event_name="Legacy Challenge 2026-05-10",
        source="mtgtop8",
        results=[
            EventResultEntry(
                player_name="Alice",
                placement=1,
                deck_name="Reanimator",
                decklist_main={"Reanimate": 4},
                decklist_sideboard={"Surgical Extraction": 2},
            ),
            EventResultEntry(
                player_name="Bob",
                placement=2,
            ),
        ],
    )
    assert len(ed.results) == 2
    assert ed.results[0].deck_name == "Reanimator"
    assert ed.results[1].decklist_main == {}


def test_trend_dataset_schema() -> None:
    ds = TrendDataset(label="Burn", data=[10.0, 15.0, 12.0])
    assert ds.label == "Burn"
    assert len(ds.data) == 3


def test_metagame_trends_schema() -> None:
    trends = MetagameTrends(
        format="Vintage",
        window="90d",
        labels=["2026-W10", "2026-W11", "2026-W12"],
        datasets=[
            TrendDataset(label="Dredge", data=[5, 8, 3]),
            TrendDataset(label="Shops", data=[12, 10, 14]),
        ],
    )
    assert trends.format == "Vintage"
    assert len(trends.labels) == 3
    assert len(trends.datasets) == 2


# --------------------------------------------------------------------------- #
# Tier calculation logic (pure)
# --------------------------------------------------------------------------- #


def _compute_tiers(
    rows: list[tuple[str, int, float | None]],
) -> list[ArchetypeTier]:
    """Reproduce the tier-building logic from the router."""
    total = sum(count for _, count, _ in rows)
    return [
        ArchetypeTier(
            deck_name=name,
            popularity_pct=round(count / total * 100, 2) if total else 0.0,
            avg_placement=round(avg, 2) if avg is not None else None,
            sample_count=count,
        )
        for name, count, avg in rows
    ]


def test_tier_calculation_basic() -> None:
    rows: list[tuple[str, int, float | None]] = [
        ("Burn", 30, 3.5),
        ("Jund", 20, 4.2),
        ("Storm", 50, 2.1),
    ]
    tiers = _compute_tiers(rows)
    assert len(tiers) == 3
    # Storm has 50/100 = 50%
    storm = next(t for t in tiers if t.deck_name == "Storm")
    assert storm.popularity_pct == 50.0
    assert storm.sample_count == 50
    assert storm.avg_placement == 2.1
    # Total should sum to 100%
    total_pct = sum(t.popularity_pct for t in tiers)
    assert abs(total_pct - 100.0) < 0.01


def test_tier_calculation_single_deck() -> None:
    rows: list[tuple[str, int, float | None]] = [("Mono Red", 10, 1.5)]
    tiers = _compute_tiers(rows)
    assert len(tiers) == 1
    assert tiers[0].popularity_pct == 100.0


def test_tier_calculation_empty() -> None:
    tiers = _compute_tiers([])
    assert tiers == []


def test_tier_calculation_null_placement() -> None:
    rows: list[tuple[str, int, float | None]] = [("Unknown", 5, None)]
    tiers = _compute_tiers(rows)
    assert tiers[0].avg_placement is None
    assert tiers[0].popularity_pct == 100.0
