"""Unit tests for the pure HTML extraction functions in ``mtgo_scraper``.

The scraper has two hard requirements:

1. The pure parsing functions never raise on malformed input — they
   return ``[]`` and let the caller treat that as a parse failure.
2. They successfully extract events / decklists from at least one
   plausible HTML shape per strategy.

These tests exercise both paths. No HTTP, no DB.
"""

from __future__ import annotations

from datetime import date

from analytics_service.mtgo_scraper import (
    ScrapeResult,
    extract_decklists_from_html,
    extract_events_from_html,
)

# --------------------------------------------------------------------------- #
# extract_events_from_html
# --------------------------------------------------------------------------- #


def test_extract_events_valid_anchor_html() -> None:
    """Primary strategy: anchors with /decklist/ in href."""
    html = """
    <html><body>
      <ul>
        <li><a href="/en/mtgo/decklist/modern-challenge-2026-05-08">
          Modern Challenge 32 — 2026-05-08
        </a></li>
        <li><a href="/en/mtgo/decklist/pioneer-preliminary-2026-05-07">
          Pioneer Preliminary — 2026-05-07
        </a></li>
        <li><a href="/some/unrelated/page">Other</a></li>
      </ul>
    </body></html>
    """
    events = extract_events_from_html(html)
    assert len(events) == 2
    by_url = {e["event_url"]: e for e in events}
    modern = by_url["https://www.mtgo.com/en/mtgo/decklist/modern-challenge-2026-05-08"]
    assert "Modern" in modern["event_name"]
    assert modern["format"] == "Modern"
    assert modern["event_date"] == date(2026, 5, 8)


def test_extract_events_dedupes_repeated_urls() -> None:
    html = """
    <html><body>
      <a href="/en/mtgo/decklist/standard-challenge-2026-05-09">A</a>
      <a href="/en/mtgo/decklist/standard-challenge-2026-05-09">B</a>
    </body></html>
    """
    events = extract_events_from_html(html)
    assert len(events) == 1


def test_extract_events_garbage_html() -> None:
    html = "<html><body>nothing useful here</body></html>"
    assert extract_events_from_html(html) == []


def test_extract_events_empty_string() -> None:
    assert extract_events_from_html("") == []


def test_extract_events_whitespace_only() -> None:
    assert extract_events_from_html("   \n\t  ") == []


def test_extract_events_malformed_html_does_not_raise() -> None:
    html = "<html><body><a href='/decklist/foo'>unclosed"
    result = extract_events_from_html(html)
    # html.parser is lenient — should still extract the anchor without raising.
    assert isinstance(result, list)


# --------------------------------------------------------------------------- #
# extract_decklists_from_html
# --------------------------------------------------------------------------- #


def _card(name: str, qty: int, *, side: bool = False) -> dict:
    return {
        "qty": str(qty),
        "sideboard": str(side).lower(),
        "card_attributes": {"card_name": name},
    }


def test_extract_decklists_mtgo_js_data() -> None:
    """Primary strategy: window.MTGO.decklists.data JS payload."""
    import json

    data = {
        "event_id": "12345",
        "description": "Modern Challenge 32",
        "decklists": [
            {
                "player": "Alice",
                "main_deck": [
                    _card("Lightning Bolt", 4),
                    _card("Goblin Guide", 4),
                    _card("Smash to Smithereens", 2, side=True),
                ],
            },
            {
                "player": "Bob",
                "main_deck": [
                    _card("Karn Liberated", 4),
                    _card("Nature's Claim", 3, side=True),
                ],
            },
        ],
    }
    html = f"""
    <html><body>
      <script type="text/javascript">
        window.MTGO = window.MTGO || {{}};
        window.MTGO.decklists = window.MTGO.decklists || {{}};
        window.MTGO.decklists.data = {json.dumps(data)};
      </script>
    </body></html>
    """
    decks = extract_decklists_from_html(html, "https://example.com/event")
    assert len(decks) == 2
    by_player = {d["player_name"]: d for d in decks}
    alice = by_player["Alice"]
    assert alice["decklist_main"] == {"Lightning Bolt": 4, "Goblin Guide": 4}
    assert alice["decklist_sideboard"] == {"Smash to Smithereens": 2}
    bob = by_player["Bob"]
    assert bob["decklist_main"] == {"Karn Liberated": 4}
    assert bob["decklist_sideboard"] == {"Nature's Claim": 3}


def test_extract_decklists_mtgo_js_data_bad_json() -> None:
    """JS data strategy gracefully handles malformed JSON."""
    html = """
    <html><body>
      <script>window.MTGO.decklists.data = {not valid json};</script>
    </body></html>
    """
    assert extract_decklists_from_html(html, "https://example.com") == []


def test_extract_decklists_player_blocks() -> None:
    """Fallback strategy: per-player decklist blocks with main + sideboard."""
    html = """
    <html><body>
      <div class="deck-block">
        <h3>1. Alice — Burn</h3>
        <div class="rank">1st</div>
        <div class="mainboard">
          <ul>
            <li>4 Lightning Bolt</li>
            <li>4 Goblin Guide</li>
            <li>4 Lava Spike</li>
          </ul>
        </div>
        <div class="sideboard">
          <ul>
            <li>2 Smash to Smithereens</li>
          </ul>
        </div>
      </div>
      <div class="deck-block">
        <h3>2. Bob — Tron</h3>
        <div class="rank">2nd</div>
        <div class="mainboard">
          <ul>
            <li>4 Karn Liberated</li>
            <li>4 Urza's Tower</li>
          </ul>
        </div>
        <div class="sideboard">
          <ul>
            <li>3 Nature's Claim</li>
          </ul>
        </div>
      </div>
    </body></html>
    """
    decks = extract_decklists_from_html(html, "https://example.com/event")
    assert len(decks) == 2
    by_player = {d["player_name"]: d for d in decks}
    alice = by_player["Alice — Burn"]
    assert alice["placement"] == 1
    assert alice["decklist_main"] == {
        "Lightning Bolt": 4,
        "Goblin Guide": 4,
        "Lava Spike": 4,
    }
    assert alice["decklist_sideboard"] == {"Smash to Smithereens": 2}
    bob = by_player["Bob — Tron"]
    assert bob["placement"] == 2
    assert bob["decklist_main"] == {"Karn Liberated": 4, "Urza's Tower": 4}


def test_extract_decklists_no_match() -> None:
    html = "<html><body>no decklists here</body></html>"
    assert extract_decklists_from_html(html, "https://example.com") == []


def test_extract_decklists_empty() -> None:
    assert extract_decklists_from_html("", "https://example.com") == []


def test_extract_decklists_whitespace_only() -> None:
    assert extract_decklists_from_html("   ", "https://example.com") == []


def test_extract_decklists_embedded_json_fallback() -> None:
    """Fallback strategy: structured deck data inside an application/json blob."""
    html = """
    <html><body>
      <script type="application/json">
        {"decks": [
          {"player": "Carol", "placement": 3,
           "main": {"Counterspell": 4, "Brainstorm": 4},
           "sideboard": {"Force of Will": 2}}
        ]}
      </script>
    </body></html>
    """
    decks = extract_decklists_from_html(html, "https://example.com/event")
    assert len(decks) == 1
    assert decks[0]["player_name"] == "Carol"
    assert decks[0]["placement"] == 3
    assert decks[0]["decklist_main"] == {"Counterspell": 4, "Brainstorm": 4}
    assert decks[0]["decklist_sideboard"] == {"Force of Will": 2}


def test_extract_decklists_malformed_json_does_not_raise() -> None:
    html = """
    <html><body>
      <script type="application/json">{not valid json</script>
    </body></html>
    """
    assert extract_decklists_from_html(html, "https://example.com") == []


# --------------------------------------------------------------------------- #
# ScrapeResult
# --------------------------------------------------------------------------- #


def test_scrape_result_defaults() -> None:
    """A freshly constructed ScrapeResult is the "no work yet" zero state."""
    result = ScrapeResult()
    assert result.events_found == 0
    assert result.events_new == 0
    assert result.results_stored == 0
    assert result.consecutive_failures == 0
    assert result.is_broken is False
    assert result.error is None
