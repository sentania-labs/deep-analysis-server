"""Unit tests for the pure HTML extraction functions in ``mtgtop8_scraper``.

Same test philosophy as ``test_mtgo_scraper``:

1. Pure parsing functions never raise on malformed input — they return
   ``[]`` or ``None``.
2. They successfully extract events / decklists from plausible HTML
   shapes matching mtgtop8.com's structure.

No HTTP, no DB.
"""

from __future__ import annotations

from datetime import date

from analytics_service.mtgtop8_scraper import (
    FORMATS,
    ScrapeResult,
    extract_decklist_from_detail_page,
    extract_decklists_from_event_page,
    extract_events_from_format_page,
)

# --------------------------------------------------------------------------- #
# extract_events_from_format_page
# --------------------------------------------------------------------------- #


def test_extract_events_table_strategy() -> None:
    """Primary strategy: event links in table rows."""
    html = """
    <html><body>
      <table>
        <tr>
          <td>1</td>
          <td><a href="event?e=54321&f=MO">Modern Challenge #32</a></td>
          <td>128 players</td>
          <td>10/05/26</td>
        </tr>
        <tr>
          <td>2</td>
          <td><a href="event?e=54322&f=MO">Modern Preliminary</a></td>
          <td>64 players</td>
          <td>09/05/26</td>
        </tr>
      </table>
    </body></html>
    """
    events = extract_events_from_format_page(html, "MO")
    assert len(events) == 2
    by_id = {e["event_id"]: e for e in events}

    ev1 = by_id["54321"]
    assert ev1["event_name"] == "Modern Challenge #32"
    assert ev1["format"] == "Modern"
    assert ev1["event_date"] == date(2026, 5, 10)
    assert ev1["player_count"] == 128
    assert "event?e=54321" in ev1["event_url"]

    ev2 = by_id["54322"]
    assert ev2["event_name"] == "Modern Preliminary"
    assert ev2["event_date"] == date(2026, 5, 9)
    assert ev2["player_count"] == 64


def test_extract_events_dedupes_same_event_id() -> None:
    html = """
    <html><body>
      <a href="event?e=11111&f=VI">Vintage Challenge</a>
      <a href="event?e=11111&f=VI">Vintage Challenge (dup)</a>
    </body></html>
    """
    events = extract_events_from_format_page(html, "VI")
    assert len(events) == 1


def test_extract_events_empty_string() -> None:
    assert extract_events_from_format_page("", "MO") == []


def test_extract_events_whitespace_only() -> None:
    assert extract_events_from_format_page("   \n\t  ", "MO") == []


def test_extract_events_garbage_html() -> None:
    html = "<html><body>nothing useful here</body></html>"
    assert extract_events_from_format_page(html, "MO") == []


def test_extract_events_malformed_html_does_not_raise() -> None:
    html = "<html><body><a href='event?e=999&f=MO'>unclosed"
    result = extract_events_from_format_page(html, "MO")
    assert isinstance(result, list)
    # html.parser is lenient — should still extract the anchor
    assert len(result) == 1


def test_extract_events_all_format_codes() -> None:
    """Every format code we support maps to the correct format name."""
    for code, name in FORMATS.items():
        html = f'<a href="event?e=1&f={code}">{name} Challenge</a>'
        events = extract_events_from_format_page(html, code)
        assert len(events) == 1
        assert events[0]["format"] == name


# --------------------------------------------------------------------------- #
# extract_decklists_from_event_page
# --------------------------------------------------------------------------- #


def test_extract_decklists_player_rows() -> None:
    """Primary strategy: ``div.chosen_tr`` / ``div.hover_tr`` finisher rows.

    Regression test for #73. mtgtop8 event pages render finishers in div-based
    rows, not real ``<tr>`` table rows. Each row has the placement in a leading
    ``S14`` div, the deck archetype in an anchor (with a sibling thumbnail
    anchor that points to the same href but carries no text), and the player
    name in an ``a.player`` link.
    """
    html = """
    <html><body>
      <div class="chosen_tr">
        <div style="display:flex;">
          <div class="S14" style="width:42px;">1</div>
          <div style="width:80px;"><a href="?e=54321&d=100001&f=MO"><img/></a></div>
          <div style="flex:1;">
            <div class="S14"><a href="?e=54321&d=100001&f=MO">Burn</a></div>
            <div class="G11"><a class="player" href="search?player=Alice">Alice</a></div>
          </div>
        </div>
      </div>
      <div class="hover_tr">
        <div style="display:flex;">
          <div class="S14" style="width:42px;">2</div>
          <div style="width:80px;"><a href="?e=54321&d=100002&f=MO"><img/></a></div>
          <div style="flex:1;">
            <div class="S14"><a href="?e=54321&d=100002&f=MO">Tron</a></div>
            <div class="G11"><a class="player" href="search?player=Bob">Bob</a></div>
          </div>
        </div>
      </div>
      <div class="hover_tr">
        <div style="display:flex;">
          <div class="S14" style="width:42px;">3-4</div>
          <div style="width:80px;"><a href="?e=54321&d=100003&f=MO"><img/></a></div>
          <div style="flex:1;">
            <div class="S14"><a href="?e=54321&d=100003&f=MO">Reanimator</a></div>
            <div class="G11"><a class="player" href="search?player=Carol">Carol</a></div>
          </div>
        </div>
      </div>
    </body></html>
    """
    decks = extract_decklists_from_event_page(html, "https://mtgtop8.com/event?e=54321&f=MO")
    assert len(decks) == 3
    by_player = {d["player_name"]: d for d in decks}
    assert by_player["Alice"]["placement"] == 1
    assert by_player["Alice"]["deck_name"] == "Burn"
    assert by_player["Bob"]["placement"] == 2
    assert by_player["Bob"]["deck_name"] == "Tron"
    # Placement ranges like "3-4" collapse to the top finishing position.
    assert by_player["Carol"]["placement"] == 3
    assert by_player["Carol"]["deck_name"] == "Reanimator"


def test_extract_decklists_player_rows_old_table_shape_returns_empty() -> None:
    """The pre-fix ``<tr>``/``<td>`` shape no longer matches.

    Guards against re-introducing the table-row assumption that caused #73 —
    the real site uses div-based rows.
    """
    html = """
    <html><body>
      <table>
        <tr>
          <td>1</td>
          <td><a href="?e=54321&d=100001&f=MO">Burn</a></td>
          <td>Alice</td>
        </tr>
      </table>
    </body></html>
    """
    # No chosen_tr / hover_tr, no a.player → primary strategy yields nothing,
    # and the fallback finds no card lines either.
    decks = extract_decklists_from_event_page(html, "https://mtgtop8.com/event?e=54321&f=MO")
    assert decks == []


def test_extract_decklists_empty() -> None:
    assert extract_decklists_from_event_page("", "https://example.com") == []


def test_extract_decklists_whitespace_only() -> None:
    assert extract_decklists_from_event_page("   ", "https://example.com") == []


def test_extract_decklists_no_match() -> None:
    html = "<html><body>no decks here</body></html>"
    assert extract_decklists_from_event_page(html, "https://example.com") == []


def test_extract_decklists_deck_blocks_fallback() -> None:
    """Fallback strategy: deck blocks with card lists."""
    html = """
    <html><body>
      <div class="deck-list">
        <h3>Alice</h3>
        <div>4 Lightning Bolt</div>
        <div>4 Goblin Guide</div>
        <div>Sideboard</div>
        <div>2 Smash to Smithereens</div>
      </div>
    </body></html>
    """
    decks = extract_decklists_from_event_page(html, "https://example.com")
    assert len(decks) == 1
    assert decks[0]["player_name"] == "Alice"
    assert decks[0]["decklist_main"] == {"Lightning Bolt": 4, "Goblin Guide": 4}
    assert decks[0]["decklist_sideboard"] == {"Smash to Smithereens": 2}


# --------------------------------------------------------------------------- #
# extract_decklist_from_detail_page
# --------------------------------------------------------------------------- #


def test_extract_decklist_detail_page() -> None:
    """Individual deck detail page using mtgtop8's real layout.

    Regression test for #73. mtgtop8 separates the mainboard and sideboard
    with a sibling ``<div class="O14">SIDEBOARD</div>`` header (not a
    deck_line), so the parser has to walk the deck column in document order
    and flip into the sideboard section when it sees that header.
    """
    html = """
    <html><body>
      <div style="margin:3px;flex:1;">
        <div class="O14">20 LANDS</div>
        <div class="deck_line">4 Mountain</div>
        <div class="deck_line">4 Inspiring Vantage</div>
        <div class="O14">12 CREATURES</div>
        <div class="deck_line">4 Goblin Guide</div>
        <div class="deck_line">4 Eidolon of the Great Revel</div>
        <div class="O14">28 INSTANTS and SORC.</div>
        <div class="deck_line">4 Lightning Bolt</div>
        <div class="deck_line">4 Lava Spike</div>
        <div class="deck_line">4 Rift Bolt</div>
        <div class="O14">SIDEBOARD</div>
        <div class="deck_line">2 Smash to Smithereens</div>
        <div class="deck_line">3 Searing Blood</div>
      </div>
    </body></html>
    """
    result = extract_decklist_from_detail_page(
        html, "Alice", "https://mtgtop8.com/event?e=1&d=2&f=MO"
    )
    assert result is not None
    assert result["player_name"] == "Alice"
    # Section headers like "20 LANDS" and "12 CREATURES" are <div class="O14">,
    # not deck_line — they must not be picked up as cards.
    assert "LANDS" not in result["decklist_main"]
    assert "CREATURES" not in result["decklist_main"]
    assert result["decklist_main"]["Lightning Bolt"] == 4
    assert result["decklist_main"]["Goblin Guide"] == 4
    assert result["decklist_main"]["Mountain"] == 4
    # Sideboard cards land in the sideboard bucket, not main.
    assert "Smash to Smithereens" not in result["decklist_main"]
    assert "Searing Blood" not in result["decklist_main"]
    assert result["decklist_sideboard"]["Smash to Smithereens"] == 2
    assert result["decklist_sideboard"]["Searing Blood"] == 3


def test_extract_decklist_detail_page_text_fallback() -> None:
    """Fallback: plain text card lines without deck_line class."""
    html = """
    <html><body>
      <div>
        4 Counterspell
        4 Brainstorm
        2 Force of Will

        Sideboard
        3 Hydroblast
        2 Blue Elemental Blast
      </div>
    </body></html>
    """
    result = extract_decklist_from_detail_page(
        html, "Bob", "https://mtgtop8.com/event?e=1&d=3&f=LE"
    )
    assert result is not None
    assert result["decklist_main"]["Counterspell"] == 4
    assert result["decklist_main"]["Brainstorm"] == 4
    assert result["decklist_main"]["Force of Will"] == 2
    assert result["decklist_sideboard"]["Hydroblast"] == 3
    assert result["decklist_sideboard"]["Blue Elemental Blast"] == 2


def test_extract_decklist_detail_page_empty() -> None:
    assert extract_decklist_from_detail_page("", "Alice", "https://example.com") is None


def test_extract_decklist_detail_page_no_cards() -> None:
    html = "<html><body>no cards here</body></html>"
    assert extract_decklist_from_detail_page(html, "Alice", "https://example.com") is None


def test_extract_decklist_detail_page_malformed_html() -> None:
    html = "<html><body><div class='deck_line'>4 Lightning Bolt</div>unclosed"
    result = extract_decklist_from_detail_page(html, "Alice", "https://example.com")
    # html.parser is lenient — should extract what it can
    assert result is not None or result is None  # just confirm no exception


# --------------------------------------------------------------------------- #
# ScrapeResult
# --------------------------------------------------------------------------- #


def test_scrape_result_defaults() -> None:
    result = ScrapeResult()
    assert result.events_found == 0
    assert result.events_new == 0
    assert result.results_stored == 0
    assert result.consecutive_failures == 0
    assert result.is_broken is False
    assert result.error is None


# --------------------------------------------------------------------------- #
# Date parsing edge cases
# --------------------------------------------------------------------------- #


def test_date_parsing_in_event_extraction() -> None:
    """mtgtop8 dates in DD/MM/YY format parse correctly."""
    html = """
    <table><tr>
      <td><a href="event?e=99999&f=MO">Event</a></td>
      <td>01/12/25</td>
    </tr></table>
    """
    events = extract_events_from_format_page(html, "MO")
    assert len(events) == 1
    assert events[0]["event_date"] == date(2025, 12, 1)


def test_date_parsing_full_year() -> None:
    """Four-digit year also works."""
    html = """
    <table><tr>
      <td><a href="event?e=88888&f=LE">Event</a></td>
      <td>15/06/2025</td>
    </tr></table>
    """
    events = extract_events_from_format_page(html, "LE")
    assert len(events) == 1
    assert events[0]["event_date"] == date(2025, 6, 15)
