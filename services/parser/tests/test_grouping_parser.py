"""Unit tests for the MTGO grouping XML parser."""

from __future__ import annotations

from parser_service.parsing.grouping_parser import (
    ParsedGrouping,
    extract_deck_uuid,
    parse_grouping_xml,
)

# ---------------------------------------------------------------------------
# Sample XML payloads
# ---------------------------------------------------------------------------

SAMPLE_DECK_XML = b"""\
<CardGrouping Name="Legacy Reanimator" NetDeckId="111106631"
              GroupingType="Deck" FormatCode="CLEGACY"
              Timestamp="2026-05-17T23:10:30.413Z">
  <Item CatId="30302" Quantity="1" IsSideboard="false" Annotation="0" />
  <Item CatId="35118" Quantity="4" IsSideboard="false" Annotation="0" />
  <Item CatId="42001" Quantity="2" IsSideboard="true" Annotation="0" />
</CardGrouping>
"""

SAMPLE_WISHLIST_XML = b"""\
<CardGrouping Name="My Wishlist" NetDeckId=""
              GroupingType="Wishlist" FormatCode=""
              Timestamp="2026-05-10T12:00:00.000Z">
  <Item CatId="10001" Quantity="1" IsSideboard="false" Annotation="0" />
</CardGrouping>
"""

SAMPLE_BINDER_XML = b"""\
<CardGrouping Name="Trade Binder" GroupingType="Binder">
  <Item CatId="20001" Quantity="3" IsSideboard="false" Annotation="0" />
  <Item CatId="20002" Quantity="1" IsSideboard="false" Annotation="0" />
</CardGrouping>
"""

SAMPLE_MODERN_XML = b"""\
<CardGrouping Name="Modern Storm" NetDeckId="222333444"
              GroupingType="Deck" FormatCode="CMODERN"
              Timestamp="2026-05-15T08:30:00.000Z">
  <Item CatId="50001" Quantity="4" IsSideboard="false" Annotation="0" />
  <Item CatId="50002" Quantity="3" IsSideboard="false" Annotation="0" />
  <Item CatId="50003" Quantity="2" IsSideboard="true" Annotation="0" />
  <Item CatId="50004" Quantity="1" IsSideboard="true" Annotation="0" />
</CardGrouping>
"""

MALFORMED_XML = b"<this is not valid xml"

WRONG_ROOT_XML = b"""\
<DeckList Name="oops">
  <Card Name="Lightning Bolt" />
</DeckList>
"""

MISSING_GROUPING_TYPE_XML = b"""\
<CardGrouping Name="Unnamed">
  <Item CatId="10001" Quantity="1" IsSideboard="false" />
</CardGrouping>
"""


# ---------------------------------------------------------------------------
# parse_grouping_xml tests
# ---------------------------------------------------------------------------


def test_parse_deck_xml() -> None:
    result = parse_grouping_xml(SAMPLE_DECK_XML)
    assert result is not None
    assert result.name == "Legacy Reanimator"
    assert result.net_deck_id == "111106631"
    assert result.grouping_type == "Deck"
    assert result.format_code == "CLEGACY"
    assert result.deck_timestamp is not None
    assert result.deck_timestamp.year == 2026
    assert result.deck_timestamp.month == 5
    assert result.deck_timestamp.day == 17
    assert len(result.items) == 3
    # First item
    assert result.items[0].cat_id == 30302
    assert result.items[0].quantity == 1
    assert result.items[0].is_sideboard is False
    # Third item — sideboard
    assert result.items[2].cat_id == 42001
    assert result.items[2].quantity == 2
    assert result.items[2].is_sideboard is True


def test_parse_wishlist_xml() -> None:
    result = parse_grouping_xml(SAMPLE_WISHLIST_XML)
    assert result is not None
    assert result.grouping_type == "Wishlist"
    assert result.name == "My Wishlist"
    # Empty string NetDeckId → None
    assert result.net_deck_id is None
    # Empty FormatCode → None
    assert result.format_code is None
    assert len(result.items) == 1


def test_parse_binder_xml() -> None:
    result = parse_grouping_xml(SAMPLE_BINDER_XML)
    assert result is not None
    assert result.grouping_type == "Binder"
    assert result.name == "Trade Binder"
    # No NetDeckId attribute → None
    assert result.net_deck_id is None
    # No FormatCode attribute → None
    assert result.format_code is None
    # No Timestamp attribute → None
    assert result.deck_timestamp is None
    assert len(result.items) == 2


def test_parse_modern_deck() -> None:
    result = parse_grouping_xml(SAMPLE_MODERN_XML)
    assert result is not None
    assert result.format_code == "CMODERN"
    assert result.net_deck_id == "222333444"
    assert len(result.items) == 4
    mainboard = [i for i in result.items if not i.is_sideboard]
    sideboard = [i for i in result.items if i.is_sideboard]
    assert len(mainboard) == 2
    assert len(sideboard) == 2


def test_malformed_xml_returns_none() -> None:
    assert parse_grouping_xml(MALFORMED_XML) is None


def test_wrong_root_element_returns_none() -> None:
    assert parse_grouping_xml(WRONG_ROOT_XML) is None


def test_missing_grouping_type_returns_none() -> None:
    assert parse_grouping_xml(MISSING_GROUPING_TYPE_XML) is None


def test_empty_content_returns_none() -> None:
    assert parse_grouping_xml(b"") is None


def test_item_with_missing_catid_skipped() -> None:
    xml = b"""\
<CardGrouping Name="test" GroupingType="Deck">
  <Item Quantity="1" IsSideboard="false" />
  <Item CatId="100" Quantity="2" IsSideboard="false" />
</CardGrouping>
"""
    result = parse_grouping_xml(xml)
    assert result is not None
    # First item missing CatId is skipped
    assert len(result.items) == 1
    assert result.items[0].cat_id == 100


def test_item_with_bad_quantity_skipped() -> None:
    xml = b"""\
<CardGrouping Name="test" GroupingType="Deck">
  <Item CatId="100" Quantity="notanumber" IsSideboard="false" />
  <Item CatId="200" Quantity="3" IsSideboard="true" />
</CardGrouping>
"""
    result = parse_grouping_xml(xml)
    assert result is not None
    assert len(result.items) == 1
    assert result.items[0].cat_id == 200


# ---------------------------------------------------------------------------
# extract_deck_uuid tests
# ---------------------------------------------------------------------------


def test_extract_deck_uuid_standard_filename() -> None:
    fn = "grouping a1b2c3d4-e5f6-7890-abcd-ef1234567890.xml"
    assert extract_deck_uuid(fn) == "a1b2c3d4-e5f6-7890-abcd-ef1234567890"


def test_extract_deck_uuid_none_filename() -> None:
    assert extract_deck_uuid(None) is None


def test_extract_deck_uuid_empty_string() -> None:
    assert extract_deck_uuid("") is None


def test_extract_deck_uuid_no_match() -> None:
    assert extract_deck_uuid("Match_GameLog_01ea1246.dat") is None


def test_extract_deck_uuid_uppercase() -> None:
    fn = "grouping A1B2C3D4-E5F6-7890-ABCD-EF1234567890.xml"
    assert extract_deck_uuid(fn) == "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"


# ---------------------------------------------------------------------------
# ParsedGrouping model tests
# ---------------------------------------------------------------------------


def test_parsed_grouping_defaults() -> None:
    g = ParsedGrouping(grouping_type="Deck")
    assert g.name is None
    assert g.net_deck_id is None
    assert g.format_code is None
    assert g.deck_timestamp is None
    assert g.items == []
