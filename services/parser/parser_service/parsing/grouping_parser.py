"""Parse MTGO grouping XML files (deck compositions).

Grouping files are shipped by the agent alongside match logs.  Each
file describes a single deck (or binder/wishlist) with MTGO catalog
IDs, quantities, sideboard splits, and format metadata.

Expected XML structure::

    <CardGrouping Name="deck-name" NetDeckId="111106631"
                  GroupingType="Deck" FormatCode="CLEGACY"
                  Timestamp="2026-05-17T23:10:30.413Z">
      <Item CatId="30302" Quantity="1" IsSideboard="false" Annotation="0" />
      ...
    </CardGrouping>
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime

from pydantic import BaseModel, Field

_log = logging.getLogger("parser.grouping")


class GroupingItem(BaseModel):
    """A single card entry in a grouping XML."""

    cat_id: int
    quantity: int
    is_sideboard: bool


class ParsedGrouping(BaseModel):
    """Result of parsing an MTGO grouping XML file."""

    name: str | None = None
    net_deck_id: str | None = None
    grouping_type: str  # Deck, Wishlist, Binder
    format_code: str | None = None
    deck_timestamp: datetime | None = None
    items: list[GroupingItem] = Field(default_factory=list)


# Regex to extract the UUID from filenames like "grouping <uuid>.xml"
_DECK_UUID_RE = re.compile(
    r"grouping\s+([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
)


def extract_deck_uuid(filename: str | None) -> str | None:
    """Extract the deck UUID from a grouping filename.

    Filenames follow the pattern ``grouping <uuid>.xml``.  Returns
    ``None`` if the filename is missing or doesn't match.
    """
    if not filename:
        return None
    m = _DECK_UUID_RE.search(filename)
    return m.group(1) if m else None


def parse_grouping_xml(content: bytes) -> ParsedGrouping | None:
    """Parse an MTGO grouping XML payload.

    Returns ``None`` on malformed/unrecognisable XML so the caller
    can skip the file without raising.
    """
    try:
        root = ET.fromstring(content)  # noqa: S314 — trusted internal content
    except ET.ParseError:
        _log.warning("failed to parse grouping XML: invalid XML")
        return None

    if root.tag != "CardGrouping":
        _log.warning("unexpected root element <%s>; expected <CardGrouping>", root.tag)
        return None

    grouping_type = root.attrib.get("GroupingType")
    if not grouping_type:
        _log.warning("missing GroupingType attribute on <CardGrouping>")
        return None

    name = root.attrib.get("Name") or None
    net_deck_id = root.attrib.get("NetDeckId") or None
    format_code = root.attrib.get("FormatCode") or None

    deck_timestamp: datetime | None = None
    ts_str = root.attrib.get("Timestamp")
    if ts_str:
        try:
            # MTGO timestamps are ISO-8601 with 'Z' suffix.
            deck_timestamp = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            _log.debug("unparseable Timestamp %r; ignoring", ts_str)

    items: list[GroupingItem] = []
    for elem in root.iter("Item"):
        try:
            cat_id = int(elem.attrib["CatId"])
            quantity = int(elem.attrib["Quantity"])
            is_sb_raw = elem.attrib.get("IsSideboard", "false").lower()
            is_sideboard = is_sb_raw == "true"
            items.append(
                GroupingItem(
                    cat_id=cat_id,
                    quantity=quantity,
                    is_sideboard=is_sideboard,
                )
            )
        except (KeyError, ValueError, TypeError):
            _log.debug("skipping malformed <Item>: %s", ET.tostring(elem, encoding="unicode"))
            continue

    return ParsedGrouping(
        name=name,
        net_deck_id=net_deck_id,
        grouping_type=grouping_type,
        format_code=format_code,
        deck_timestamp=deck_timestamp,
        items=items,
    )
