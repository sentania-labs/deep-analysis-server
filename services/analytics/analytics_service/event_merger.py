"""Canonical-event merger for the mtgtop8 and mtgo scraper feeds.

The two scrapers populate independent tables (``analytics.mtgtop8_events``
and ``analytics.mtgo_events``). The same real-world event — say a Pauper
League on 2026-05-21 — often shows up in both. The user-facing metagame
view wants a single canonical entry per logical event, but the two
sources aren't strictly redundant:

- mtgtop8 carries archetype labels (``deck_name``) — those are gold; we
  don't want to throw them away or re-derive them.
- mtgo.com sometimes publishes deeper standings (more participants) than
  mtgtop8 covers — for leagues especially, the MTGO listing may include
  the full top-32 while mtgtop8 only shows the top-8.

Rule:
    * Event metadata (name, date, format) — **mtgtop8 wins** when both
      sources have it.
    * Participants / decklists — **union** both sources keyed by player
      name. mtgtop8-derived entries keep their archetype labels;
      MTGO-only entries land without labels (the classifier can attempt
      them later).
    * When only one source has the event, that source is used as-is.

This module is pure logic — no DB, no HTTP. Callers load events from
each scraper's tables, hand them to :func:`merge_events`, and get back
a list of :class:`CanonicalEvent` for display. :func:`merge_results`
performs the same union on per-event participant rows for the detail
view.

Match key
---------
Two events match iff all three of these agree, and none of them is
missing:

    (format, event_date, event_signature)

``event_signature`` is the event name with format names, dates, and
numeric suffixes stripped — so ``"Pauper League May212026"`` and
``"Pauper League — May 21, 2026"`` both reduce to ``"league"`` and
match on the same date + format.

If any of (format, date, signature) is missing for an event, it does
not merge — it stands alone. That's conservative: we miss some
genuine duplicates rather than false-merge unrelated events.
"""

from __future__ import annotations

import dataclasses
import re
from datetime import date
from typing import Any

# Format tokens that appear in event names and should be stripped before
# the signature is computed. Keep lowercase, no plurals.
_FORMAT_TOKENS = (
    "vintage",
    "legacy",
    "modern",
    "pioneer",
    "pauper",
    "standard",
    "historic",
    "explorer",
    "alchemy",
    "timeless",
    "premodern",
    "limited",
    "draft",
    "sealed",
)

# Patterns that look like dates inside the event name. mtgo.com uses
# both YYYY-MM-DD and the slug form, mtgtop8 uses DD/MM/YY, and humans
# write things like "May 21, 2026" or "21st May 2026".
_DATE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\d{4}-\d{2}-\d{2}"),
    re.compile(r"\d{1,2}/\d{1,2}/\d{2,4}"),
    # Day-first ("21st May 2026", "21 May 2026"). Run before the
    # month-first pattern so the ordinal suffix doesn't get stranded
    # when the month-first pattern would otherwise claim "may 2026"
    # and leave "21st" behind.
    re.compile(
        r"\b\d{1,2}(st|nd|rd|th)?\s*(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s*\d{2,4}\b",
        re.IGNORECASE,
    ),
    # Month-first ("May 21, 2026" or "May 21 2026"). The ``\s+`` between
    # day and year (rather than ``\s*``) is what stops it from greedily
    # matching just "May 2026" — we want a real day token in between.
    re.compile(
        r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\s+\d{1,2}\s*,?\s+\d{2,4}\b",
        re.IGNORECASE,
    ),
    # MTGO often joins month + day + year with no spaces:
    # "May212026" or "may212026". Match a month name followed by
    # 5-8 digits.
    re.compile(
        r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\d{4,8}\b",
        re.IGNORECASE,
    ),
)


def normalize_format(value: str | None) -> str | None:
    """Lower-case and trim a format string. ``None`` / blank → ``None``."""
    if not value:
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def event_signature(name: str | None) -> str | None:
    """Reduce an event name to its 'type' tokens.

    The signature is what's left of the name after stripping format
    words, date patterns, and numeric suffixes. Empty result → ``None``.

    Examples:
        "Pauper League May212026"          -> "league"
        "Pauper League — May 21, 2026"     -> "league"
        "Modern Challenge 32 2026-05-08"   -> "challenge"
        "Modern Showcase Challenge"        -> "showcase challenge"
        "Vintage Super Qualifier"          -> "super qualifier"
    """
    if not name:
        return None
    text = name.lower()
    for pattern in _DATE_PATTERNS:
        text = pattern.sub(" ", text)
    for token in _FORMAT_TOKENS:
        text = re.sub(r"\b" + re.escape(token) + r"\b", " ", text)
    # Drop standalone numbers (event sizes like "32", "64", years like
    # "2026") and punctuation. We keep letters and whitespace only.
    text = re.sub(r"[^a-z\s]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or None


@dataclasses.dataclass(frozen=True)
class MatchKey:
    """Three-tuple that identifies the same logical event across sources."""

    format: str
    event_date: date
    signature: str


def match_key(event: dict[str, Any]) -> MatchKey | None:
    """Return a :class:`MatchKey` for *event*, or ``None`` if it can't merge.

    An event with any of (format, event_date, signature) missing is
    treated as un-mergeable — it stands alone in the output.
    """
    fmt = normalize_format(event.get("format"))
    if fmt is None:
        return None
    event_date = event.get("event_date")
    if not isinstance(event_date, date):
        return None
    signature = event_signature(event.get("event_name"))
    if signature is None:
        return None
    return MatchKey(format=fmt, event_date=event_date, signature=signature)


@dataclasses.dataclass
class CanonicalEvent:
    """A single canonical event after merging the two scraper feeds."""

    primary_source: str
    primary_event_id: int
    event_name: str
    event_date: date | None
    format: str | None
    player_count: int | None
    # ``sources`` lists every feed that contributed to this canonical
    # event, primary first. Used by the UI to show "merged from N
    # sources" attribution.
    sources: list[str]
    # ``supplement_events`` lists ``(source, event_id)`` pairs for the
    # non-primary contributors. The detail view loads these and unions
    # their participants into the primary's result list.
    supplement_events: list[tuple[str, int]]


def merge_events(
    mtgtop8_events: list[dict[str, Any]],
    mtgo_events: list[dict[str, Any]],
) -> list[CanonicalEvent]:
    """Merge per-source event lists into a canonical list.

    Each input event dict must carry at least ``id``, ``event_name``,
    ``event_date``, and ``format``; ``player_count`` is optional.

    Output ordering: events with a date are sorted by date descending,
    then by name. Date-less events come last.
    """
    by_key: dict[MatchKey, dict[str, list[dict[str, Any]]]] = {}
    no_key: list[tuple[str, dict[str, Any]]] = []

    def assign(source: str, event: dict[str, Any]) -> None:
        key = match_key(event)
        if key is None:
            no_key.append((source, event))
            return
        by_key.setdefault(key, {"mtgtop8": [], "mtgo": []})[source].append(event)

    for event in mtgtop8_events:
        assign("mtgtop8", event)
    for event in mtgo_events:
        assign("mtgo", event)

    out: list[CanonicalEvent] = []

    for sources in by_key.values():
        mtgtop8_group = sources["mtgtop8"]
        mtgo_group = sources["mtgo"]
        if mtgtop8_group:
            # The first mtgtop8 entry absorbs every MTGO sibling as a
            # supplement. Any additional mtgtop8 entries at the same key
            # stand alone — we don't second-guess mtgtop8's own list of
            # events; it deliberately separates them.
            primary = mtgtop8_group[0]
            out.append(
                _canonical(
                    primary_source="mtgtop8",
                    primary=primary,
                    sources=["mtgtop8"] + (["mtgo"] if mtgo_group else []),
                    supplements=[("mtgo", e["id"]) for e in mtgo_group],
                )
            )
            for extra in mtgtop8_group[1:]:
                out.append(
                    _canonical(
                        primary_source="mtgtop8",
                        primary=extra,
                        sources=["mtgtop8"],
                        supplements=[],
                    )
                )
        else:
            for event in mtgo_group:
                out.append(
                    _canonical(
                        primary_source="mtgo",
                        primary=event,
                        sources=["mtgo"],
                        supplements=[],
                    )
                )

    for source, event in no_key:
        out.append(
            _canonical(
                primary_source=source,
                primary=event,
                sources=[source],
                supplements=[],
            )
        )

    out.sort(
        key=lambda c: (
            c.event_date is None,
            -(c.event_date.toordinal() if c.event_date else 0),
            c.event_name or "",
        )
    )
    return out


def _canonical(
    *,
    primary_source: str,
    primary: dict[str, Any],
    sources: list[str],
    supplements: list[tuple[str, int]],
) -> CanonicalEvent:
    raw_date = primary.get("event_date")
    return CanonicalEvent(
        primary_source=primary_source,
        primary_event_id=int(primary["id"]),
        event_name=str(primary.get("event_name") or ""),
        event_date=raw_date if isinstance(raw_date, date) else None,
        format=primary.get("format"),
        player_count=(
            int(primary["player_count"]) if primary.get("player_count") is not None else None
        ),
        sources=sources,
        supplement_events=supplements,
    )


def find_supplements_for(
    *,
    primary_source: str,
    primary_event: dict[str, Any],
    candidate_events: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return the events from *candidate_events* that match *primary_event*.

    Used by the detail endpoint to supplement an mtgtop8 event with its
    sibling MTGO event(s) (or the reverse, though in practice mtgtop8
    wins primary so the reverse never fires through the UI).

    Candidates with a different source than expected are returned as-is;
    callers are responsible for sorting that out. The function is a pure
    key match — no source check beyond the *primary_event* anchor.
    """
    primary_key = match_key(primary_event)
    if primary_key is None:
        return []
    out: list[dict[str, Any]] = []
    for candidate in candidate_events:
        if match_key(candidate) == primary_key:
            # Skip the primary itself if the caller mixed it into the
            # candidate pool (same source, same id).
            if (
                candidate.get("id") == primary_event.get("id")
                and candidate.get("source", primary_source) == primary_source
            ):
                continue
            out.append(candidate)
    return out


def merge_results(
    primary_results: list[dict[str, Any]],
    supplement_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Union per-player rows from the primary and supplementing sources.

    Keyed by ``player_name`` (case-insensitive, trimmed). Primary
    entries always win — they carry the archetype label (``deck_name``)
    from mtgtop8 which we don't want to drop. Supplement-only players
    (e.g., the top-9-to-32 from an MTGO league that mtgtop8 skipped)
    land in the merged list with their MTGO data and ``deck_name=None``.

    The function never mutates its inputs.

    Output ordering: by placement ascending (NULLs last), then by
    player name.
    """
    seen: dict[str, dict[str, Any]] = {}
    out: list[dict[str, Any]] = []

    def _key(entry: dict[str, Any]) -> str:
        return (entry.get("player_name") or "").strip().lower()

    for entry in primary_results:
        key = _key(entry)
        if not key or key in seen:
            continue
        copied = dict(entry)
        seen[key] = copied
        out.append(copied)

    for entry in supplement_results:
        key = _key(entry)
        if not key or key in seen:
            continue
        copied = dict(entry)
        # MTGO-only players don't carry an archetype label; null it
        # explicitly so the UI doesn't render a stale value from the
        # supplement source's schema.
        copied["deck_name"] = None
        seen[key] = copied
        out.append(copied)

    out.sort(
        key=lambda r: (
            r.get("placement") is None,
            r.get("placement") if r.get("placement") is not None else 0,
            (r.get("player_name") or "").lower(),
        )
    )
    return out
