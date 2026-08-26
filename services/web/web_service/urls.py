"""URL helpers for filter-preserving navigation links.

Shared by the admin and user-facing templates. Any link that changes one facet
of a filtered list (a review-status chip, an opponent drill-down) must keep the
filters the user already set, otherwise the result set silently widens.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

__all__ = ["filter_url"]


def filter_url(
    path: str,
    filters: Mapping[str, Any] | None = None,
    replace: Mapping[str, Any] | None = None,
    *,
    per_page: Any = None,
) -> str:
    """Build ``path`` with the current ``filters``, some of them replaced.

    ``filters`` is the route's active filter mapping (the same dict the
    templates already receive). ``replace`` overrides individual keys: a value
    that is empty or ``None`` drops that key entirely, which is how a link
    clears a single filter. Empty values in ``filters`` are dropped too.

    Pagination is always reset: ``page`` is never carried over, so a link built
    here lands on page 1 of the new result set. ``per_page`` is kept when a
    truthy value is passed, since page size is a display preference rather than
    a position in the results.

    Returns ``path`` with no ``?`` when nothing survives, so unfiltered links
    stay clean.
    """
    merged: dict[str, Any] = {}
    for key, value in (filters or {}).items():
        if key in ("page", "per_page"):
            continue
        merged[key] = value
    for key, value in (replace or {}).items():
        merged[key] = value

    # Explicit None/empty-string test rather than a truthiness check: a
    # numeric filter value of 0 is a real filter and must survive.
    params = [(k, str(v)) for k, v in merged.items() if v is not None and v != ""]
    if per_page:
        params.append(("per_page", str(per_page)))
    if not params:
        return path
    return f"{path}?{urlencode(params)}"
