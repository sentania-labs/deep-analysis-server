"""Template and markup assertions for mobile hamburger and sidebar (issue #171).

Asserts that:
- The mobile hamburger button carries the exclusion attribute (AC3).
- The hamburger button does not stop propagation with .stop so outside handlers
  (e.g., profile dropdown) still receive the event (AC2).
- The sidebar element registers an outside-click handler with event forwarding.
- The profile dropdown carries its outside-click closing handler.
- The Alpine sidebar store closeOnMobile implementation respects the exclusion.
"""

from __future__ import annotations

import re
from pathlib import Path

from bs4 import BeautifulSoup

TEMPLATE_PATH = Path(__file__).resolve().parents[1] / "web_service" / "templates" / "base.html"
APP_JS_PATH = Path(__file__).resolve().parents[1] / "web_service" / "static" / "js" / "app.js"


def _load_soup() -> BeautifulSoup:
    html = TEMPLATE_PATH.read_text(encoding="utf-8")
    return BeautifulSoup(html, "html.parser")


def test_hamburger_markup_carries_exclusion() -> None:
    """AC3: Assert the hamburger button carries the exclusion markup."""
    soup = _load_soup()
    hamburger = soup.find("button", attrs={"aria-label": "Toggle sidebar"})
    assert hamburger is not None, (
        "Hamburger button with aria-label='Toggle sidebar' not found in base.html"
    )

    # Must carry the exclusion attribute so outside handlers distinguish it from background clicks
    assert hamburger.has_attr("data-sidebar-toggle"), (
        "Hamburger button markup must carry 'data-sidebar-toggle' exclusion attribute"
    )

    # Click handler must invoke sidebar toggle
    click_handler = hamburger.get("@click")
    assert click_handler is not None, "Hamburger button must have an @click directive"
    assert "$store.sidebar.toggle()" in str(click_handler), (
        f"Hamburger @click must toggle sidebar store: {click_handler}"
    )

    # Must NOT use .stop modifier, which would block propagation to other outside handlers
    # like the profile dropdown menu
    assert not hamburger.has_attr("@click.stop"), (
        "Hamburger must not use @click.stop; event must bubble so open dropdowns close"
    )


def test_sidebar_markup_has_outside_handler() -> None:
    """Assert the sidebar aside element registers an outside click handler with event forwarding."""
    soup = _load_soup()
    aside = soup.find("aside")
    assert aside is not None, "<aside> element not found in base.html"

    handler = aside.get("@click.outside.window") or aside.get("@click.outside")
    assert handler is not None, (
        "Sidebar <aside> must have an @click.outside or @click.outside.window handler"
    )
    has_close = "$store.sidebar.closeOnMobile($event)" in str(
        handler
    ) or "$store.sidebar.closeOnMobile()" in str(handler)
    assert has_close, f"Sidebar outside handler must call closeOnMobile: {handler}"


def test_profile_dropdown_markup_has_outside_handler() -> None:
    """AC2: Profile dropdown must carry an outside click handler to close when tapping outside."""
    soup = _load_soup()
    profile_btn = soup.find("button", attrs={"aria-haspopup": "true"})
    assert profile_btn is not None, "Profile dropdown button not found in base.html"

    outside_handler = profile_btn.get("@click.outside")
    assert outside_handler is not None, "Profile button must have an @click.outside handler"
    assert "open = false" in str(outside_handler), (
        f"Profile button @click.outside must close the dropdown: {outside_handler}"
    )


def test_app_js_close_on_mobile_excludes_hamburger() -> None:
    """Assert that app.js Alpine sidebar store closeOnMobile ignores hamburger clicks."""
    content = APP_JS_PATH.read_text(encoding="utf-8")
    assert "closeOnMobile" in content, "closeOnMobile function missing in app.js"
    assert "data-sidebar-toggle" in content, (
        "app.js closeOnMobile must check for data-sidebar-toggle exclusion"
    )
    # Check that it checks width and closest selector
    assert re.search(r"closest\([^)]*data-sidebar-toggle", content), (
        "app.js closeOnMobile must query closest('[data-sidebar-toggle]') on event target"
    )
