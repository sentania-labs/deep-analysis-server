"""Public landing page (`/`) rendering tests.

The route logic itself (redirect-when-logged-in) is exercised
elsewhere; here we confirm the anonymous landing page actually
ships the substantive marketing content we promise — sections,
CTAs, SEO/OpenGraph meta tags, and the registration-open toggle.
"""

from __future__ import annotations

from collections.abc import AsyncIterator

import httpx
import pytest
import pytest_asyncio


@pytest_asyncio.fixture
async def app_client() -> AsyncIterator[httpx.AsyncClient]:
    from web_service import deps as _deps
    from web_service import main as _main
    from web_service import settings as _settings

    _settings._settings = None
    _deps.reset_verifier()

    transport = httpx.ASGITransport(app=_main.app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


async def _patch_registration_mode(monkeypatch: pytest.MonkeyPatch, mode: str) -> None:
    from web_service import auth_client

    async def fake_mode(_url: str) -> str:
        return mode

    monkeypatch.setattr(auth_client, "public_get_registration_mode", fake_mode)


@pytest.mark.asyncio
async def test_landing_renders_core_sections(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _patch_registration_mode(monkeypatch, "open")

    r = await app_client.get("/")
    assert r.status_code == 200
    body = r.text

    # Hero + product framing
    assert "Deep Analysis" in body
    assert "MTGO" in body
    # "What this is" section
    assert "what this is" in body
    # "Get started" section (anchor and label)
    assert 'id="get-started"' in body
    assert "get started" in body
    # Feature section
    assert "what you get" in body
    # FAQ
    assert "faq" in body
    assert "Is my play data private?" in body
    # Final CTA buttons
    assert 'href="/login"' in body


@pytest.mark.asyncio
async def test_landing_shows_register_link_when_registration_open(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _patch_registration_mode(monkeypatch, "open")

    r = await app_client.get("/")
    assert r.status_code == 200
    assert 'href="/register"' in r.text


@pytest.mark.asyncio
async def test_landing_hides_register_link_when_registration_closed(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _patch_registration_mode(monkeypatch, "closed")

    r = await app_client.get("/")
    assert r.status_code == 200
    # Login is always available; registration is gated.
    assert 'href="/login"' in r.text
    assert 'href="/register"' not in r.text


@pytest.mark.asyncio
async def test_landing_has_seo_and_open_graph_meta(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _patch_registration_mode(monkeypatch, "open")

    r = await app_client.get("/")
    assert r.status_code == 200
    body = r.text

    # Descriptive <title> (not just the default "Deep Analysis")
    assert "<title>Deep Analysis — MTGO match analytics, automatically</title>" in body
    # Meta description
    assert '<meta name="description"' in body
    # Open Graph
    assert 'property="og:type"' in body
    assert 'property="og:title"' in body
    assert 'property="og:description"' in body
    # Twitter card
    assert 'name="twitter:card"' in body


@pytest.mark.asyncio
async def test_landing_links_to_github_releases_and_repos(
    app_client: httpx.AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    await _patch_registration_mode(monkeypatch, "open")

    r = await app_client.get("/")
    assert r.status_code == 200
    body = r.text

    assert "sentania-labs/deep-analysis-agent/releases/latest" in body
    assert "sentania-labs/deep-analysis-server" in body
    assert "sentania-labs/deep-analysis-agent" in body
