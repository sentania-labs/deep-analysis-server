"""Template and asset lint for the browser execution boundary (issue #126).

This is a lint over the web service's own artifacts, not a behaviour test:

* no inline ``<script>`` in a template (JSON data blocks excepted: they are
  never executed),
* no ``on*=`` handler and no ``style=`` attribute in a template,
* no script, stylesheet, font or frame loaded from another origin,
* every vendored third-party file hashes to ``static/vendor/manifest.json``,
* the ``integrity`` attributes in templates match the manifest.

Whether the pages actually run under the gateway CSP (Alpine expressions
evaluating on the CSP build, htmx not injecting inline styles, no console
error on any page or control) is proven in a real browser by
``ci/browser/smoke_csp.py``, which is part of ``bash ci/smoke.sh ui``.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

STATIC_DIR = Path(__file__).resolve().parents[1] / "web_service" / "static"
TEMPLATE_DIR = Path(__file__).resolve().parents[1] / "web_service" / "templates"
MANIFEST = STATIC_DIR / "vendor" / "manifest.json"

TEMPLATES = sorted(TEMPLATE_DIR.glob("*.html"))

_SCRIPT_OPEN = re.compile(r"<script\b([^>]*)>", re.IGNORECASE)
_HANDLER_ATTR = re.compile(r"""\son[a-z]+\s*=\s*["']""", re.IGNORECASE)
_STYLE_ATTR = re.compile(r"""\sstyle\s*=\s*["']""", re.IGNORECASE)
_STYLE_TAG = re.compile(r"<style\b", re.IGNORECASE)
_EXTERNAL_RESOURCE = re.compile(
    r"""<(?:script|link|iframe|object|embed|frame|img)\b[^>]*\b(?:src|href)\s*=\s*["'](?:https?:)?//""",
    re.IGNORECASE,
)
_INTEGRITY = re.compile(r"""src="/static/([^"?]+)(?:\?[^"]*)?"[^>]*integrity="([^"]+)\"""")


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text())


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_has_no_inline_script(template: Path) -> None:
    text = template.read_text()
    for m in _SCRIPT_OPEN.finditer(text):
        attrs = m.group(1)
        if re.search(r"""type\s*=\s*["']application/json["']""", attrs):
            continue
        assert re.search(r"""\bsrc\s*=\s*["']/static/""", attrs), (
            f"{template.name}: inline <script> is blocked by script-src 'self': {m.group(0)}"
        )


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_has_no_inline_handlers_or_styles(template: Path) -> None:
    text = template.read_text()
    handlers = [m.group(0).strip() for m in _HANDLER_ATTR.finditer(text)]
    assert not handlers, f"{template.name}: inline event handlers: {handlers}"
    styles = [m.group(0).strip() for m in _STYLE_ATTR.finditer(text)]
    assert not styles, f"{template.name}: style= attributes are inline styles: {styles}"
    assert not _STYLE_TAG.search(text), f"{template.name}: inline <style> element"


@pytest.mark.parametrize("template", TEMPLATES, ids=lambda p: p.name)
def test_template_loads_no_third_party_resource(template: Path) -> None:
    text = template.read_text()
    hits = [m.group(0) for m in _EXTERNAL_RESOURCE.finditer(text)]
    assert not hits, f"{template.name}: third-party resource load: {hits}"


def test_manifest_lists_every_vendored_file() -> None:
    manifest = _manifest()
    listed = {entry["path"] for entry in manifest["assets"]}
    on_disk = set()
    for sub in ("vendor", "fonts"):
        for f in (STATIC_DIR / sub).iterdir():
            if f.name == "manifest.json" or f.name.startswith("LICENSE"):
                continue
            on_disk.add(f"{sub}/{f.name}")
    assert on_disk == listed, (
        f"unlisted on disk: {sorted(on_disk - listed)}; "
        f"listed but missing: {sorted(listed - on_disk)}"
    )


@pytest.mark.parametrize("entry", _manifest()["assets"], ids=lambda e: e["path"])
def test_vendored_file_matches_manifest(entry: dict) -> None:
    path = STATIC_DIR / entry["path"]
    assert path.is_file(), f"{entry['path']} missing"
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    assert digest == entry["sha256"], f"{entry['path']}: sha256 {digest} != manifest"
    assert (STATIC_DIR / entry["license_file"]).is_file(), f"{entry['path']}: license file missing"
    if "sri" in entry:
        algo, _, expected = entry["sri"].partition("-")
        import base64

        actual = base64.b64encode(hashlib.new(algo, path.read_bytes()).digest()).decode()
        assert actual == expected, f"{entry['path']}: {algo} SRI mismatch"


def test_template_integrity_attributes_match_manifest() -> None:
    by_path = {e["path"]: e for e in _manifest()["assets"] if "sri" in e}
    seen = 0
    for t in TEMPLATES:
        for m in _INTEGRITY.finditer(t.read_text()):
            rel, sri = m.group(1), m.group(2)
            assert rel in by_path, f"{t.name}: integrity on unlisted asset {rel}"
            assert sri == by_path[rel]["sri"], f"{t.name}: stale integrity for {rel}"
            seen += 1
    assert seen >= 3, "expected integrity attributes on htmx, alpine and chart.js"
