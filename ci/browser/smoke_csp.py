#!/usr/bin/env python3
"""ci/browser/smoke_csp.py: the web UI, in a real browser, under the production CSP.

The gateway ships ``script-src 'self'; style-src 'self'`` with no
'unsafe-inline', no 'unsafe-eval' and no third-party origin (issue #126). A
template that still needs one of those does not fail a curl test; the browser
refuses the script or style and only the console knows. This suite loads every
rendered page as the admin and as an ordinary user, drives every JavaScript
control the pages have, and fails on:

* any ``securitypolicyviolation`` event,
* any console error (Chrome reports CSP refusals, Alpine expression errors and
  failed asset loads there), any uncaught exception, any failed request,
* any control that does not do what it did before the CSP tightened.

Runs against a stack started by ci/smoke.sh, which is the only supported
caller; it needs the bootstrap admin credentials in the environment, the same
way ci/smoke_ui.sh does.

Usage:
    DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL=... DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD=... \\
    uv run smoke_csp.py http://localhost:8080

Exit 0 = every check passed. Exit 1 = one or more failed.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import re
import sys
import time
from dataclasses import dataclass, field

from playwright.sync_api import (
    Browser,
    BrowserContext,
    Dialog,
    Page,
    Response,
    sync_playwright,
)


class WaitTimeout(Exception):
    """wait_until gave up."""


# Archetype, B&R event and match ids are UUIDs, so a digit-only pattern
# never matches and the edit pages drop out of the suite unnoticed.
_UUID = "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"

SMOKE_USER_EMAIL = "csp-smoke@local"
SMOKE_USER_PASSWORD = "CspSmokeUserPw2026!"
CANCELLED_USER_EMAIL = "csp-cancelled@local"
FIXTURE_USER_EMAIL = "csp-fixture@local"
FIXTURE_USER_PASSWORD = "CspFixtureUserPw2026!"

# Recorded before any page script runs, so nothing is missed.
INIT_SCRIPT = """
window.__cspViolations = [];
document.addEventListener('securitypolicyviolation', function (e) {
    window.__cspViolations.push({
        directive: e.effectiveDirective || e.violatedDirective,
        blocked: e.blockedURI,
        sample: e.sample || '',
        source: (e.sourceFile || '') + ':' + (e.lineNumber || 0)
    });
});
"""

ADMIN_PAGES = [
    "/admin/users",
    "/admin/agents",
    "/admin/matches",
    "/admin/archetypes",
    "/admin/archetypes/new",
    "/admin/bnr-events",
    "/admin/bnr-events/new",
    "/admin/cards",
    "/admin/invites",
    "/admin/settings",
    "/admin/scrapers",
    "/metagame",
    "/settings/password",
]

USER_PAGES = [
    "/dashboard",
    "/matches",
    "/cards",
    "/metagame",
    "/profile",
    "/profile/edit",
    "/profile/agents",
    "/settings/password",
]

PUBLIC_PAGES = ["/", "/login", "/register"]


@dataclass
class Tally:
    passed: int = 0
    failed: int = 0

    def check(self, label: str, ok: bool, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"  PASS: {label}")
        else:
            self.failed += 1
            print(f"  FAIL: {label}{(' (' + detail + ')') if detail else ''}", file=sys.stderr)
        return ok


@dataclass
class Recorder:
    """Console errors, uncaught exceptions and failed requests since the last drain."""

    console_errors: list[str] = field(default_factory=list)
    page_errors: list[str] = field(default_factory=list)
    request_failures: list[str] = field(default_factory=list)
    bad_responses: list[str] = field(default_factory=list)

    def attach(self, page: Page) -> None:
        page.on(
            "console",
            lambda m: self.console_errors.append(m.text) if m.type == "error" else None,
        )
        page.on("pageerror", lambda e: self.page_errors.append(str(e)))
        page.on(
            "requestfailed",
            lambda r: self.request_failures.append(f"{r.method} {r.url}: {r.failure}"),
        )
        page.on("response", self._on_response)

    def _on_response(self, r: Response) -> None:
        # Subresources only; document status is asserted by visit().
        if r.status >= 400 and r.request.resource_type in {
            "script",
            "stylesheet",
            "font",
            "image",
            "fetch",
            "xhr",
        }:
            self.bad_responses.append(f"{r.status} {r.request.method} {r.url}")

    def drain(self) -> list[str]:
        out = (
            [f"console: {m}" for m in self.console_errors]
            + [f"uncaught: {m}" for m in self.page_errors]
            + [f"request failed: {m}" for m in self.request_failures]
            + [f"bad response: {m}" for m in self.bad_responses]
        )
        self.console_errors.clear()
        self.page_errors.clear()
        self.request_failures.clear()
        self.bad_responses.clear()
        return out


class Smoke:
    def __init__(self, base_url: str) -> None:
        self.base = base_url.rstrip("/")
        self.t = Tally()
        self.admin_email = os.environ["DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL"]
        self.admin_password = os.environ["DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD"]
        self.dialog_action = "accept"

    # ------------------------------------------------------------------ setup
    def new_page(self, browser: Browser) -> tuple[BrowserContext, Page, Recorder]:
        ctx = browser.new_context(viewport={"width": 1280, "height": 900})
        ctx.add_init_script(INIT_SCRIPT)
        page = ctx.new_page()
        rec = Recorder()
        rec.attach(page)
        page.on("dialog", self._on_dialog)
        return ctx, page, rec

    def _on_dialog(self, dialog: Dialog) -> None:
        # data-confirm prompts. self.dialog_action is flipped by the test
        # that wants the cancel path.
        if self.dialog_action == "accept":
            dialog.accept()
        else:
            dialog.dismiss()

    # ---------------------------------------------------------------- helpers
    def wait_until(self, page: Page, expression: str, timeout: int = 10_000) -> None:
        """Poll a JS expression through page.evaluate until it is truthy.

        Playwright's own wait-for-function polls by compiling the expression
        inside the page with new Function, which this very CSP blocks (a
        nice confirmation that the policy works, but useless for waiting).
        page.evaluate runs through DevTools and is not subject to the CSP.
        """
        deadline = time.monotonic() + timeout / 1000
        while True:
            if page.evaluate(f"!!({expression})"):
                return
            if time.monotonic() > deadline:
                raise WaitTimeout(f"timed out after {timeout}ms waiting for: {expression}")
            page.wait_for_timeout(100)

    def settle(self, page: Page) -> None:
        page.wait_for_load_state("networkidle")
        # Alpine and htmx both initialise on DOMContentLoaded; wait for
        # Alpine's global so expression errors have had their chance.
        with contextlib.suppress(WaitTimeout):
            self.wait_until(page, "window.Alpine && window.htmx", timeout=10_000)

    def audit(self, page: Page, rec: Recorder, label: str) -> None:
        violations = page.evaluate("window.__cspViolations || []")
        page.evaluate("window.__cspViolations = []")
        self.t.check(
            f"{label}: no CSP violations",
            not violations,
            "; ".join(
                f"{v['directive']} blocked {v['blocked']} at {v['source']}" for v in violations
            ),
        )
        errors = rec.drain()
        self.t.check(f"{label}: no console errors or failed loads", not errors, "; ".join(errors))

    def visit(self, page: Page, rec: Recorder, path: str, expect_path: str | None = None) -> bool:
        resp = page.goto(self.base + path, wait_until="domcontentloaded")
        self.settle(page)
        status = resp.status if resp else 0
        ok = self.t.check(f"GET {path} -> 200", status == 200, f"got {status}")
        final = re.sub(r"^https?://[^/]+", "", page.url)
        if expect_path is not None:
            ok = (
                self.t.check(
                    f"GET {path} lands on {expect_path}", final.startswith(expect_path), final
                )
                and ok
            )
        elif final.startswith("/login") and not path.startswith("/login"):
            ok = (
                self.t.check(f"GET {path} stays authenticated", False, f"redirected to {final}")
                and ok
            )
        self.audit(page, rec, f"GET {path}")
        if resp is not None and path in ("/login", "/dashboard", "/admin/users"):
            self.check_csp_header(resp, path)
        return ok

    def check_csp_header(self, resp: Response, path: str) -> None:
        csp = resp.headers.get("content-security-policy", "")
        self.t.check(f"{path}: CSP header present", bool(csp))
        self.t.check(f"{path}: CSP has no unsafe-inline / unsafe-eval", "unsafe-" not in csp, csp)
        m = re.search(r"script-src ([^;]+)", csp)
        self.t.check(
            f"{path}: script-src is exactly 'self'", bool(m) and m.group(1).strip() == "'self'", csp
        )
        m = re.search(r"style-src ([^;]+)", csp)
        self.t.check(
            f"{path}: style-src is exactly 'self'", bool(m) and m.group(1).strip() == "'self'", csp
        )
        for directive in ("object-src 'none'", "base-uri 'self'"):
            self.t.check(f"{path}: CSP has {directive}", directive in csp, csp)

    def login(self, page: Page, rec: Recorder, email: str, password: str, lands_on: str) -> bool:
        page.goto(self.base + "/login", wait_until="domcontentloaded")
        self.settle(page)
        page.fill('input[name="email"]', email)
        page.fill('input[name="password"]', password)
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.click('button[type="submit"]')
        self.settle(page)
        final = re.sub(r"^https?://[^/]+", "", page.url)
        ok = self.t.check(
            f"login as {email} lands on {lands_on}", final.startswith(lands_on), final
        )
        self.audit(page, rec, f"login as {email}")
        return ok

    # ------------------------------------------------------------- public
    def run_public(self, browser: Browser) -> None:
        print("")
        print("--- public pages ---")
        ctx, page, rec = self.new_page(browser)
        for path in PUBLIC_PAGES:
            self.visit(page, rec, path)
        ctx.close()

    # -------------------------------------------------------------- admin
    def run_admin(self, browser: Browser) -> None:
        print("")
        print("--- admin session ---")
        ctx, page, rec = self.new_page(browser)
        if not self.login(page, rec, self.admin_email, self.admin_password, "/admin/users"):
            ctx.close()
            return

        for path in ADMIN_PAGES:
            self.visit(page, rec, path)

        # Detail pages that only exist when rows exist: follow whatever the
        # list pages link to, so a populated stack gets more coverage.
        self.visit_linked(page, rec, "/admin/archetypes", rf"^/admin/archetypes/{_UUID}/edit$")
        self.visit_linked(page, rec, "/admin/bnr-events", rf"^/admin/bnr-events/{_UUID}/edit$")
        self.visit_linked(page, rec, "/admin/matches", r"^/admin/matches/[^/?]+$")

        self.section("shared chrome", self.check_chrome, page, rec)
        self.section("/admin/settings controls", self.check_settings, page, rec)
        self.section("submit-once control", self.check_submit_once, page, rec)
        self.section("scraper event pages", self.check_scraper_events, page, rec)
        self.section("/metagame component", self.check_metagame, page, rec)

        print("")
        print("--- admin creates the smoke user ---")
        self.section("create smoke user", self.ensure_smoke_user, page, rec)
        self.admin_ctx = ctx
        self.admin_page = page
        self.admin_rec = rec

    def visit_linked(self, page: Page, rec: Recorder, list_path: str, pattern: str) -> None:
        page.goto(self.base + list_path, wait_until="domcontentloaded")
        self.settle(page)
        hrefs = page.evaluate(
            "Array.from(document.querySelectorAll('a[href]')).map(a => a.getAttribute('href'))"
        )
        rx = re.compile(pattern)
        for href in hrefs:
            if href and rx.match(href):
                self.visit(page, rec, href)
                return
        # Not a skip. Every list this is called with is backed by a seeded
        # fixture, so "no matching link" means the page did not render the
        # row or the pattern no longer matches the id format, and the page
        # it guards would silently drop out of the CSP coverage.
        self.t.check(
            f"{list_path} links to a page matching {pattern}",
            False,
            "no matching link rendered",
        )

    def check_chrome(self, page: Page, rec: Recorder) -> None:
        """The base.html controls: theme toggle, profile menu, sidebar, MOTD."""
        print("")
        print("--- shared chrome (base.html) ---")
        self.visit(page, rec, "/admin/users")

        # Theme toggle flips <html class="dark"> and persists to localStorage.
        was_dark = page.evaluate("document.documentElement.classList.contains('dark')")
        page.click('button[title="Toggle theme"]')
        self.wait_until(
            page,
            f"document.documentElement.classList.contains('dark') === {str(not was_dark).lower()}",
            timeout=5_000,
        )
        stored = page.evaluate("localStorage.getItem('theme')")
        self.t.check("theme toggle flips the dark class", True)
        self.t.check(
            "theme toggle persists to localStorage",
            stored == ("light" if was_dark else "dark"),
            f"stored={stored}",
        )
        page.click('button[title="Toggle theme"]')
        self.wait_until(
            page,
            f"document.documentElement.classList.contains('dark') === {str(was_dark).lower()}",
            timeout=5_000,
        )

        # Profile dropdown opens on click and closes on an outside click
        # (the page heading is a safe place to click: nothing submits).
        menu = page.locator('ul[role="menu"]')
        self.t.check("profile menu starts hidden", not menu.is_visible())
        page.click('button[aria-haspopup="true"]')
        menu.wait_for(state="visible", timeout=5_000)
        self.t.check("profile menu opens", menu.is_visible())
        page.locator("main h1").first.click()
        menu.wait_for(state="hidden", timeout=5_000)
        self.t.check("profile menu closes on outside click", not menu.is_visible())

        # Sidebar store on a narrow viewport: the backdrop closes it. Start
        # from a known state.
        page.set_viewport_size({"width": 800, "height": 900})
        page.evaluate("Alpine.store('sidebar').open = true")
        backdrop = page.locator("div.fixed.inset-0.z-30")
        backdrop.wait_for(state="visible", timeout=5_000)
        backdrop.click(position={"x": 700, "y": 600})
        self.wait_until(page, "Alpine.store('sidebar').open === false", timeout=5_000)
        self.t.check("backdrop click closes the sidebar", True)
        page.set_viewport_size({"width": 1280, "height": 900})
        self.audit(page, rec, "shared chrome interactions")

    def check_settings(self, page: Page, rec: Recorder) -> None:
        """/admin/settings: MOTD set / dismiss / clear (data-confirm both ways),
        and the raw-backfill progress bar width applied through the CSSOM."""
        print("")
        print("--- /admin/settings controls ---")
        self.visit(page, rec, "/admin/settings")

        bars = page.locator("[data-progress-percent]")
        if bars.count():
            width = bars.first.evaluate("el => el.style.width")
            self.t.check("progress bar width applied via CSSOM", width.endswith("%"), width)
        else:
            print("  SKIP: no [data-progress-percent] bar rendered")

        form = page.locator('form[action="/admin/settings/motd"]')
        if not form.count():
            print("  SKIP: MOTD form not rendered for this admin")
            return
        page.fill('input[name="motd_message"]', "CSP smoke banner")
        page.fill('input[name="motd_expires_at"]', "2099-01-01T00:00")
        with page.expect_navigation(wait_until="domcontentloaded"):
            form.locator('button[type="submit"]').click()
        self.settle(page)
        banner = page.locator("#motd-banner")
        self.t.check("MOTD banner renders after saving", banner.is_visible())
        if banner.is_visible():
            page.click('#motd-banner button[aria-label="Dismiss banner"]')
            banner.wait_for(state="hidden", timeout=5_000)
            self.t.check("MOTD banner dismisses", not banner.is_visible())

        # data-confirm: cancel keeps the banner, accept clears it. The
        # dismiss mode is reset in a finally so a failure here cannot leak
        # into the later create/delete-user steps, which also confirm.
        clear = page.locator('form[action="/admin/settings/motd/clear"] button[type="submit"]')
        try:
            self.dialog_action = "dismiss"
            clear.click()
            page.wait_for_timeout(500)
            self.t.check(
                "data-confirm cancel keeps the banner",
                page.locator('form[action="/admin/settings/motd/clear"]').count() == 1,
            )
        finally:
            self.dialog_action = "accept"
        with page.expect_navigation(wait_until="domcontentloaded"):
            clear.click()
        self.settle(page)
        self.t.check(
            "data-confirm accept clears the banner",
            page.locator('form[action="/admin/settings/motd/clear"]').count() == 0,
        )
        self.audit(page, rec, "/admin/settings interactions")

    def check_submit_once(self, page: Page, rec: Recorder) -> None:
        self.visit(page, rec, "/admin/bnr-events")
        button = page.locator('button[data-submit-once][type="submit"]')
        if not self.t.check(
            "import-wiki submit-once button renders",
            button.count() == 1,
            str(button.count()),
        ):
            return

        pattern = "**/admin/bnr-events/import-wiki"
        intercepted_methods: list[str] = []

        def intercept(route) -> None:
            intercepted_methods.append(route.request.method)
            route.fulfill(
                status=303,
                headers={"Location": "/admin/bnr-events"},
                body="",
            )

        page.route(pattern, intercept)
        try:
            with page.expect_request(pattern):
                state = button.evaluate(
                    """button => {
                        button.click();
                        return {disabled: button.disabled, label: button.textContent.trim()};
                    }"""
                )
            page.wait_for_timeout(100)
        finally:
            page.unroute(pattern, intercept)

        self.t.check(
            "submit-once sends only the intercepted POST",
            intercepted_methods == ["POST"],
            str(intercepted_methods),
        )
        self.t.check(
            "submit-once disables and relabels the button",
            state == {"disabled": True, "label": "Importing..."},
            str(state),
        )
        self.audit(page, rec, "submit-once interaction")

    def check_metagame(self, page: Page, rec: Recorder) -> None:
        """/metagame/<format>: the Alpine `metagame` component (x-for, x-if,
        :style object, async window switch) and the Chart.js render."""
        print("")
        print("--- /metagame component ---")
        page.goto(self.base + "/metagame", wait_until="domcontentloaded")
        self.settle(page)
        links = page.evaluate(
            "Array.from(document.querySelectorAll('a[href^=\"/metagame/\"]'))"
            ".map(a => a.getAttribute('href'))"
        )
        links = [h for h in links if h and "/events/" not in h]
        if not links:
            self.t.check("metagame fixture rendered a format link", False, "none found")
            return
        self.visit(page, rec, links[0])
        root = page.locator('[x-data="metagame"]')
        self.t.check("metagame component root rendered", root.count() == 1)
        self.wait_until(
            page,
            "document.querySelectorAll("
            '\'[x-data="metagame"] tbody tr td[x-text="tier.deck_name"]\').length > 0',
            timeout=10_000,
        )
        names = page.locator('td[x-text="tier.deck_name"]').all_text_contents()
        self.t.check("tier rows rendered by x-for", bool(names) and all(names), str(names))
        total = page.locator("[x-text=\"totalResults + ' results'\"]").text_content() or ""
        self.t.check("total results text rendered", total.strip().endswith("results"), total)
        bar_width = page.locator(
            '[x-data="metagame"] .bg-accent.rounded-full.h-full'
        ).first.evaluate("el => el.style.width")
        self.t.check(
            ":style object sets the popularity bar width", bar_width.endswith("%"), bar_width
        )
        buttons = page.locator('[x-data="metagame"] button[x-text="w"]')
        self.t.check("window buttons rendered by x-for", buttons.count() == 4, str(buttons.count()))
        chart = page.evaluate(
            "(() => { const c = document.getElementById('trendsChart');"
            " return !!(c && window.Chart && Chart.getChart(c)); })()"
        )
        self.t.check("Chart.js rendered the trends chart", chart)
        # Switch the window: rows re-render from the JSON API without errors.
        buttons.nth(2).click()  # 90d
        self.wait_until(
            page,
            'document.querySelector(\'[x-data="metagame"] button.bg-accent[x-text="w"]\')'
            ".textContent.trim() === '90d'",
            timeout=10_000,
        )
        self.wait_until(
            page,
            "document.querySelectorAll('td[x-text=\"tier.deck_name\"]').length > 0",
            timeout=10_000,
        )
        self.t.check("window switch re-rendered the tier table", True)
        self.audit(page, rec, "/metagame interactions")

        # Event detail page: the per-row expand toggle.
        event_links = page.evaluate(
            "Array.from(document.querySelectorAll('a[href*=\"/events/\"]'))"
            ".map(a => a.getAttribute('href'))"
        )
        if event_links:
            self.visit(page, rec, event_links[0])
            row = page.locator('[x-data="{ expanded: false }"]').first
            detail = row.locator("[x-show='expanded']")
            self.t.check("event result starts collapsed", not detail.is_visible())
            row.locator("div.cursor-pointer").first.click()
            detail.wait_for(state="visible", timeout=5_000)
            self.t.check("event result expands on click", detail.is_visible())
            self.audit(page, rec, "/metagame event interactions")

    def check_scraper_events(self, page: Page, rec: Recorder) -> None:
        list_path = "/admin/scrapers/mtgtop8/events"
        self.visit(page, rec, list_path)
        links = page.locator('a[href^="/admin/scrapers/mtgtop8/events/"]')
        if not self.t.check(
            "scraper fixture rendered an event link",
            links.count() > 0,
            "none found",
        ):
            return
        detail_path = links.first.get_attribute("href")
        if self.t.check("scraper fixture event link has a target", bool(detail_path)):
            self.visit(page, rec, detail_path)

    def ensure_smoke_user(self, page: Page, rec: Recorder) -> None:
        self.dialog_action = "accept"
        self.delete_user(page, CANCELLED_USER_EMAIL, quiet=True)
        self.delete_smoke_user(page, quiet=True)
        page.goto(self.base + "/admin/users", wait_until="domcontentloaded")
        self.settle(page)
        form = page.locator('form[action^="/admin/users/create"]')

        form.locator('input[name="email"]').fill(CANCELLED_USER_EMAIL)
        form.locator('input[name="password"]').fill(SMOKE_USER_PASSWORD)
        form.locator('select[name="role"]').select_option("user")
        form.locator('input[name="must_change_password"]').uncheck()
        initial_url = page.url
        try:
            self.dialog_action = "dismiss"
            form.locator('button[type="submit"]').click()
            page.wait_for_timeout(500)
            self.settle(page)
            self.t.check(
                "create-user cancel stays on the same page",
                page.url == initial_url,
                page.url,
            )
            self.t.check(
                "create-user cancel does not create a user",
                self.user_row(page, CANCELLED_USER_EMAIL) is None,
            )
            self.audit(page, rec, "cancel create smoke user")
        finally:
            self.dialog_action = "accept"

        if self.user_row(page, CANCELLED_USER_EMAIL) is not None:
            self.delete_user(page, CANCELLED_USER_EMAIL, quiet=True)

        form.locator('input[name="email"]').fill(SMOKE_USER_EMAIL)
        form.locator('input[name="password"]').fill(SMOKE_USER_PASSWORD)
        form.locator('select[name="role"]').select_option("user")
        form.locator('input[name="must_change_password"]').uncheck()
        with page.expect_navigation(wait_until="domcontentloaded"):
            form.locator('button[type="submit"]').click()  # data-confirm accepted
        self.settle(page)
        self.t.check(
            "create-user button (data-confirm) created the smoke user",
            self.smoke_user_row(page) is not None,
        )
        self.audit(page, rec, "create smoke user")

    def user_row(self, page: Page, email: str):
        rows = page.locator("tr[id^='user-']")
        for i in range(rows.count()):
            row = rows.nth(i)
            if email in (row.text_content() or ""):
                return row
        return None

    def smoke_user_row(self, page: Page):
        return self.user_row(page, SMOKE_USER_EMAIL)

    def delete_user(self, page: Page, email: str, quiet: bool = False) -> None:
        self.dialog_action = "accept"
        page.goto(self.base + "/admin/users", wait_until="domcontentloaded")
        self.settle(page)
        row = self.user_row(page, email)
        if row is None:
            if not quiet:
                print(f"  SKIP: {email} not present")
            return
        with page.expect_navigation(wait_until="domcontentloaded"):
            row.locator('form[action*="/delete"] button[type="submit"]').click()
        self.settle(page)
        if not quiet:
            self.t.check(f"{email} deleted", self.user_row(page, email) is None)

    def delete_smoke_user(self, page: Page, quiet: bool = False) -> None:
        self.delete_user(page, SMOKE_USER_EMAIL, quiet)

    def check_dashboard_row_navigation(self, page: Page, rec: Recorder) -> None:
        for label, key in (("mouse", None), ("Enter", "Enter"), ("Space", "Space")):
            self.visit(page, rec, "/dashboard")
            row = page.locator('tr[data-format][data-href*="format="]').first
            if not self.t.check(
                f"data-href {label} row renders",
                row.count() == 1,
            ):
                continue
            target = row.get_attribute("data-href")
            if not self.t.check(
                f"data-href {label} row has a format target",
                bool(target) and "format=" in target,
                str(target),
            ):
                continue
            if key is None:
                row.click()
            else:
                row.press(key)
            self.settle(page)
            final = re.sub(r"^https?://[^/]+", "", page.url)
            self.t.check(
                f"data-href {label} navigates to its format target",
                final == target,
                final,
            )
            self.audit(page, rec, f"data-href {label} interaction")

    # -------------------------------------------------------- fixture user
    def run_fixture_user(self, browser: Browser) -> None:
        print("")
        print("--- fixture user session ---")
        ctx, page, rec = self.new_page(browser)
        if not self.login(
            page,
            rec,
            FIXTURE_USER_EMAIL,
            FIXTURE_USER_PASSWORD,
            "/dashboard",
        ):
            ctx.close()
            return

        self.check_dashboard_row_navigation(page, rec)
        self.visit(page, rec, "/matches")
        links = page.locator('a[href^="/matches/"]')
        if not self.t.check(
            "fixture match renders in match history",
            links.count() > 0,
            "none found",
        ):
            ctx.close()
            return
        match_path = links.first.get_attribute("href")
        if not self.t.check("fixture match links to its detail page", bool(match_path)):
            ctx.close()
            return

        self.visit(page, rec, match_path)
        format_select = page.locator("select[data-autosubmit]")
        if not self.t.check(
            "match detail renders the format selector",
            format_select.count() == 1,
            str(format_select.count()),
        ):
            ctx.close()
            return
        with page.expect_navigation(wait_until="domcontentloaded") as navigation:
            format_select.select_option("Pauper")
        self.settle(page)
        response = navigation.value
        self.t.check(
            "data-autosubmit returns the match detail page",
            response is not None and response.status == 200,
            f"got {response.status if response else 0}",
        )
        selected_format = page.input_value("select[data-autosubmit]")
        self.t.check(
            "data-autosubmit persists the selected format",
            selected_format == "Pauper",
            selected_format,
        )

        show_turns = page.locator('button[hx-get$="/turns"]')
        if not self.t.check(
            "match detail renders the Show turns control",
            show_turns.count() > 0,
            "none found",
        ):
            ctx.close()
            return
        show_turns.first.click()
        details = page.locator("#turns-1 button[data-toggle-target]")
        details.first.wait_for(state="visible", timeout=10_000)
        self.t.check("Show turns swaps in populated turn rows", details.count() == 2)

        detail_button = details.first
        target_id = detail_button.get_attribute("data-toggle-target")
        if not self.t.check("turn Details control has a target", bool(target_id)):
            ctx.close()
            return
        detail_row = page.locator(f"#{target_id}")
        self.t.check("turn details start hidden", not detail_row.is_visible())
        detail_button.click()
        detail_row.wait_for(state="visible", timeout=5_000)
        self.t.check("turn details reveal", detail_row.is_visible())
        detail_button.click()
        detail_row.wait_for(state="hidden", timeout=5_000)
        self.t.check("turn details re-hide", not detail_row.is_visible())
        self.audit(page, rec, "fixture match interactions")
        ctx.close()

    # --------------------------------------------------------------- user
    def run_user(self, browser: Browser) -> None:
        print("")
        print("--- user session ---")
        ctx, page, rec = self.new_page(browser)
        if not self.login(page, rec, SMOKE_USER_EMAIL, SMOKE_USER_PASSWORD, "/dashboard"):
            ctx.close()
            return
        for path in USER_PAGES:
            self.visit(page, rec, path)

        print("")
        print("--- user controls ---")
        # Dashboard: the date preset select navigates with date_from/date_to.
        self.visit(page, rec, "/dashboard")
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.select_option('[x-data="dateRangeFilter"] select', "7")
        self.settle(page)
        self.t.check("date preset navigates with a date range", "date_from=" in page.url, page.url)
        date_from = page.input_value('[x-data="dateRangeFilter"] input[x-model="dateFrom"]')
        self.t.check("date inputs bound from data attributes", bool(date_from), date_from)
        preset = page.input_value('[x-data="dateRangeFilter"] select')
        self.t.check("preset shows custom after a date range", preset == "custom", preset)
        self.audit(page, rec, "/dashboard interactions")

        # Profile: the reparse modal opens, closes on Escape and on Cancel.
        self.visit(page, rec, "/profile")
        modal = page.locator('[role="dialog"]')
        self.t.check("reparse modal starts hidden", not modal.is_visible())
        page.click("text=Reparse my matches")
        modal.wait_for(state="visible", timeout=5_000)
        self.t.check("reparse modal opens", modal.is_visible())
        page.keyboard.press("Escape")
        modal.wait_for(state="hidden", timeout=5_000)
        self.t.check("reparse modal closes on Escape", not modal.is_visible())
        page.click("text=Reparse my matches")
        modal.wait_for(state="visible", timeout=5_000)
        modal.locator("text=Cancel").click()
        modal.wait_for(state="hidden", timeout=5_000)
        self.t.check("reparse modal closes on Cancel", not modal.is_visible())
        self.audit(page, rec, "/profile interactions")

        # Agents: generate a registration code, copy it.
        self.visit(page, rec, "/profile/agents")
        with page.expect_navigation(wait_until="domcontentloaded"):
            page.click("text=Generate Registration Code")
        self.settle(page)
        code = page.locator("#registration-code-block")
        self.t.check("registration code rendered", code.count() == 1 and bool(code.text_content()))
        copy_btn = page.locator("[data-copy-target]")
        if copy_btn.count():
            copy_btn.click()
            self.wait_until(
                page,
                "document.querySelector('[data-copy-target]').textContent.trim() === 'Copied'",
                timeout=5_000,
            )
            self.t.check("copy button reports Copied", True)
        self.audit(page, rec, "/profile/agents interactions")

        # Edit profile: detect usernames calls the JSON endpoint.
        self.visit(page, rec, "/profile/edit")
        page.click("#detect-usernames-btn")
        self.wait_until(
            page,
            "(() => { const t = document.getElementById('detect-status').textContent;"
            " return t === 'No usernames found in match data.'"
            " || t === 'Could not detect usernames.' || t.startsWith('Found '); })()",
            timeout=15_000,
        )
        status = page.text_content("#detect-status") or ""
        self.t.check(
            "detect usernames reports a result",
            status.startswith("Found ") or status == "No usernames found in match data.",
            status,
        )
        self.audit(page, rec, "/profile/edit interactions")
        ctx.close()

    # ---------------------------------------------------------------- run
    def section(self, label: str, fn, *args) -> None:
        """Run one part of the suite; an exception is a FAIL for that part,
        not the end of the run, so the summary still lists everything else."""
        try:
            fn(*args)
        except Exception as exc:  # noqa: BLE001 - any failure is a FAIL line
            self.t.check(f"{label} completed", False, f"{type(exc).__name__}: {exc}"[:400])

    def run(self) -> int:
        print(f"=== Deep Analysis browser CSP smoke: {self.base} ===")
        with sync_playwright() as pw:
            browser = pw.chromium.launch()
            try:
                self.section("public pages", self.run_public, browser)
                self.section("admin session", self.run_admin, browser)
                if getattr(self, "admin_page", None) is not None:
                    self.section("fixture user session", self.run_fixture_user, browser)
                    self.section("user session", self.run_user, browser)
                    print("")
                    print("--- cleanup ---")
                    self.section("cleanup", self.delete_smoke_user, self.admin_page)
                    self.audit(self.admin_page, self.admin_rec, "cleanup")
                    self.admin_ctx.close()
            finally:
                browser.close()
        print("")
        print(f"=== Browser CSP smoke result: {self.t.passed} PASS, {self.t.failed} FAIL ===")
        return 1 if self.t.failed else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("base_url", nargs="?", default="http://localhost:8080")
    args = ap.parse_args()
    for var in ("DEEP_ANALYSIS_BOOTSTRAP_ADMIN_EMAIL", "DEEP_ANALYSIS_BOOTSTRAP_ADMIN_PASSWORD"):
        if not os.environ.get(var):
            print(f"FAIL: {var} must be set", file=sys.stderr)
            return 1
    return Smoke(args.base_url).run()


if __name__ == "__main__":
    sys.exit(main())
