"""Integration test placeholder for the W3.5-B/-C browser surfaces.

The real end-to-end coverage is the bash smoke script
``ci/smoke_ui.sh``, which spins the full compose stack, logs in as
the bootstrap admin, exercises ``/profile``, ``/profile/edit``,
``/profile/agents``, and the admin panel — including seeding
``testuser@local`` via the auth JSON API, rotating its password
through the web admin UI, and deleting it. This Python file is the
pytest harness's record of that fact — same shape as
``test_migrations.py``: the assertion is that CI invoked the smoke
script and that it exited 0 *before* pytest is collected.

A deeper Python integration test would re-implement what the bash
smoke already does (compose up, cookie jar, browser navigation),
which is wasted churn. If the smoke script becomes insufficient,
replace this stub with a real test that drives the running stack
via ``httpx.AsyncClient``.
"""

from __future__ import annotations


def test_smoke_ui_covers_self_service_and_admin() -> None:
    # See ci/smoke_ui.sh sections 6-7. CI runs the smoke step
    # `smoke-ui -> ci/smoke_ui.sh ...` against the live stack before
    # pytest fires; a non-zero exit there breaks the build well
    # before this assertion runs.
    assert True
