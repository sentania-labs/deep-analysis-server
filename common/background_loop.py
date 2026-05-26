"""Generic background-task loop for periodic schedulers.

Eliminates the repeated start/stop/loop boilerplate across the
analytics service's Scryfall, MTGO, and mtgtop8 schedulers.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Any

_log = logging.getLogger(__name__)


class BackgroundLoop:
    """Runs an async callback on a fixed interval inside a managed task.

    Parameters
    ----------
    name:
        Human-readable identifier used for task naming and log messages.
    callback:
        An async callable invoked once per iteration.  Receives no
        arguments — the caller should bind any state via a closure or
        ``functools.partial``.
    get_interval:
        An async callable returning the sleep duration (in seconds) for
        the **current** iteration.  Called *after* each callback
        invocation so config changes (e.g. scraper interval tweaks)
        take effect without a restart.
    """

    def __init__(
        self,
        name: str,
        callback: Callable[[], Awaitable[Any]],
        get_interval: Callable[[], Awaitable[float]],
    ) -> None:
        self.name = name
        self._callback = callback
        self._get_interval = get_interval
        self._task: asyncio.Task[None] | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Create the background task (idempotent)."""
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._loop(), name=self.name)
        _log.info("%s task started", self.name)

    async def stop(self) -> None:
        """Cancel the background task and await its completion."""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        except Exception:  # noqa: BLE001 — surface but don't crash shutdown
            _log.exception("%s raised on shutdown", self.name)
        self._task = None

    def reset(self) -> None:
        """Test hook — drop the task reference without cancellation."""
        self._task = None

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _loop(self) -> None:
        while True:
            try:
                await self._callback()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 — never let a single failure kill the loop
                _log.exception("%s iteration failed", self.name)
            interval = await self._get_interval()
            await asyncio.sleep(interval)
