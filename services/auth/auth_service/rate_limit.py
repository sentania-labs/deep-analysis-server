"""In-memory IP-based sliding-window rate limiter.

No external dependencies — uses a dict of timestamps, cleaned up
periodically on each check call to prevent unbounded growth.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request, status


@dataclass(frozen=True)
class RateLimitRule:
    """Defines a rate limit: ``max_requests`` within ``window_seconds``."""

    max_requests: int
    window_seconds: int


@dataclass
class RateLimiter:
    """Sliding-window counter keyed by client IP.

    Thread-safe via a ``threading.Lock``; the async FastAPI path is
    single-threaded per worker so the lock is contention-free in
    production but makes the class safe for sync test helpers too.

    ``_store`` maps ``(bucket, ip)`` → list of request timestamps.
    ``_last_cleanup`` tracks the last time we purged expired entries
    so we don't scan on every call.
    """

    _store: dict[tuple[str, str], list[float]] = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _last_cleanup: float = field(default_factory=time.monotonic)

    # Purge expired entries at most once every 60 s.
    _CLEANUP_INTERVAL: float = 60.0

    def _cleanup(self, now: float, rules: dict[str, RateLimitRule]) -> None:
        """Remove entries older than each bucket's own window."""
        dead_keys: list[tuple[str, str]] = []
        for key, timestamps in self._store.items():
            bucket = key[0]
            rule = rules.get(bucket)
            cutoff = now - (rule.window_seconds if rule else 3600) - 1
            timestamps[:] = [t for t in timestamps if t > cutoff]
            if not timestamps:
                dead_keys.append(key)
        for key in dead_keys:
            del self._store[key]
        self._last_cleanup = now

    def check(
        self,
        bucket: str,
        ip: str,
        rule: RateLimitRule,
        all_rules: dict[str, RateLimitRule] | None = None,
    ) -> None:
        """Record a request and raise ``HTTPException(429)`` if over limit.

        ``bucket`` is a string identifying the endpoint (e.g. ``"login"``).
        ``all_rules`` is the full rule map, passed for cleanup; if omitted
        cleanup uses only the current rule.
        """
        now = time.monotonic()
        key = (bucket, ip)

        with self._lock:
            if now - self._last_cleanup > self._CLEANUP_INTERVAL:
                self._cleanup(now, all_rules or RULES)

            timestamps = self._store.setdefault(key, [])
            cutoff = now - rule.window_seconds
            timestamps[:] = [t for t in timestamps if t > cutoff]

            if len(timestamps) >= rule.max_requests:
                # Oldest surviving timestamp determines when the window
                # opens up again.
                oldest = min(timestamps)
                retry_after = int(oldest + rule.window_seconds - now) + 1
                if retry_after < 1:
                    retry_after = 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail={
                        "detail": "rate_limit_exceeded",
                        "retry_after_seconds": retry_after,
                    },
                )

            timestamps.append(now)

    def reset(self) -> None:
        """Clear all state — useful in tests."""
        with self._lock:
            self._store.clear()


# ---------------------------------------------------------------------------
# Singleton + rules
# ---------------------------------------------------------------------------

_limiter = RateLimiter()

RULES: dict[str, RateLimitRule] = {
    "login": RateLimitRule(max_requests=10, window_seconds=60),
    "register": RateLimitRule(max_requests=3, window_seconds=3600),
    "agent_register_with_credentials": RateLimitRule(max_requests=5, window_seconds=60),
}


def reset_rate_limiter() -> None:
    """Test hook: clear accumulated state between tests."""
    _limiter.reset()


def _get_client_ip(request: Request) -> str:
    """Extract client IP from X-Forwarded-For (Caddy) or fall back to peer."""
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    if request.client is not None:
        return request.client.host
    return "unknown"


def _make_dependency(bucket: str) -> Any:
    """Build a FastAPI dependency that enforces the named rate limit."""
    rule = RULES[bucket]

    async def _check_rate_limit(request: Request) -> None:
        ip = _get_client_ip(request)
        _limiter.check(bucket, ip, rule, all_rules=RULES)

    return _check_rate_limit


# Pre-built FastAPI dependencies — add via ``Depends(...)`` on endpoints.
check_login_rate = _make_dependency("login")
check_register_rate = _make_dependency("register")
check_agent_register_creds_rate = _make_dependency("agent_register_with_credentials")
