"""Public-key-only JWT verification (RS256)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import jwt


class InvalidTokenError(Exception):
    """Raised when a token fails verification."""


class JWTVerifier:
    def __init__(self, public_key_path: Path, issuer: str, audience: str) -> None:
        self._public_key = Path(public_key_path).read_text()
        self._issuer = issuer
        self._audience = audience

    def verify(self, token: str) -> dict[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=["RS256"],
                issuer=self._issuer,
                audience=self._audience,
            )
        except jwt.PyJWTError as exc:
            raise InvalidTokenError(str(exc)) from exc
        # TODO(W2): claims model — e.g., admin role flag
        return claims
