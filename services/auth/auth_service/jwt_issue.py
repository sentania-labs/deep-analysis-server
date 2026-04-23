"""RS256 JWT issuance + refresh-token helpers."""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt

from auth_service.settings import get_settings


class JWTIssuer:
    def __init__(
        self,
        private_key_path: Path,
        issuer: str,
        audience: str,
        access_ttl_seconds: int,
    ) -> None:
        self._private_key = Path(private_key_path).read_text()
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = access_ttl_seconds

    def issue_access_token(self, user_id: int, role: str, session_id: uuid.UUID) -> str:
        now = datetime.now(UTC)
        claims = {
            "sub": str(user_id),
            "role": role,
            "sid": str(session_id),
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self._access_ttl)).timestamp()),
            "iss": self._issuer,
            "aud": self._audience,
        }
        return jwt.encode(claims, self._private_key, algorithm="RS256")


_issuer: JWTIssuer | None = None


def get_issuer() -> JWTIssuer:
    global _issuer
    if _issuer is None:
        s = get_settings()
        _issuer = JWTIssuer(
            private_key_path=s.jwt_private_key_path,
            issuer=s.jwt_issuer,
            audience=s.jwt_audience,
            access_ttl_seconds=s.access_token_ttl_seconds,
        )
    return _issuer


def issue_access_token(user_id: int, role: str, session_id: uuid.UUID) -> str:
    return get_issuer().issue_access_token(user_id, role, session_id)


def issue_refresh_token() -> str:
    return secrets.token_urlsafe(32)


def hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
