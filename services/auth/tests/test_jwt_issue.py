"""JWT issuance tests."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

import jwt
import pytest
from auth_service.jwt_issue import (
    JWTIssuer,
    hash_refresh_token,
    issue_access_token,
    issue_refresh_token,
)


def _pub() -> str:
    return open(os.environ["DA_JWT_PUBLIC_KEY_PATH"]).read()


def test_access_token_verifies_and_claims_roundtrip() -> None:
    sid = uuid.uuid4()
    token = issue_access_token(42, "admin", sid)
    claims = jwt.decode(
        token,
        _pub(),
        algorithms=["RS256"],
        issuer="deep-analysis-auth",
        audience="deep-analysis",
    )
    assert claims["sub"] == "42"
    assert claims["role"] == "admin"
    assert claims["sid"] == str(sid)
    assert claims["iss"] == "deep-analysis-auth"
    assert claims["aud"] == "deep-analysis"
    assert "iat" in claims and "exp" in claims
    assert claims["exp"] > claims["iat"]


def test_expired_access_token_rejected() -> None:
    # Issuer with a negative TTL produces immediately-expired tokens.
    iss = JWTIssuer(
        private_key_path=Path(os.environ["DA_JWT_PRIVATE_KEY_PATH"]),
        issuer="deep-analysis-auth",
        audience="deep-analysis",
        access_ttl_seconds=-60,
    )
    token = iss.issue_access_token(1, "user", uuid.uuid4())
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(
            token,
            _pub(),
            algorithms=["RS256"],
            issuer="deep-analysis-auth",
            audience="deep-analysis",
        )


def test_refresh_token_is_opaque_not_jwt() -> None:
    token = issue_refresh_token()
    # url-safe base64 of 32 bytes = 43 chars, no dots.
    assert "." not in token
    assert len(token) >= 32
    # Sanity: not decodable as a JWT.
    with pytest.raises(jwt.DecodeError):
        jwt.get_unverified_header(token)


def test_refresh_token_hash_is_sha256_hex() -> None:
    h = hash_refresh_token("some-token")
    assert len(h) == 64
    int(h, 16)  # raises if not hex


def test_access_token_iat_is_current() -> None:
    token = issue_access_token(1, "user", uuid.uuid4())
    claims = jwt.decode(
        token,
        _pub(),
        algorithms=["RS256"],
        issuer="deep-analysis-auth",
        audience="deep-analysis",
    )
    now = datetime.now(UTC)
    iat = datetime.fromtimestamp(claims["iat"], tz=UTC)
    assert abs(now - iat) < timedelta(seconds=10)
