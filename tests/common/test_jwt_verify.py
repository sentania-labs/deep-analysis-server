"""Tests for common.jwt_verify."""

from __future__ import annotations

import datetime as dt
from pathlib import Path

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from common.jwt_verify import InvalidTokenError, JWTVerifier

ISSUER = "test-iss"
AUDIENCE = "test-aud"


def _keypair(tmp_path: Path) -> tuple[str, Path]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    pub_path = tmp_path / "pub.pem"
    pub_path.write_bytes(public_pem)
    return private_pem, pub_path


def _make_token(private_pem: str, exp_delta: int = 300) -> str:
    now = dt.datetime.now(tz=dt.UTC)
    return jwt.encode(
        {
            "sub": "user-1",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "iat": now,
            "exp": now + dt.timedelta(seconds=exp_delta),
        },
        private_pem,
        algorithm="RS256",
    )


def test_verify_valid_token(tmp_path: Path) -> None:
    private_pem, pub_path = _keypair(tmp_path)
    verifier = JWTVerifier(pub_path, ISSUER, AUDIENCE)
    claims = verifier.verify(_make_token(private_pem))
    assert claims["sub"] == "user-1"
    assert claims["iss"] == ISSUER
    assert claims["aud"] == AUDIENCE


def test_verify_tampered_signature(tmp_path: Path) -> None:
    private_pem, pub_path = _keypair(tmp_path)
    verifier = JWTVerifier(pub_path, ISSUER, AUDIENCE)
    token = _make_token(private_pem)
    # flip last char of signature
    tampered = token[:-1] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(InvalidTokenError):
        verifier.verify(tampered)


def test_verify_expired_token(tmp_path: Path) -> None:
    private_pem, pub_path = _keypair(tmp_path)
    verifier = JWTVerifier(pub_path, ISSUER, AUDIENCE)
    expired = _make_token(private_pem, exp_delta=-60)
    with pytest.raises(InvalidTokenError):
        verifier.verify(expired)
