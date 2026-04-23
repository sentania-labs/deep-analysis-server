"""Argon2id password hashing tests."""

from __future__ import annotations

import pytest
from argon2 import PasswordHasher
from auth_service.passwords import hash_password, needs_rehash, verify_password


def test_hash_roundtrip() -> None:
    hashed = hash_password("correct horse battery staple")
    assert hashed.startswith("$argon2id$")
    assert verify_password("correct horse battery staple", hashed) is True


def test_verify_mismatch_returns_false() -> None:
    hashed = hash_password("hunter2")
    assert verify_password("hunter3", hashed) is False


def test_needs_rehash_on_weaker_params() -> None:
    weak = PasswordHasher(time_cost=1, memory_cost=8, parallelism=1, hash_len=16)
    weak_hash = weak.hash("hunter2")
    assert needs_rehash(weak_hash) is True


def test_needs_rehash_on_same_params_is_false() -> None:
    hashed = hash_password("hunter2")
    assert needs_rehash(hashed) is False


def test_malformed_hash_raises() -> None:
    with pytest.raises(Exception):  # noqa: B017 — argon2 raises InvalidHashError
        verify_password("anything", "not-a-real-hash")
