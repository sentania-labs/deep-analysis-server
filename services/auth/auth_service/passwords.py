"""Argon2id password hashing.

Parameters follow OWASP Password Storage Cheat Sheet guidance for
Argon2id (2023 revision): m=64 MiB, t=3, p=4, output length 32 bytes.
"""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

_TIME_COST = 3
_MEMORY_COST = 65_536
_PARALLELISM = 4
_HASH_LEN = 32

_hasher = PasswordHasher(
    time_cost=_TIME_COST,
    memory_cost=_MEMORY_COST,
    parallelism=_PARALLELISM,
    hash_len=_HASH_LEN,
)


def hash_password(plaintext: str) -> str:
    return _hasher.hash(plaintext)


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        return _hasher.verify(hashed, plaintext)
    except VerifyMismatchError:
        return False


def needs_rehash(hashed: str) -> bool:
    try:
        return _hasher.check_needs_rehash(hashed)
    except InvalidHashError:
        return True
