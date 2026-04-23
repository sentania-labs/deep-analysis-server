"""Generate an RS256 keypair for JWT signing.

Usage
-----

    uv run python -m auth_service.keygen --out ./secrets/

Writes ``jwt_private.pem`` and ``jwt_public.pem`` (mode 0600 / 0644) to
the target directory. Operators run this once at deploy time and mount
the files into the relevant containers; see ``docs/admin-bootstrap.md``.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_keypair(out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = out_dir / "jwt_private.pem"
    public_path = out_dir / "jwt_public.pem"

    private_path.write_bytes(private_pem)
    os.chmod(private_path, 0o600)
    public_path.write_bytes(public_pem)
    os.chmod(public_path, 0o644)

    return private_path, public_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate JWT RS256 keypair.")
    parser.add_argument("--out", required=True, type=Path, help="Output directory")
    args = parser.parse_args()

    priv, pub = generate_keypair(args.out)
    print(f"private: {priv}")
    print(f"public:  {pub}")


if __name__ == "__main__":
    main()
