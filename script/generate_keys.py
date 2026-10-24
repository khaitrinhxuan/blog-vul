#!/usr/bin/env python3
"""Generate the local RSA key pair used for the JWT_Key_Confusion path.

The key pair used to be committed (`blogapp/key/priv.pem`, `blogapp/key/pub.key`),
which handed the JWT signing key to every holder of the repository and of images
built from it. Keys are now generated per deployment, outside version control:

    python3 script/generate_keys.py            # create if missing (idempotent)
    python3 script/generate_keys.py --force    # rotate (invalidates old tokens)

Paths come from PRIVATEKEY / PUBLICKEY (see .env.example). Existing keys are left
untouched unless --force is given, so a restart never invalidates live sessions.
"""

from __future__ import annotations

import argparse
import os
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_PRIVATE = "blogapp/key/priv.pem"
DEFAULT_PUBLIC = "blogapp/key/pub.key"


def _configured(name: str, default: str) -> str:
    """Read a path from the environment, tolerating a python-decouple .env file."""
    value = os.environ.get(name)
    if value:
        return value
    env_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if os.path.exists(env_path):
        with open(env_path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if line.startswith(f"{name}="):
                    return line.split("=", 1)[1].strip() or default
    return default


def _write_private(path: str, payload: bytes) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    # Create with restrictive permissions rather than relaxing them afterwards.
    handle = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(handle, "wb") as stream:
        stream.write(payload)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="overwrite existing keys")
    parser.add_argument("--key-size", type=int, default=2048)
    args = parser.parse_args()

    private_path = _configured("PRIVATEKEY", DEFAULT_PRIVATE)
    public_path = _configured("PUBLICKEY", DEFAULT_PUBLIC)

    if not args.force and (os.path.exists(private_path) or os.path.exists(public_path)):
        print(f"Keys already present ({private_path}, {public_path}); leaving them untouched.")
        return 0

    key = rsa.generate_private_key(public_exponent=65537, key_size=args.key_size)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    _write_private(private_path, private_pem)
    _write_private(public_path, public_pem)
    os.chmod(public_path, 0o644)

    # Paths only -- never the key material.
    print(f"Generated RSA-{args.key_size} key pair: {private_path} (0600), {public_path} (0644)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
