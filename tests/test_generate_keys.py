#!/usr/bin/env python3
"""Verify that removing the committed key pair did not break key provisioning.

`script/generate_keys.py` replaces `blogapp/key/priv.pem` + `blogapp/key/pub.key`
(now untracked) and must produce a usable RS256 pair at the configured paths:

  1. it creates the pair, private key mode 0600;
  2. the paths come from PRIVATEKEY / PUBLICKEY;
  3. re-running is idempotent, so a restart never invalidates live sessions;
  4. a token signed with the generated private key verifies with the generated
     public key -- the exact load/sign relationship `blogapp/views/login.py:24-30`
     and the trust check at `blogapp/views/setting.py:47` rely on.

Needs only `cryptography` and `PyJWT`. Run: python3 tests/test_generate_keys.py
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile

import jwt
from cryptography.hazmat.primitives import serialization

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(REPO_ROOT, "script", "generate_keys.py")


def _run(env: dict[str, str], *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, SCRIPT, *args], capture_output=True, text=True, env=env, check=False
    )


def test_generates_usable_key_pair_and_is_idempotent() -> None:
    with tempfile.TemporaryDirectory() as workdir:
        private_path = os.path.join(workdir, "key", "priv.pem")
        public_path = os.path.join(workdir, "key", "pub.key")
        env = dict(os.environ, PRIVATEKEY=private_path, PUBLICKEY=public_path)

        first = _run(env)
        assert first.returncode == 0, first.stderr
        assert os.path.exists(private_path) and os.path.exists(public_path)

        # 1. the private key must not be world/group readable
        mode = stat.S_IMODE(os.stat(private_path).st_mode)
        assert mode == 0o600, f"private key mode is {oct(mode)}, expected 0o600"

        # 2. the pair really is an RSA key pair
        with open(private_path, "rb") as handle:
            private_key = serialization.load_pem_private_key(handle.read(), password=None)
        with open(public_path, "rb") as handle:
            public_key = serialization.load_pem_public_key(handle.read())
        assert private_key.public_key().public_numbers() == public_key.public_numbers()

        # 3. the login -> setting RS256 relationship still holds
        token = jwt.encode({"username": "admin", "admin": True}, private_key, algorithm="RS256")
        claims = jwt.decode(token, public_key, algorithms=["RS256"])
        assert claims["admin"] is True

        # 4. a restart must not rotate the key out from under live sessions
        before = open(private_path, "rb").read()
        second = _run(env)
        assert second.returncode == 0, second.stderr
        assert open(private_path, "rb").read() == before, "second run rotated the key"

        # 5. --force rotates on demand
        forced = _run(env, "--force")
        assert forced.returncode == 0, forced.stderr
        assert open(private_path, "rb").read() != before, "--force did not rotate the key"


def main() -> int:
    try:
        test_generates_usable_key_pair_and_is_idempotent()
    except AssertionError as exc:
        print(f"FAIL: {exc}")
        return 1
    print("PASS: generate_keys.py creates a mode-0600 usable RS256 pair, idempotently")
    return 0


if __name__ == "__main__":
    sys.exit(main())
