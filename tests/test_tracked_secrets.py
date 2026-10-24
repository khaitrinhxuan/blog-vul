#!/usr/bin/env python3
"""Regression gate for Code Audit finding 58fa58ce-c849-498e-9dfd-dcdf6080d33c.

Finding: `.env` (Django SECRET_KEY, Postgres credentials, RSA key paths) and the
RSA private key `blogapp/key/priv.pem` are tracked in version control, so any
holder of the repository -- or of an image built from it (`dockerfile:5 COPY . .`)
-- holds the Django signing key, the database password and the JWT signing key.

The gate reads the git index only: no database, no Django settings, no network.
It fails while secret material is reachable from the tracked tree and passes
once that material is untracked, ignored and kept out of the image build context.

Run:  python3 tests/test_tracked_secrets.py     (exit 0 = pass, 1 = fail)
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- rules (byte patterns, so binary blobs are safe to scan) -----------------

# Exact repo-relative paths that must never be tracked.
FORBIDDEN_PATHS = {
    ".env",
    "blogapp/key/priv.pem",
    "blogapp/key/pub.key",
}

# Tracked paths matching any of these patterns are violations.
FORBIDDEN_PATH_PATTERNS = [
    (re.compile(rb"(?:^|/)\.env$"), "environment file"),
    (re.compile(rb"\.pem$"), "PEM key material"),
    (re.compile(rb"(?:^|/)(?:id_rsa|id_ed25519)$"), "SSH private key"),
]

# Assemble the private-key marker by concatenation so this file does not contain
# the literal it forbids (otherwise the gate would flag its own source).
_KEY_MARKER = ("-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |PGP )?" + "PRIVATE KEY-----")

FORBIDDEN_CONTENT_PATTERNS = [
    (re.compile(_KEY_MARKER.encode()), "embedded private key"),
]

# `SECRET_KEY = <literal>` / `SECRET_KEY: <literal>`. Bindings that read the value
# from the environment (config("SECRET_KEY"), os.environ[...], getenv(...)) are the
# intended sink and must NOT match. `os.environ` is spelled in pieces for the same
# self-match reason: this file names the indirection in its own control test.
SECRET_ASSIGNMENT = re.compile(
    rb"^[ \t]*SECRET_KEY[ \t]*[=:][ \t]*(?P<value>.+?)[ \t]*$", re.MULTILINE
)
INDIRECTION = re.compile(
    rb"^(?:config\(|os[.]environ|os[.]getenv|getenv\(|env\(|django[.]core[.])"
)
PLACEHOLDER = re.compile(rb"^(?:<[^>]*>|\*\*\*+|x{3,}|change[-_]?me|your[-_].*)$", re.I)

# Committed templates: a secret *name* is documented, the value must stay empty.
TEMPLATE_PATHS = {".env.example"}

# Image build context must not carry the secret material either.
DOCKERIGNORE_PATH = ".dockerignore"
DOCKERIGNORE_REQUIRED = {".env", "*.pem"}

GITIGNORE_REQUIRED = (".env", "*.pem")

EXIT_PASS, EXIT_VIOLATIONS, EXIT_CANNOT_VERIFY = 0, 1, 2


class GitUnavailable(RuntimeError):
    """No git metadata at this path, so the tracked file list cannot be read."""


def _git_raw(*args: str, stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "-C", REPO_ROOT, *args],
        input=stdin,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            "git %s failed (rc=%s): %s"
            % (" ".join(args), proc.returncode, proc.stderr.decode("utf-8", "replace").strip())
        )
    return proc.stdout


def index_snapshot() -> dict[str, bytes]:
    """{repo-relative path: blob bytes} for every tracked path, in one git call."""
    listing = _git_raw("ls-files", "-s", "-z")
    sha_to_path: dict[bytes, str] = {}
    shas: list[bytes] = []
    for record in listing.split(b"\0"):
        if not record:
            continue
        meta, _, path = record.partition(b"\t")
        parts = meta.split()
        if len(parts) < 2:
            continue
        sha = parts[1]
        sha_to_path[sha] = path.decode("utf-8", "surrogateescape")
        shas.append(sha)

    if not shas:
        return {}

    stream = _git_raw("cat-file", "--batch", stdin=b"\n".join(shas) + b"\n")
    snapshot: dict[str, bytes] = {}
    pos = 0
    while pos < len(stream):
        newline = stream.find(b"\n", pos)
        if newline < 0:
            break
        header = stream[pos:newline].split()
        pos = newline + 1
        # "<sha> blob <size>"; "<sha> missing" has no payload
        if len(header) != 3 or header[1] != b"blob":
            continue
        sha, size = header[0], int(header[2])
        snapshot[sha_to_path[sha]] = stream[pos:pos + size]
        pos += size + 1
    return snapshot


def inspect(
    snapshot: dict[str, bytes],
    gitignore: bytes | None,
    dockerignore: bytes | None,
) -> list[str]:
    """Return human-readable violations for a {path: blob} snapshot."""
    violations: list[str] = []

    for path in sorted(snapshot):
        if path in FORBIDDEN_PATHS:
            violations.append(f"tracked secret file: {path}")

        encoded = path.encode("utf-8", "surrogateescape")
        for pattern, label in FORBIDDEN_PATH_PATTERNS:
            if pattern.search(encoded):
                violations.append(f"tracked {label}: {path}")
                break

        content = snapshot[path]
        for pattern, label in FORBIDDEN_CONTENT_PATTERNS:
            if pattern.search(content):
                violations.append(f"{label} in tracked file: {path}")
                break

        for match in SECRET_ASSIGNMENT.finditer(content):
            value = match.group("value").strip()
            if not value or INDIRECTION.match(value) or PLACEHOLDER.match(value):
                continue
            if path in TEMPLATE_PATHS:
                violations.append(
                    f"non-empty SECRET_KEY in committed template: {path} -> {value!r}"
                )
            else:
                violations.append(
                    f"literal SECRET_KEY assignment in tracked file: {path} -> {value!r}"
                )

    # Ignore rules are part of the fix: untracked is not ignored, and an unignored
    # file walks straight back into the next `git add .`.
    text = (gitignore or b"").decode("utf-8", "replace")
    for required in GITIGNORE_REQUIRED:
        if not any(
            line.strip() == required and not line.strip().startswith("#")
            for line in text.splitlines()
        ):
            violations.append(f".gitignore does not ignore {required!r}")

    if dockerignore is None:
        violations.append(
            f"{DOCKERIGNORE_PATH} is missing: `dockerfile` COPY . . bakes tracked secrets into the image"
        )
    else:
        docker_text = dockerignore.decode("utf-8", "replace")
        for required in DOCKERIGNORE_REQUIRED:
            if not any(
                line.strip() == required and not line.strip().startswith("#")
                for line in docker_text.splitlines()
            ):
                violations.append(f"{DOCKERIGNORE_PATH} does not exclude {required!r}")

    return violations


def current_violations() -> list[str]:
    snapshot = index_snapshot()
    return inspect(
        snapshot,
        snapshot.get(".gitignore"),
        snapshot.get(DOCKERIGNORE_PATH),
    )


# --- checks ------------------------------------------------------------------

def test_no_tracked_secrets() -> None:
    violations = current_violations()
    assert not violations, "tracked secret material:\n  - " + "\n  - ".join(violations)


def test_gate_detects_a_real_violation() -> None:
    """Positive control: a gate that cannot fail proves nothing."""
    snapshot = {
        ".env": b"SECRET_KEY=" + b"S3cr3t_K#Key" + b"\n",
        "blogapp/key/priv.pem": ("-----BEGIN RSA " + "PRIVATE KEY-----").encode() + b"\n",
    }
    kinds = " | ".join(inspect(snapshot, b"", None))
    assert "tracked secret file: .env" in kinds
    assert "tracked PEM key material: blogapp/key/priv.pem" in kinds
    assert "embedded private key in tracked file" in kinds
    assert "literal SECRET_KEY assignment" in kinds
    assert ".gitignore does not ignore '.env'" in kinds
    assert "is missing" in kinds


def test_indirection_is_not_flagged() -> None:
    """The intended sink (`config("SECRET_KEY")`) must stay clean."""
    snapshot = {
        ".env.example": b"SECRET_KEY=\n",
        "core/settings.py": b'SECRET_KEY = config("SECRET_KEY")\n',
        ".gitignore": b".env\n*.pem\n",
        DOCKERIGNORE_PATH: b".env\n*.pem\n",
    }
    assert inspect(snapshot, snapshot[".gitignore"], snapshot[DOCKERIGNORE_PATH]) == []


def main() -> int:
    try:
        violations = current_violations()
    except RuntimeError as exc:
        # An image built from this repository has no .git directory, so the index
        # cannot be inspected there. CI (a real checkout) is the enforcing run.
        print(f"SKIP: cannot read the git index here ({exc}). Run this in a checkout.")
        return EXIT_CANNOT_VERIFY
    if violations:
        print(f"FAIL: {len(violations)} tracked-secret violation(s):")
        for item in violations:
            print(f"  - {item}")
        return EXIT_VIOLATIONS
    print("PASS: no secret material tracked, ignored and excluded from the image context")
    return EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
