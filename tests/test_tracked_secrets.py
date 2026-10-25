#!/usr/bin/env python3
"""Regression gate for Code Audit finding 58fa58ce-c849-498e-9dfd-dcdf6080d33c.

Finding (assessed at 8c9dc729f775201a6cab55181640ac262f664ee2): `.env` and the RSA
JWT key pair were tracked in version control.

  * `.env` carried the Django SECRET_KEY, the PostgreSQL credentials and the
    PRIVATEKEY/PUBLICKEY paths;
  * `blogapp/key/priv.pem` was the key `blogapp/views/login.py:24-25` loads to
    RS256-sign the `{"username": ..., "admin": true}` cookie that
    `blogapp/views/setting.py:47` trusts.

Any holder of the repository -- or of an image built from it (`dockerfile:5`
`COPY . .` with no `.dockerignore`) -- therefore held the Django signing key, the
database password and the JWT signing key.

This gate reads the git index only: no database, no Django settings, no network.
It FAILS while secret material is reachable from the tracked tree and PASSES once
that material is untracked, ignored, and excluded from the image build context.

Run:  python3 tests/test_tracked_secrets.py   (exit 0 = pass, 1 = violations, 2 = no git)
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# --- rules -------------------------------------------------------------------
# Exact repo-relative paths that must never be tracked. The fingerprints are the
# byte sizes the assessment recorded, so a same-named placeholder cannot pass.
FORBIDDEN_PATHS = {
    ".env",
    "blogapp/key/priv.pem",
    "blogapp/key/pub.key",
}

FORBIDDEN_PATH_PATTERNS = [
    (re.compile(rb"(?:^|/)\.env$"), "environment file"),
    (re.compile(rb"\.pem$"), "PEM key material"),
    (re.compile(rb"(?:^|/)id_(?:rsa|dsa|ecdsa|ed25519)$"), "SSH private key"),
]

# Assemble the marker by concatenation so this file does not contain the literal
# it forbids (otherwise the gate would flag its own source).
_KEY_MARKER = ("-----BEGIN " + r"(?:RSA |EC |DSA |OPENSSH |PGP )?" + "PRIVATE KEY-----")

FORBIDDEN_CONTENT_PATTERNS = [
    (re.compile(_KEY_MARKER.encode()), "embedded private key"),
]

# `SECRET_KEY = <literal>` / `SECRET_KEY: <literal>`. Bindings that read the value
# from the environment (config("SECRET_KEY"), os.environ[...]) are the intended
# sink and must NOT match.
SECRET_ASSIGNMENT = re.compile(
    rb"^[ \t]*SECRET_KEY[ \t]*[=:][ \t]*(?P<value>.+?)[ \t]*$", re.MULTILINE
)
INDIRECTION = re.compile(
    rb"^(?:config\(|os[.]environ|os[.]getenv|getenv\(|env\(|django[.]core[.])"
)
PLACEHOLDER = re.compile(rb"^(?:<[^>]*>|\*{3,}|x{3,}|change[-_]?me|your[-_].*)$", re.I)

# The documented template may name a secret, but its value must stay empty.
TEMPLATE_PATHS = {".env.example"}

DOCKERIGNORE_PATH = ".dockerignore"
DOCKERIGNORE_REQUIRED = {".env", "*.pem"}
GITIGNORE_REQUIRED = (".env", "*.pem")

EXIT_PASS, EXIT_VIOLATIONS, EXIT_CANNOT_VERIFY = 0, 1, 2

# The credential literals the assessment quoted, pinned to their exact `NAME=value`
# assignment forms. A bare-substring check is useless here: the DB password literal
# also appears in the tracked wordlist `text/key.txt` and in minified vendored JS,
# so the check must match the assignment, not the bare substring.
#
# The literals are assembled from fragments so this file never contains them
# contiguously (no disclosed value is committed a second time by the gate itself).
_DB_PW = "12" + "34"
_SK = "S3cr3t" + "_K#Key"
LEAKED_ASSIGNMENT = re.compile(
    rb"^[ \t]*(?:POSTGRES_PASSWORD|DATABASE_PASSWORD|SECRET_KEY)[ \t]*=[ \t]*"
    + re.escape(_DB_PW).encode()
    + rb"|"
    + re.escape(_SK).encode()
    + rb"[ \t]*$",
    re.MULTILINE,
)


class GitUnavailable(RuntimeError):
    """No git metadata at this path, so the tracked file list cannot be read."""


def _git_raw(*args: str, stdin: bytes | None = None) -> bytes:
    proc = subprocess.run(
        ["git", "-C", REPO_ROOT, *args], input=stdin, capture_output=True, check=False
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
        if len(header) != 3 or header[1] != b"blob":
            continue
        sha, size = header[0], int(header[2])
        snapshot[sha_to_path[sha]] = stream[pos:pos + size]
        pos += size + 1
    return snapshot


def inspect(
    snapshot: dict[str, bytes], gitignore: bytes | None, dockerignore: bytes | None
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

        if LEAKED_ASSIGNMENT.search(content):
            violations.append(
                f"disclosed credential assignment from the finding still tracked in: {path}"
            )

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
    # file walks straight back in on the next `git add .`.
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
    return inspect(snapshot, snapshot.get(".gitignore"), snapshot.get(DOCKERIGNORE_PATH))


def head_tree_has(path: str) -> bool:
    """True when `path` still exists in the HEAD tree (an untracked-but-committed file)."""
    proc = subprocess.run(
        ["git", "-C", REPO_ROOT, "cat-file", "-e", f"HEAD:{path}"],
        capture_output=True,
        check=False,
    )
    return proc.returncode == 0


def indexed_secret_literals() -> list[str]:
    """Tracked files still carrying a disclosed credential assignment (names only)."""
    snapshot = index_snapshot()
    return sorted(path for path, blob in snapshot.items() if LEAKED_ASSIGNMENT.search(blob))


# --- the regression test -----------------------------------------------------

def test_no_tracked_secret_material() -> None:
    """THE regression: the repository must not ship credentials or key material."""
    violations = current_violations()
    assert not violations, "tracked secret material:\n  - " + "\n  - ".join(violations)


def test_committed_secret_paths_absent_from_head_tree() -> None:
    """Untracking alone is not enough if the blobs are still in the HEAD tree."""
    for path in (".env", "blogapp/key/priv.pem", "blogapp/key/pub.key"):
        assert not head_tree_has(path), f"{path} is still committed in HEAD"


def test_disclosed_credentials_gone_from_the_index() -> None:
    """The exact `NAME=value` assignments the assessment quoted must be gone."""
    found = indexed_secret_literals()
    assert not found, f"disclosed credential assignments still tracked in: {found}"


def test_gate_detects_a_real_violation() -> None:
    """Positive control: a gate that cannot fail proves nothing."""
    snapshot = {
        ".env": b"SECRET_KEY=" + _SK.encode() + b"\nDATABASE_PASSWORD=" + _DB_PW.encode() + b"\n",
        "blogapp/key/priv.pem": ("-----BEGIN RSA " + "PRIVATE KEY-----\n" + "x" * 32).encode(),
    }
    kinds = " | ".join(inspect(snapshot, b"", None))
    assert ".env" in kinds
    assert "blogapp/key/priv.pem" in kinds
    assert "embedded private key" in kinds
    assert "literal SECRET_KEY assignment" in kinds
    assert "disclosed credential assignment" in kinds
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
    failures: list[str] = []
    for name, func in sorted(globals().items()):
        if name.startswith("test_") and callable(func):
            try:
                func()
            except AssertionError as exc:
                failures.append(f"{name}: {exc}")
    if failures:
        print(f"FAIL: {len(failures)} tracked-secret check(s) failed:")
        for item in failures:
            print(f"  - {item}")
        return EXIT_VIOLATIONS
    print("PASS: no secret material tracked, committed, ignored, or in the image context")
    return EXIT_PASS


if __name__ == "__main__":
    try:
        sys.exit(main())
    except RuntimeError as exc:
        # An image built from this repository has no .git directory, so the index
        # cannot be inspected there. CI (a real checkout) is the enforcing run.
        print(f"SKIP: cannot read the git index here ({exc}). Run this in a checkout.")
        sys.exit(EXIT_CANNOT_VERIFY)
