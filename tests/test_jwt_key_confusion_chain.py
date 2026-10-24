"""Regression tests for Code Audit finding ceca3e76-4eb0-4cfb-83ce-caf7fdfd071c.

Finding (audit 68421145-a581-4528-9011-424c0a9a0a52, assessed SHA
8c9dc729f775201a6cab55181640ac262f664ee2):
"Issuer side: login emits the auth JWT with the RSA public key embedded in its own
header" -- `blogapp/views/login.py:20-30`.

The defect is a two-role chain in one token:

  issuer    `create_cookie` signs `{"username": ..., "admin": is_superuser}` with
            RS256 and copies `config("PUBLICKEY")` into the token's own header
            (`headers={"publickey": embedded}`).
  verifier  `blogapp/views/setting.py:31-36` takes the verification key back out of
            that header, `jwt_vul.decode`s the token with it, and line 47 trusts the
            resulting `admin` claim to rewrite every vulnerability toggle.

Because the key travels with the token, any holder of a token can mint
`admin: True` with a key of their own choosing. `jwt_vul.decode` also selects the
algorithm from the token header (`core/lib/jwt_vul/api.py:147`) and has no
allow-list argument, so the header's `alg` is attacker-controlled as well.

Tests (the finding's stated regression test, run against the app):

  * `test_issued_token_header_carries_no_key_material` -- FAILS before the fix.
  * `test_forged_header_key_token_is_rejected`         -- FAILS before the fix.
  * `test_alg_none_token_is_rejected`                  -- FAILS before the fix.
  * `test_legit_admin_token_still_changes_toggles`     -- guards against over-fixing.

Only the vulnerable configuration is exercised (`JWT_Key_Confusion` on, `JWT` off);
the wordlist-key `JWT` branch at `login.py:32-38` is a separate finding.

Run (see the pull request body for the full recipe):

    export SECRET_KEY=test-only-secret DEBUG=False ALLOWED_HOSTS='["*"]' \
           DATABASE_ENGINE=django.db.backends.sqlite3 DATABASE_NAME=':memory:' \
           DATABASE_USER=test DATABASE_PASSWORD=test DATABASE_HOST= DATABASE_PORT=0
    python manage.py test tests -v 2

The tests generate their own RS256 key pair and point PRIVATEKEY/PUBLICKEY at it, so
they do not depend on `blogapp/key/priv.pem` or on `.env` being present.
"""

import base64
import hashlib
import hmac
import json
import os
import tempfile

import jwt as pyjwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from django.contrib.auth.models import User
from django.test import TestCase, override_settings

from blogapp.models.Setting import Vul

# Vulnerability toggles seeded by text/post.txt, in that file's order.
VUL_NAMES = [
    "XSS",
    "CSRF",
    "SSRF",
    "SQLI",
    "SSTI",
    "XXE",
    "JWT",
    "Broken Aut",
    "Deserialize",
    "Path travesal",
    "JWT_Key_Confusion",
    "IDOR",
]

# The app stores sessions in a cache (core/settings.py -> PyMemcacheCache). Tests use
# locmem so the suite needs no memcached daemon.
TEST_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "jwt-key-confusion-chain-tests",
    }
}


def b64url_decode(segment):
    raw = segment.encode("utf-8")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def b64url_encode(raw):
    return base64.urlsafe_b64encode(raw).replace(b"=", b"").decode("ascii")


def forge_hs256(payload, secret):
    """Build an HS256 token by hand.

    PyJWT refuses to use an asymmetric key as an HMAC secret (that check is itself a
    PyJWT hardening), but an attacker is not bound by it: the classic key-confusion
    attack signs HS256 with the server's *public* key as the shared secret.
    """
    header = b64url_encode(json.dumps({"typ": "JWT", "alg": "HS256"},
                                      separators=(",", ":")).encode("utf-8"))
    body = b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = ("%s.%s" % (header, body)).encode("ascii")
    digest = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return "%s.%s.%s" % (header, body, b64url_encode(digest))


def token_header(token):
    """Decode a JWT's header without verifying anything."""
    return json.loads(b64url_decode(token.split(".", 1)[0]).decode("utf-8"))


def make_rsa_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    return private_pem, public_pem


@override_settings(CACHES=TEST_CACHES)
class JwtKeyConfusionChainTests(TestCase):
    """JWT_Key_Confusion on / JWT off -- the configuration the finding describes."""

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # Point the app's signing/verification key at a pair generated for this run.
        cls._key_dir = tempfile.TemporaryDirectory()
        cls._env_backup = {}
        private_pem, public_pem = make_rsa_pair()
        for name, material in (("PRIVATEKEY", private_pem), ("PUBLICKEY", public_pem)):
            path = os.path.join(cls._key_dir.name, name.lower() + ".pem")
            with open(path, "w") as handle:
                handle.write(material)
            cls._env_backup[name] = os.environ.get(name)
            os.environ[name] = path

    @classmethod
    def tearDownClass(cls):
        for name, previous in cls._env_backup.items():
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous
        cls._key_dir.cleanup()
        super().tearDownClass()

    def setUp(self):
        for name in VUL_NAMES:
            Vul.objects.update_or_create(name=name, defaults={"status": False})
        Vul.objects.filter(name="JWT_Key_Confusion").update(status=True)
        Vul.objects.filter(name="JWT").update(status=False)

        self.admin = User.objects.create_superuser(
            username="admin", email="admin@example.com", password="adminpass"
        )
        self.bob = User.objects.create_user(
            username="bob", email="bob@example.com", password="bobpass"
        )

        # A rejected token must not be reported as a server error the test cannot
        # inspect: settingView has no handler for an undecodable cookie in any of its
        # three branches (pre-existing behaviour), so a bad token surfaces as a 500.
        self.client.raise_request_exception = False

    # -- helpers -------------------------------------------------------------

    def login(self, username, password):
        response = self.client.post(
            "/login?next=/",
            {"username": username, "password": password, "rememberMe": ""},
        )
        self.assertEqual(response.status_code, 302, "login did not redirect")
        self.assertIn("auth", response.cookies, "login set no auth cookie")
        return response.cookies["auth"].value

    def toggle_state(self):
        return {row.name: row.status for row in Vul.objects.all()}

    def post_all_toggles_yes_with(self, auth_token):
        """Log in as the low-privileged user, then present `auth_token` to /setting/."""
        self.login("bob", "bobpass")
        before = self.toggle_state()
        self.client.cookies["auth"] = auth_token
        response = self.client.post("/setting/", {name: "yes" for name in VUL_NAMES})
        return before, response

    def assert_no_toggle_changed(self, before, response):
        """A token the server must not trust: no admin, and no toggle write.

        Setting the `auth` cookie to a token that does not verify cannot be observed
        directly, so the two things the defect actually did are checked: the view
        never reported the change as accepted, and no toggle row moved. A refused
        token reaches the view's own "You don't have permission" branch.
        """
        body = response.content.decode("utf-8", "replace")
        self.assertNotIn(
            "Change is success!",
            body,
            "a token that should have been rejected was accepted by /setting/",
        )
        after = self.toggle_state()
        changed = sorted(name for name, value in after.items() if before[name] != value)
        self.assertEqual(changed, [], "a rejected token rewrote toggles: %s" % changed)
        self.assertTrue(
            "You don&#x27;t have permission" in body or "You don't have permission" in body,
            "expected the view to refuse the token, got status %s" % response.status_code,
        )
        self.assertEqual(response.status_code, 200)

    # -- tests ---------------------------------------------------------------

    def test_issued_token_header_carries_no_key_material(self):
        """The token issued at login must not carry the verification key."""
        header = token_header(self.login("admin", "adminpass"))
        self.assertEqual(header.get("alg"), "RS256")
        self.assertNotIn(
            "publickey",
            header,
            "the auth token header embeds key material: %r"
            % sorted(header),
        )

    def test_forged_header_key_token_is_rejected(self):
        """A token signed by the attacker's own key must not grant admin."""
        attacker_private, attacker_public = make_rsa_pair()
        forged = pyjwt.encode(
            {"username": "attacker", "admin": True},
            attacker_private,
            algorithm="RS256",
            headers={"publickey": attacker_public},
        )
        before, response = self.post_all_toggles_yes_with(forged)
        self.assert_no_toggle_changed(before, response)

    def test_hs256_signed_with_the_public_key_is_rejected(self):
        """Classic key confusion: sign HS256 with the (public) RSA key as the secret.

        Unpinned verification accepts this because the library reads the algorithm
        from the token header; an allow-list of RS256 refuses it.
        """
        with open(os.environ["PUBLICKEY"], "r") as handle:
            publickey = handle.read()
        forged = forge_hs256({"username": "attacker", "admin": True}, publickey)
        before, response = self.post_all_toggles_yes_with(forged)
        self.assert_no_toggle_changed(before, response)

    def test_alg_none_token_is_rejected(self):
        """`alg: none` must not be accepted: the accepted algorithms are allow-listed."""
        forged = pyjwt.encode(
            {"username": "attacker", "admin": True},
            key="",
            algorithm="none",
            headers={"publickey": "not-a-real-key"},
        )
        before, response = self.post_all_toggles_yes_with(forged)
        self.assert_no_toggle_changed(before, response)

    def test_legit_admin_token_still_changes_toggles(self):
        """The fix must not break the genuine login -> /setting/ flow."""
        self.client.cookies["auth"] = self.login("admin", "adminpass")
        response = self.client.post("/setting/", {name: "yes" for name in VUL_NAMES})
        self.assertEqual(response.status_code, 200)
        self.assertIn("Change is success!", response.content.decode("utf-8", "replace"))
        self.assertTrue(Vul.objects.get(name="XSS").status)
