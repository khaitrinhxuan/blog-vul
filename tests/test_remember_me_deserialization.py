"""Regression tests for Code Audit finding 0842f912-6fb2-44a9-891b-8bdea7cf8e08.

Finding (audit 68421145-a581-4528-9011-424c0a9a0a52, assessed SHA
8c9dc729f775201a6cab55181640ac262f664ee2): unauthenticated ``pickle.loads`` RCE on the
``rememberMe`` cookie, ``blogapp/views/login.py:72``.

``loginView.post`` reads the ``rememberMe`` cookie straight from the request and passes
``base64.b64decode`` of it to ``pickle.loads`` with no signature or integrity check, so the
attacker controls the deserialised bytes. Reachability: the route is
``path("login", loginView.as_view())`` (``blogapp/urls.py:16``, no auth), every ``LoginForm``
field is ``required=False`` (``blogapp/views/login_form.py:5-33``), and the branch is gated
only by the ``Deserialize`` row read at ``login.py:62`` (seeded False at
``text/post.txt:28``). The value loaded from the pickle then *becomes* the authenticated
user, so the sink is also an authentication bypass, not just code execution.

Tests:

  * ``test_remember_me_pickle_payload_does_not_execute`` -- FAILS before the fix (canary fires).
  * ``test_unsigned_remember_me_cookie_grants_no_session`` -- FAILS before the fix.
  * ``test_foreign_key_signed_cookie_is_rejected`` -- FAILS before the fix.
  * ``test_tampered_remember_me_cookie_is_rejected`` -- FAILS before the fix.
  * ``test_legit_remember_me_round_trip_still_works`` -- passes before and after; guards
    against over-fixing (the remember-me feature must stay usable).

Only the vulnerable configuration (``Deserialize`` on) is exercised; the gate itself is
correct and is not part of the repair.

Run (no PostgreSQL or memcached needed; both are overridden):

    export SECRET_KEY=test-only-secret DEBUG=False ALLOWED_HOSTS='["*"]' \\
           DATABASE_ENGINE=django.db.backends.sqlite3 DATABASE_NAME=':memory:' \\
           DATABASE_USER=test DATABASE_PASSWORD=test DATABASE_HOST= DATABASE_PORT=0
    python manage.py test tests.test_remember_me_deserialization -v 2
"""

import base64
import json
import os
import pickle
import shutil
import tempfile

from django.core import signing
from django.test import Client, TestCase, override_settings

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

# The app stores sessions in a cache (core/settings.py:53-58 -> PyMemcacheCache). Tests use
# locmem so the suite needs no memcached daemon.
TEST_CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        "LOCATION": "remember-me-deserialization-tests",
    }
}


class Remembered(object):
    """What the vulnerable view expects from the unpickled cookie (``info.username``)."""

    def __init__(self, username, password):
        self.username = username
        self.password = password


def canary_sink(path):
    """Stand-in for any attacker-chosen callable reached through the pickle sink."""
    with open(path, "w") as handle:
        handle.write("executed")


def canary_then_remembered(path, username, password):
    """Runs on unpickling: prove execution, then satisfy the view's attribute access.

    Returning an object that carries ``username``/``password`` keeps the request from
    failing downstream, so the *canary* is what the test observes, not an incidental
    ``AttributeError``.
    """
    canary_sink(path)
    return Remembered(username, password)


class Evil(object):
    """A pickle payload whose reconstruction executes :func:`canary_then_remembered`."""

    def __init__(self, canary_path, username="admin", password="adminpass"):
        self.canary_path = canary_path
        self.username = username
        self.password = password

    def __reduce__(self):
        return (canary_then_remembered, (self.canary_path, self.username, self.password))


@override_settings(CACHES=TEST_CACHES)
class RememberMeDeserializationTests(TestCase):
    """``Deserialize`` on -- the configuration the finding's RCE path requires."""

    def setUp(self):
        for name in VUL_NAMES:
            Vul.objects.update_or_create(name=name, defaults={"status": False})
        Vul.objects.filter(name="Deserialize").update(status=True)

    # -- helpers -------------------------------------------------------------

    def post_login(self, client=None):
        """One unauthenticated POST /login with empty credentials and the set cookies."""
        client = client or self.client
        return client.post(
            "/login?next=/",
            {"username": "", "password": "", "rememberMe": ""},
        )

    def assert_rejected(self, response):
        """A cookie the server must not trust grants no session and no server error."""
        self.assertEqual(
            response.status_code,
            200,
            "an untrusted rememberMe cookie was not refused cleanly (status %s)"
            % response.status_code,
        )
        self.assertNotIn(
            "auth",
            response.cookies,
            "an untrusted rememberMe cookie produced an authenticated session",
        )

    # -- tests ---------------------------------------------------------------

    def test_remember_me_pickle_payload_does_not_execute(self):
        """A client-supplied pickle must never be deserialised nor trusted as identity."""
        from django.contrib.auth.models import User

        # A real account with the credentials the payload names, so a successful
        # deserialisation turns into a genuine authenticated session rather than a no-op.
        User.objects.create_superuser(
            username="admin", email="admin@example.com", password="adminpass"
        )

        canary_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, canary_dir, ignore_errors=True)
        canary = os.path.join(canary_dir, "canary")
        self.assertFalse(os.path.exists(canary))

        self.client.cookies["rememberMe"] = base64.b64encode(
            pickle.dumps(Evil(canary))
        ).decode("ascii")
        response = self.post_login()

        self.assertFalse(
            os.path.exists(canary),
            "the rememberMe cookie was unpickled and executed attacker-supplied code",
        )
        self.assertNotIn(
            "auth",
            response.cookies,
            "an attacker-supplied pickle authenticated the request",
        )

    def test_unsigned_remember_me_cookie_grants_no_session(self):
        """Base64 JSON is enough to forge a login only if the cookie is trusted blindly."""
        self.client.cookies["rememberMe"] = base64.b64encode(
            json.dumps({"username": "admin", "password": "adminpass"}).encode("utf-8")
        ).decode("ascii")
        self.assert_rejected(self.post_login())

    def test_foreign_key_signed_cookie_is_rejected(self):
        """A cookie signed with a key the attacker holds must fail signature verification."""
        forged = signing.dumps(
            {"username": "admin", "password": "adminpass"}, key="attacker-known-key"
        )
        self.client.cookies["rememberMe"] = base64.b64encode(
            forged.encode("utf-8")
        ).decode("ascii")
        self.assert_rejected(self.post_login())

    def test_tampered_remember_me_cookie_is_rejected(self):
        """Altering a server-issued cookie must fail its check and grant no session."""
        issued = self.issue_remember_me_cookie()
        tampered = issued[:-1] + ("A" if issued[-1] != "A" else "B")
        self.assertNotEqual(tampered, issued)
        self.client.cookies["rememberMe"] = tampered
        self.assert_rejected(self.post_login())

    def test_legit_remember_me_round_trip_still_works(self):
        """The remember-me feature must keep working: issue, then replay, its own cookie."""
        issued = self.issue_remember_me_cookie()

        fresh = Client()
        fresh.cookies["rememberMe"] = issued
        replay = self.post_login(client=fresh)
        self.assertEqual(
            replay.status_code,
            302,
            "a server-issued rememberMe cookie was not honoured on replay",
        )
        self.assertIn(
            "auth",
            replay.cookies,
            "a server-issued rememberMe cookie did not produce an authenticated session",
        )

    # -- feature helper ------------------------------------------------------

    def issue_remember_me_cookie(self):
        """Log in as a normal user with remember-me ticked and return the issued value."""
        from django.contrib.auth.models import User

        User.objects.create_user(username="bob", email="bob@example.com", password="bobpass")
        response = self.client.post(
            "/login?next=/",
            {"username": "bob", "password": "bobpass", "rememberMe": "on"},
        )
        self.assertEqual(response.status_code, 302, "remember-me login did not redirect")
        self.assertIn(
            "rememberMe",
            response.cookies,
            "remember-me login issued no rememberMe cookie",
        )
        return response.cookies["rememberMe"].value
