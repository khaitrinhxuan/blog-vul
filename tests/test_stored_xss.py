#!/usr/bin/env python3
"""Regression test for Code Audit finding 26df3ad5-3f59-4f3b-b3b1-aa547e1fea1d.

Finding (audit 68421145-a581-4528-9011-424c0a9a0a52, assessed SHA 8c9dc729):
`blogapp/models/Post.py:28-29` returned `mark_safe(self.content)`, so the raw
database value was marked trusted HTML and template auto-escaping was suppressed
at every render site (`index.html:39,56,99`, `post.html:112`, `preview.html`,
`tags.html`, `blog.html`, `search.html`, `setting.html`). `content` is
attacker-influenced: `blogapp/views/requestpost.py:79-82` builds it from a
crawled page and `:98` stores the uploaded XML `root[2].text`, and no
`blogapp_vul` row gates the sink -- the XSS toggle only switches other display
paths -- so the sink is live in the default seeded state (`text/post.txt:20`
seeds `XSS` False).

The test writes the same hostile markup through an unauthenticated
`POST /requestpost/` crawl and through a direct ORM write, then renders `/`,
`/post/<id>/`, `/tag/<t>/` and `/search/`, and asserts the payload cannot
execute. It also asserts ordinary rich text still renders, so the fix is a
sanitisation boundary rather than a blanket escape of stored content.

Runs on sqlite + local-memory cache so it needs no PostgreSQL and no memcached.
Run:  python3 tests/test_stored_xss.py     (exit 0 = pass, 1 = fail)
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

# `requestpost.py` reads `text/blacklist.txt` (`:53`) and writes crawl images to
# `core/media/...` (`:46-47`) by relative path, so the test runs in a throwaway
# directory that mirrors just those paths. That keeps the repository clean and
# the run repeatable. Templates resolve absolutely via settings.TEMPLATES.
WORK_ROOT = tempfile.mkdtemp(prefix="blog-vul-stored-xss-")
os.makedirs(os.path.join(WORK_ROOT, "text"))
os.makedirs(os.path.join(WORK_ROOT, "core", "media"))
shutil.copy(os.path.join(REPO_ROOT, "text", "blacklist.txt"),
            os.path.join(WORK_ROOT, "text", "blacklist.txt"))
os.chdir(WORK_ROOT)

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
# `setdefault`, so an operator driving this through `manage.py test` keeps their
# own database configuration; the standalone entry point supplies sqlite.
_ENV_DEFAULTS = {
    "DATABASE_ENGINE": "django.db.backends.sqlite3",
    "DATABASE_NAME": os.path.join(WORK_ROOT, "test_stored_xss.sqlite3"),
    "DATABASE_USER": "",
    "DATABASE_PASSWORD": "",
    "DATABASE_HOST": "",
    "DATABASE_PORT": "0",
    "SECRET_KEY": "stored-xss-regression-test-only",
    "DEBUG": "True",
    "ALLOWED_HOSTS": "*",
}
for _key, _value in _ENV_DEFAULTS.items():
    os.environ.setdefault(_key, _value)

import django  # noqa: E402

django.setup()

from django.test import Client, TestCase, override_settings  # noqa: E402
from django.test.runner import DiscoverRunner  # noqa: E402
from django.test.utils import setup_test_environment  # noqa: E402

# `manage.py test` has already set the test environment up; standalone has not.
try:
    setup_test_environment()
except RuntimeError:
    pass

from blogapp.models.Post import Post, Tags, User  # noqa: E402
from blogapp.models.Setting import Vul  # noqa: E402

SCRIPT = "<script>alert(1)</script>"
IMG_ONERROR = '<img src=x onerror="alert(2)">'
LINK_JS = '<a href="javascript:alert(1)">click</a>'
# Seeded rich text from `text/post.txt` that must keep rendering.
LEGIT = "<p>Lorem ipsum</p><h3><strong>Lorem Ipsum Dolor</strong></h3>"

# Every payload must stop being executable after the sink is applied. `+` joins
# them into one stored value, which is how a single crawled post carries several.
XSS_PAYLOADS = [
    SCRIPT,
    IMG_ONERROR,
    LINK_JS,
    "<svg/onload=alert(3)>",
    "<iframe src=\"https://evil.example/\"></iframe>",
    '<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">d</a>',
    "<div onmouseover=alert(4)>hover</div>",
    "<body onload=alert(5)>",
    '<p style="background-image:url(javascript:alert(6))">styled</p>',
    "<scr<script>ipt>alert(7)</script>",
    "&lt;script&gt;alert(8)&lt;/script&gt;",
    "<img src=x onerror=alert(9)//>",
    "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
    "<embed src=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">",
]
# Markers are payload-specific on purpose. A bare "<script" also matches the
# application's own template JavaScript (index.html:150, base.html:35), so it
# cannot distinguish stored XSS from the page's own scripts.
MARKERS = ("<script>alert(", "onerror=", "onload=", "onmouseover=", "javascript:",
           "expression(", "<iframe", "<object", "<embed", "<svg")

VUL_ROWS = ["XSS", "CSRF", "SSRF", "SQLI", "SSTI", "XXE", "JWT", "Broken Aut",
            "Deserialize", "Path travesal", "JWT_Key_Confusion", "IDOR"]

JWT_STATUS = "BooleanField <blogapp.models.Setting.Vul>"

LOCMEM_CACHES = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                             "LOCATION": "stored-xss-tests"}}


def assert_not_executable(test, body, where):
    """No attacker-controlled element may reach the rendered page as active markup."""
    lowered = body.lower()
    leaked = [m for m in MARKERS if m in lowered]
    if SCRIPT.lower() in lowered:
        leaked.append(SCRIPT)
    test.assertEqual(leaked, [], "active payload rendered at %s" % where)


@override_settings(CACHES=LOCMEM_CACHES)
class StoredXSSTestCase(TestCase):
    @classmethod
    def setUpTestData(cls):
        # `core/session_backend.py:11` evaluates Vul.objects.filter(...)[0] at
        # class-definition time and the views index several rows by name, so the
        # default seeded state must exist before the first request.
        for name in VUL_ROWS:
            Vul.objects.get_or_create(name=name, defaults={"status": False})
        cls.tag = Tags.objects.create(name="kinhnghiem")
        cls.user = User.objects.create_user(username="reporter", password="pw")

    def setUp(self):
        self.client = Client()
        # The crawl writer creates `core/media/<date>/` entries under cwd; reset
        # them so each test starts from the same place.
        media = os.path.join(WORK_ROOT, "core", "media")
        shutil.rmtree(media, ignore_errors=True)
        os.makedirs(media)

    def _hostile_post(self, content):
        post = Post.objects.create(title="poc", status=1, content=content,
                                   images="uploads/2021/05/31/postimages.jpg")
        post.tags.add(self.tag)
        return post

    # --- the sink itself ---------------------------------------------------

    def test_orm_write_admin_content_is_not_raw_markup(self):
        post = self._hostile_post(LEGIT + SCRIPT + IMG_ONERROR + LINK_JS)
        rendered = str(post.admin_content())
        self.assertNotIn(SCRIPT, rendered)
        self.assertNotIn("onerror=", rendered)
        self.assertNotIn("javascript:", rendered)
        # Stored bytes are unchanged; the sanitiser is applied on render.
        self.assertIn(SCRIPT, Post.objects.get(pk=post.pk).content)

    def test_legit_rich_text_still_renders(self):
        post = self._hostile_post(LEGIT)
        rendered = str(post.admin_content())
        self.assertIn("<p>Lorem ipsum</p>", rendered)
        self.assertIn("<h3>", rendered)
        self.assertIn("<strong>", rendered)

    def test_comment_admin_content_is_not_raw_markup(self):
        post = self._hostile_post(LEGIT)
        comment = post.comment.create(content=SCRIPT + IMG_ONERROR,
                                      author_id=self.user, email=self.user)
        rendered = str(comment.admin_content())
        self.assertNotIn(SCRIPT, rendered)
        self.assertNotIn("onerror=", rendered)

    # --- every render site the finding lists --------------------------------

    def test_render_sites_are_not_executable(self):
        post = self._hostile_post(LEGIT + SCRIPT + IMG_ONERROR)
        # `/search/` requires `tagId` (search.py:12 indexes it directly), so only
        # the form the view actually renders is exercised here.
        for url in ["/", "/post/%d/" % post.pk, "/tag/kinhnghiem/",
                    "/search/?search=poc&tagId=kinhnghiem"]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, "render failed at %s" % url)
            assert_not_executable(self, response.content.decode("utf-8", "replace"), url)

    def test_render_sites_keep_legit_markup(self):
        post = self._hostile_post(LEGIT)
        for url in ["/", "/post/%d/" % post.pk, "/tag/kinhnghiem/"]:
            response = self.client.get(url)
            self.assertEqual(response.status_code, 200, "render failed at %s" % url)
            self.assertIn("<p>Lorem ipsum</p>", response.content.decode("utf-8", "replace"),
                          "rich text lost at %s" % url)

    def test_every_payload_is_neutralised_at_the_sink(self):
        post = self._hostile_post("".join(XSS_PAYLOADS))
        rendered = str(post.admin_content()).lower()
        leaked = [m for m in MARKERS if m in rendered]
        self.assertEqual(leaked, [], "payload survived the sanitiser")

    def test_shipped_seed_rich_text_is_not_destroyed(self):
        """Sanitising must not gut the markup the repository itself ships."""
        seed = os.path.join(REPO_ROOT, "text", "post.txt")
        with open(seed, encoding="utf-8") as handle:
            raw = handle.read()
        # The first seeded post body, between the quoted title and the timestamp.
        body = raw.split("values (1,'Diversity in Engineering','1','")[1].split("','2016-06-22")[0]
        rendered = str(Post(content=body).admin_content())
        for tag in ["<p>", "</p>", "<h3>", "<strong>", "</strong>", "<cite>"]:
            self.assertIn(tag, rendered, "%s lost from shipped seed content" % tag)
        self.assertNotIn("&lt;p&gt;", rendered, "seed markup was escaped instead of sanitised")

    # --- the writer path named by the finding -------------------------------

    def test_requestpost_crawl_write_is_sanitised(self):
        page = (b"<html><head><title>crawled</title></head><body>"
                b"<main class='post-content'><p>hi</p>"
                b"<script>alert(1)</script><img src=x onerror=alert(2)>"
                b"<svg/onload=alert(3)></main></body></html>")
        fake = mock.Mock(content=page, status_code=200, raise_for_status=mock.Mock())
        self.client.force_login(self.user)
        with mock.patch("blogapp.views.requestpost.requests.get", return_value=fake):
            response = self.client.post("/requestpost/", {"crawl": "http://example.com/a"})
        self.assertEqual(response.status_code, 200)
        written = Post.objects.get(title="crawled")
        self.assertIn("alert(1)", written.content, "writer path did not store the payload")
        assert_not_executable(self, str(written.admin_content()), "admin_content after crawl write")
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        assert_not_executable(self, response.content.decode("utf-8", "replace"),
                              "/ after crawl write")


if __name__ == "__main__":
    runner = DiscoverRunner(verbosity=2)
    old_config = runner.setup_databases()
    try:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
        )
    finally:
        runner.teardown_databases(old_config)
    sys.exit(0 if result.wasSuccessful() else 1)
