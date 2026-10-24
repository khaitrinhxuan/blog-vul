"""Allow-list sanitiser for stored rich text.

Code Audit finding 26df3ad5-3f59-4f3b-b3b1-aa547e1fea1d (audit 68421145) at
8c9dc729: ``Post.admin_content`` returned ``mark_safe(self.content)``, which
marks the raw database value as trusted HTML and suppresses template
auto-escaping at every render site. ``content`` is attacker-influenced: it is
written from the crawled page by ``blogapp/views/requestpost.py:79-82`` or from
the uploaded XML by ``:98``.

Escaping alone is not a repair here: ``content`` is a
``RichTextUploadingField`` and the shipped seed (``text/post.txt``) stores real
``<p>``/``<h3>``/``<a>``/``<pre>`` markup that must keep rendering, and
``blogapp/templates/blogapp/search.html:8`` renders inside
``{% autoescape off %}``. Content is therefore sanitised against an allow-list
and only the sanitised result is marked safe.

Sanitising at the model boundary covers rows already in the database as well as
new writes, so no stored payload survives.
"""

from __future__ import annotations

import bleach
from django.utils.safestring import mark_safe

# Tags the editor and the shipped seed actually use, plus their obvious
# structural companions. Anything outside this set is stripped.
ALLOWED_TAGS = [
    "p", "br", "hr", "div", "span",
    "h1", "h2", "h3", "h4", "h5", "h6",
    "strong", "b", "em", "i", "u", "s", "sub", "sup", "small", "mark",
    "ul", "ol", "li", "dl", "dt", "dd",
    "blockquote", "pre", "code",
    "a", "img", "figure", "figcaption", "cite",
    "table", "thead", "tbody", "tfoot", "tr", "th", "td",
]

# No `style` attribute: bleach only sanitises CSS when a CSSSanitizer is
# supplied, and allowing raw `style` would re-open `url(...)`-based vectors.
ALLOWED_ATTRIBUTES = {
    "a": ["href", "title", "target", "rel"],
    "img": ["src", "alt", "title", "width", "height"],
    "span": ["dir"],
    "th": ["colspan", "rowspan", "scope"],
    "td": ["colspan", "rowspan"],
    "ol": ["start"],
    "code": ["class"],
    "pre": ["class"],
    "*": [],
}

# Protocol allow-list applied to href/src; blocks javascript:, data:, vbscript:.
ALLOWED_PROTOCOLS = ["http", "https", "mailto"]


def sanitize_html(value):
    """Return ``value`` with every tag, attribute and URL outside the allow-list removed."""
    if not value:
        return ""
    return bleach.clean(
        str(value),
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
    )


def safe_html(value):
    """Sanitised HTML marked safe, so template auto-escaping may be bypassed on it."""
    return mark_safe(sanitize_html(value))
