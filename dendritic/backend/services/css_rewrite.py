"""CSS url() rewriting, lifted out of the deleted image_proxy blueprint.

`profiles.py` sanitises operator-supplied CSS and was the only surviving caller
of `rewrite_css_image_urls`. The blueprint it lived in served the imageboard and
was removed; the function is pure and has no Flask dependency, so it moves here
rather than dragging a route back to satisfy one import.

The proxy endpoint this rewrites *to* no longer exists. That is deliberate and
is the safer of the two failure modes: an external image referenced from custom
CSS now resolves to a dead local path instead of being fetched, so a profile
cannot be used to make a visitor's browser issue requests to a third party.
Rewriting still happens because the alternative -- leaving the absolute URL in
place -- would restore exactly that tracking channel.
"""

import re
from urllib.parse import quote

_CSS_URL_RE = re.compile(
    r"""url\s*\(\s*(['"]?)(https?://[^'"\)\s]+)\1\s*\)""",
    re.IGNORECASE,
)


def rewrite_css_image_urls(css: str, proxy_path: str = "/image-proxy") -> str:
    """Rewrite external http/https URLs inside CSS url() expressions.

    data: URIs and relative paths are untouched.

    Before:
        background-image: url("http://example.com/hero.jpg");
    After:
        background-image: url("/image-proxy?url=http%3A//example.com/hero.jpg");
    """

    def _sub(m: "re.Match") -> str:
        q, img_url = m.group(1), m.group(2)
        proxied = f"{proxy_path}?url={quote(img_url, safe='')}"
        return f"url({q}{proxied}{q})"

    return _CSS_URL_RE.sub(_sub, css)
