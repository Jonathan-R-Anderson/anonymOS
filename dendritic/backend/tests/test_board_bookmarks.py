"""Bookmark URL validation.

model/BoardBookmark.py pulls in `shared.db` at import time, which would drag the
whole Flask/SQLAlchemy app in for what is a pure string function. The stub below
keeps this test runnable on its own: `db.Model` has to be a real class for the
model declaration to execute, everything else is only ever called to build class
attributes, so a MagicMock covers it.

What is being pinned down: a board moderator's bookmark is rendered as an <a
href> on every page of their board, so a `javascript:` (or `data:`) URL saved
here would be stored XSS against every visitor.
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


def _install_shared_stub():
    if "shared" in sys.modules:
        return lambda: None
    shared = types.ModuleType("shared")
    db = MagicMock()
    db.Model = object
    shared.db = db
    shared.app = MagicMock()
    sys.modules["shared"] = shared

    # RESTORE, so the stub does not outlive the import it exists for. pytest
    # imports every test module during COLLECTION, so a stub left in place
    # replaces `shared` for every module collected afterwards; this one carries
    # `db` and `app` and nothing else, and a later `from shared import db,
    # db_retry` then fails with an ImportError naming neither this file nor the
    # stub. A collection error is fatal to the entire run.
    def restore():
        sys.modules.pop("shared", None)

    return restore


_restore_stubs = _install_shared_stub()

from model.BoardBookmark import normalize_bookmark_url  # noqa: E402

_restore_stubs()



class NormalizeBookmarkUrlTest(unittest.TestCase):
    def test_keeps_http_and_https_untouched(self):
        for url in ("http://example.com/wiki", "https://example.com/a?b=c#d"):
            self.assertEqual(url, normalize_bookmark_url(url))

    def test_bare_host_is_promoted_to_https(self):
        self.assertEqual("https://example.com/wiki", normalize_bookmark_url("example.com/wiki"))

    def test_surrounding_whitespace_is_stripped(self):
        self.assertEqual("https://example.com", normalize_bookmark_url("  https://example.com  "))

    def test_script_schemes_are_rejected(self):
        # The whole point of the function: none of these may survive into an href.
        for url in (
            "javascript:alert(1)",
            "JavaScript:alert(1)",
            "  javascript:alert(1)",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox(1)",
            "file:///etc/passwd",
        ):
            with self.assertRaises(ValueError, msg=url):
                normalize_bookmark_url(url)

    def test_scheme_relative_urls_are_rejected(self):
        # "//evil.com" would inherit the page's scheme and silently leave the site.
        with self.assertRaises(ValueError):
            normalize_bookmark_url("//evil.com/path")

    def test_empty_and_hostless_values_are_rejected(self):
        for url in ("", "   ", None, "https://", "notaurl"):
            with self.assertRaises(ValueError):
                normalize_bookmark_url(url)

    def test_overlong_url_is_rejected(self):
        with self.assertRaises(ValueError):
            normalize_bookmark_url("https://example.com/" + ("a" * 600))


if __name__ == "__main__":
    unittest.main()
