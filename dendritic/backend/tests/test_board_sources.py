"""Round-trip invariant for the board-settings sources textarea.

The bug this pins down: format_source_config rendered whole-board ("*") rows
through the canonical thread-URL template, producing
"https://boards.4chan.org/a/thread/*". parse_source_line correctly refuses that
— it is not a thread URL — so the textarea arrived pre-loaded with a value that
failed its own validation, and EVERY save of such a board was rejected,
including edits nothing to do with sources (thread limit, mimetypes, rules).

The general rule, and what the first test enforces: whatever
format_source_config emits, parse_source_line must accept. Anything that cannot
survive that round trip does not belong in the textarea.

board_sources imports the Flask app stack, so it is stubbed out — the functions
under test are pure string handling.
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


def _install_shared_stub():
    """Stub ONLY `shared`, and only if nothing has imported it yet.

    Deliberately not stubbing the `model` or `services` packages: replacing them
    with plain modules leaves them without a __path__, so every later
    `model.X` import in the same process fails with "'model' is not a package" —
    which broke test_board_bookmarks when the two ran together. The real
    model.BoardSource and services.aggregator_sync.config import fine on top of
    this stub (`db.Model` has to be a real class for the model declaration to
    execute; config.py only imports os).
    """
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

from board_sources import (  # noqa: E402
    format_source_config,
    parse_source_line,
    whole_board_source_labels,
)
from services.aggregator_sync.config import WHOLE_BOARD_THREAD_ID  # noqa: E402

_restore_stubs()



class FakeSource(object):
    """Stands in for a BoardSource row; these helpers only read attributes."""

    def __init__(self, source_type, source_name, source_thread_id):
        self.source_type = source_type
        self.source_name = source_name
        self.source_thread_id = source_thread_id


def source(source_type, source_name, source_thread_id):
    return FakeSource(source_type, source_name, source_thread_id)


WHOLE_BOARD = WHOLE_BOARD_THREAD_ID


class SourceConfigRoundTripTest(unittest.TestCase):
    def test_everything_rendered_into_the_textarea_parses_back(self):
        """The invariant. A board whose settings page cannot be saved is the
        failure mode this prevents."""
        sources = [
            source("4chan", "a", WHOLE_BOARD),
            source("4chan", "g", "12345678"),
            source("8chan", "tech", WHOLE_BOARD),
            source("8chan", "b", "99887766"),
            source("7chan", "b", "4242"),
            source("reddit", "example", "abc123"),
            source("reddit", "other", WHOLE_BOARD),
        ]
        rendered = format_source_config(sources)
        self.assertTrue(rendered.strip(), "expected some thread sources to render")
        for line in rendered.splitlines():
            with self.subTest(line=line):
                # Must not raise.
                parse_source_line(line)

    def test_whole_board_rows_are_not_rendered(self):
        rendered = format_source_config([
            source("4chan", "a", WHOLE_BOARD),
            source("4chan", "g", "12345678"),
        ])
        self.assertNotIn("*", rendered)
        self.assertEqual(["https://boards.4chan.org/g/thread/12345678"], rendered.splitlines())

    def test_a_board_with_only_whole_board_sources_renders_an_empty_box(self):
        """This was the unsaveable case: one line, and it failed validation."""
        rendered = format_source_config([
            source("4chan", "a", WHOLE_BOARD),
            source("reddit", "example", WHOLE_BOARD),
        ])
        self.assertEqual("", rendered)

    def test_the_offending_url_is_still_rejected_by_the_parser(self):
        # The fix is to stop GENERATING this, not to start accepting it: a
        # whole-board row must stay inexpressible in the textarea so
        # replace_board_sources keeps refusing to delete it.
        with self.assertRaises(ValueError):
            parse_source_line("https://boards.4chan.org/a/thread/*")

    def test_unsupported_source_types_are_still_excluded(self):
        rendered = format_source_config([
            source("someotherchan.example", "b", "123"),
            source("4chan", "g", "12345678"),
        ])
        self.assertEqual(["https://boards.4chan.org/g/thread/12345678"], rendered.splitlines())

    def test_rows_with_no_thread_id_are_excluded(self):
        self.assertEqual("", format_source_config([source("4chan", "a", None)]))
        self.assertEqual("", format_source_config([source("4chan", "a", "")]))


class WholeBoardLabelsTest(unittest.TestCase):
    def test_lists_only_whole_board_sources(self):
        labels = whole_board_source_labels([
            source("4chan", "a", WHOLE_BOARD),
            source("4chan", "g", "12345678"),
            source("reddit", "example", WHOLE_BOARD),
        ])
        self.assertEqual(["4chan /a/", "reddit /r/example"], labels)

    def test_empty_when_none_configured(self):
        self.assertEqual([], whole_board_source_labels([source("4chan", "g", "12345678")]))


if __name__ == "__main__":
    unittest.main()
