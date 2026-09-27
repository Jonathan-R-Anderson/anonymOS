"""The two retention clocks and their defaults.

Requested behaviour: only keep scraped threads posted in the last 24 hours
(configurable), and when a thread falls out of that window purge its data but
keep the METADATA for 30 days (configurable) in case the same thread reappears.

These tests pin the defaults and, more importantly, the two directions the
window can be got wrong: a thread with an unknown timestamp must not be treated
as stale, and a window of 0 must disable purging rather than purge everything.
"""
import datetime as _datetime
import sys
import types
import unittest
from unittest.mock import MagicMock


_SETTINGS = {}


def _install_stubs():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        sys.modules["shared"] = shared
    # model.SiteSetting reaches the DB; back it with a dict for these tests.
    if "model.SiteSetting" not in sys.modules:
        mod = types.ModuleType("model.SiteSetting")
        mod.get_setting = lambda key, default="": _SETTINGS.get(key, default)
        mod.set_setting = lambda key, value: _SETTINGS.__setitem__(key, str(value))
        sys.modules["model.SiteSetting"] = mod


_install_stubs()

from services.scraped_retention import (  # noqa: E402
    DEFAULT_MAX_AGE_HOURS,
    DEFAULT_METADATA_DAYS,
    MAX_AGE_SETTING,
    METADATA_SETTING,
    content_cutoff,
    is_within_window,
    max_age_hours,
    metadata_cutoff,
    metadata_retention_days,
)


class RetentionDefaultsTest(unittest.TestCase):
    def setUp(self):
        _SETTINGS.clear()

    def test_defaults_are_24_hours_and_30_days(self):
        self.assertEqual(DEFAULT_MAX_AGE_HOURS, 24)
        self.assertEqual(DEFAULT_METADATA_DAYS, 30)
        self.assertEqual(max_age_hours(), 24)
        self.assertEqual(metadata_retention_days(), 30)

    def test_settings_override_the_defaults(self):
        _SETTINGS[MAX_AGE_SETTING] = "72"
        _SETTINGS[METADATA_SETTING] = "7"
        self.assertEqual(max_age_hours(), 72)
        self.assertEqual(metadata_retention_days(), 7)

    def test_zero_disables_rather_than_purging_everything(self):
        # The dangerous misreading: 0 must mean "no age limit", never
        # "cutoff = now", which would purge the entire archive on one save.
        _SETTINGS[MAX_AGE_SETTING] = "0"
        self.assertEqual(max_age_hours(), 0)
        self.assertIsNone(content_cutoff())
        _SETTINGS[METADATA_SETTING] = "0"
        self.assertIsNone(metadata_cutoff())

    def test_garbage_falls_back_to_the_default(self):
        for bad in ("", "   ", "abc", "None"):
            _SETTINGS[MAX_AGE_SETTING] = bad
            self.assertEqual(max_age_hours(), DEFAULT_MAX_AGE_HOURS, bad)

    def test_absurd_values_are_clamped_not_accepted(self):
        # A window of minutes would purge threads faster than they import.
        _SETTINGS[MAX_AGE_SETTING] = "999999"
        self.assertLessEqual(max_age_hours(), 24 * 365)


class WindowTest(unittest.TestCase):
    def setUp(self):
        _SETTINGS.clear()

    def test_recent_thread_is_inside_the_window(self):
        now = _datetime.datetime(2026, 7, 27, 12, 0, 0)
        recent = now - _datetime.timedelta(hours=2)
        self.assertTrue(is_within_window(recent, now=now))

    def test_thread_older_than_the_window_is_outside(self):
        now = _datetime.datetime(2026, 7, 27, 12, 0, 0)
        stale = now - _datetime.timedelta(hours=30)   # default window is 24h
        self.assertFalse(is_within_window(stale, now=now))

    def test_boundary_is_inclusive(self):
        now = _datetime.datetime(2026, 7, 27, 12, 0, 0)
        exactly = now - _datetime.timedelta(hours=24)
        self.assertTrue(is_within_window(exactly, now=now))

    def test_unknown_timestamp_is_kept_not_purged(self):
        # "We don't know how old it is" is not evidence that it is stale.
        # Treating None as stale would purge every source that reports no dates.
        self.assertTrue(is_within_window(None))

    def test_everything_is_kept_when_the_window_is_disabled(self):
        _SETTINGS[MAX_AGE_SETTING] = "0"
        ancient = _datetime.datetime(2001, 1, 1)
        self.assertTrue(is_within_window(ancient))


if __name__ == "__main__":
    unittest.main()
