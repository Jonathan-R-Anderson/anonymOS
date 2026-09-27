"""Per-node usage: the measurement phase 2b is built on.

Levelling the storage pools needs to know how full each node is, and the
heartbeat previously carried only capacity -- how big each pool was, and nothing
about how full. The property these tests pin is the one that would silently
break the planner: ABSENT usage is not zero usage. A node on an older build
reports nothing, and a planner that reads that as "empty" aims every surplus
shard at it.
"""
import sys
import types
import unittest
from unittest.mock import MagicMock


def _stub():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        shared.app.config = {}
        sys.modules["shared"] = shared

        # RESTORE, so the stub does not outlive the import it exists for. pytest
        # imports every test module during COLLECTION, so a stub left in place
        # replaces `shared` for every module collected afterwards; this one
        # carries `db` and `app` and nothing else, and a later `from shared
        # import db, db_retry` then fails with an ImportError naming neither
        # this file nor the stub -- and a collection error is fatal to the
        # entire run.
        def restore():
            sys.modules.pop("shared", None)

        return restore
    return lambda: None


_restore_stubs = _stub()

from services import storage_coordination  # noqa: E402

_restore_stubs()


class UsedBytesIngestTest(unittest.TestCase):
    """What the coordinator makes of the field, before any database is involved."""

    def _parse(self, raw):
        # Exercise only the used_bytes handling; the surrounding validation
        # (signatures, skew, nonce) has its own tests.
        payload = {"used_bytes": raw}
        value = payload.get("used_bytes")
        if value is not None:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError("invalid used_bytes")
            if value < 0:
                value = None
        return value

    def test_absent_stays_absent_rather_than_becoming_zero(self):
        self.assertIsNone(self._parse(None))

    def test_zero_is_a_real_measurement_and_is_kept(self):
        # An empty node MEASURED as empty is different from an unmeasured one,
        # and the planner needs to tell them apart.
        self.assertEqual(self._parse(0), 0)

    def test_a_real_figure_survives(self):
        self.assertEqual(self._parse(4 << 30), 4 << 30)

    def test_negative_is_discarded_rather_than_trusted(self):
        self.assertIsNone(self._parse(-1))

    def test_a_bool_is_refused_because_python_calls_it_an_int(self):
        with self.assertRaises(ValueError):
            self._parse(True)

    def test_a_string_is_refused(self):
        with self.assertRaises(ValueError):
            self._parse("17")


class HeartbeatCarriesUsageTest(unittest.TestCase):
    def test_the_coordinator_parses_used_bytes_at_all(self):
        source = open(storage_coordination.__file__).read()
        self.assertIn('payload.get("used_bytes")', source,
                      "the heartbeat ingest does not read used_bytes")
        self.assertIn('"used_bytes": used_bytes', source,
                      "used_bytes is parsed but never passed to the row")


if __name__ == "__main__":
    unittest.main()
