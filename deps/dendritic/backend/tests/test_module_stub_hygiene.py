"""A ratchet on test modules that replace real modules and never put them back.

WHAT THIS GUARDS
----------------
Nine test modules contain some form of

    sys.modules["shared"] = <a MagicMock-backed stand-in>

installed at import time and never removed. pytest imports every test module
during COLLECTION, before any test runs, so whichever module sorts first
silently replaces `shared` or `model.*` for every module collected after it.
Test order therefore changes behaviour, which means a green run is weaker
evidence than it looks.

This is not hypothetical and it is not cheap. The stub in test_admin_nav carried
`db` and `app` and nothing else, so anything imported later doing
`from shared import db, db_retry` -- board_access does, and blueprints/admin
imports board_access -- failed with an ImportError naming neither the stub nor
its installer. Because a collection error is FATAL, that one leak took down the
entire suite: roughly 1,800 passing tests never executed, and the failures they
would have caught were invisible. Four production defects were sitting behind it,
including a page returning 500 and account deletion that could see 16 of the 61
tables referencing slip.id.

WHY A RATCHET AND NOT A FIX
---------------------------
Converting the rest is per-module work, not a sweep: some need the stub
only while their imports run and can restore immediately (test_admin_nav now
does), while others need it for the duration of their tests because the code
under test imports lazily, and must restore in tearDownModule instead
(test_compute_cluster is the model). Restoring at the wrong moment breaks the
file -- that was tried on test_dht_object_purge and cost it 25 tests.

So this asserts the number cannot GROW. A new test module that leaks fails here
immediately, with the pattern to copy. Every conversion lowers BASELINE by one,
and the item is done when it reaches zero.
"""

import glob
import os
import re
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))

# Lower this as modules are converted. It must never be raised.
BASELINE = 7

# Restoration shows up in several shapes and the first version of this file
# missed most of them, counting 35 leakers when the real number is lower.
# test_csrf_protection saves into `self._saved` and puts it back in tearDown --
# entirely correct, and invisible to a detector looking only for module-level
# markers. A ratchet built on an inflated baseline is worse than none: it leaves
# headroom for real leaks to appear while the number still looks like progress.
_RESTORE_MARKERS = (
    "tearDownModule",       # module-level teardown (test_compute_cluster)
    "tearDown",             # per-test teardown (test_csrf_protection)
    "addCleanup",           # unittest's cleanup registry
    "SAVED", "_saved",      # the usual names for the saved originals
    "_restore_stubs", "_restore_stubbed_modules",
    "sys.modules.pop",      # explicit removal
)


def _leaking_modules():
    """Test modules that assign into sys.modules with no sign of restoring it.

    Deliberately a TEXT check rather than a runtime one: the assignment happens
    at import time, so by the time anything could observe it at runtime the
    damage is already in sys.modules and attributing it to a file is guesswork.
    """
    out = []
    for path in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        with open(path, "r", encoding="utf-8") as handle:
            source = handle.read()
        if not re.search(r"sys\.modules\[[^\]]+\]\s*=", source):
            continue
        if any(marker in source for marker in _RESTORE_MARKERS):
            continue
        out.append(os.path.basename(path))
    return out


class ModuleStubHygieneTest(unittest.TestCase):
    def test_the_number_of_leaking_modules_never_grows(self):
        leaking = _leaking_modules()
        self.assertLessEqual(
            len(leaking), BASELINE,
            "A test module now replaces a real module in sys.modules without "
            "restoring it, taking the count from %d to %d. Whichever module "
            "sorts first then changes `shared` or `model.*` for every module "
            "collected after it, and an incomplete stub turns that into a "
            "collection error, which is fatal to the WHOLE run.\n\n"
            "Copy one of the two working patterns: restore immediately after "
            "the imports that needed the stub (tests/test_admin_nav.py), or "
            "save in setUpModule and restore in tearDownModule "
            "(tests/test_compute_cluster.py).\n\nLeaking now:\n  %s"
            % (BASELINE, len(leaking), "\n  ".join(leaking)))

    def test_the_baseline_is_lowered_when_modules_are_fixed(self):
        """Keeps BASELINE honest, so a fixed module is banked rather than
        leaving headroom for a new leak to slip in unnoticed."""
        leaking = _leaking_modules()
        self.assertEqual(
            len(leaking), BASELINE,
            "%d modules leak but BASELINE says %d. If you fixed some, lower "
            "BASELINE to %d so the improvement is locked in."
            % (len(leaking), BASELINE, len(leaking)))
