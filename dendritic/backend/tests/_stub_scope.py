"""Install a sys.modules stub for the duration of ONE test, then put back what
was there.

WHY THIS EXISTS. 36 test modules install fake modules into sys.modules at
import time and most never remove them. pytest imports every test module during
COLLECTION, so whichever landed first silently replaced `shared` or `model.*`
for every module collected after it -- and the modules disagree about what a
`shared` stub contains. Some supply db.Model and app.config for import-time
model definitions; others supply only db.session, backed by a recorder the test
then inspects. A module that piggybacks on the wrong one fails for a reason
that names neither the stub nor its installer.

The two working patterns already in the tree are: restore IMMEDIATELY after the
import that needed the stub (tests/test_admin_nav.py), or hold it for the whole
module and restore in tearDownModule (tests/test_compute_cluster.py). This is
the third case -- a stub built PER TEST, because it carries a recorder that test
reads afterwards, which cannot be shared with anything.

Restoring at the wrong moment does not fail loudly: it silently removes a stub
the tests still need, which is what cost test_dht_object_purge 25 tests when it
was tried there. Hence per-test scoping via addCleanup rather than a module-wide
teardown.
"""
import contextlib
import importlib
import sys

_ABSENT = object()


def _restore(name, previous):
    if previous is _ABSENT:
        sys.modules.pop(name, None)
    else:
        sys.modules[name] = previous


def install(test_case, modules):
    """modules: {name: module}. Restored when this test finishes."""
    for name, module in modules.items():
        previous = sys.modules.get(name, _ABSENT)
        test_case.addCleanup(_restore, name, previous)
        sys.modules[name] = module


class ModuleScoped(object):
    """Hold stubs for one test MODULE's run, then put back what was there.

    For files whose tests need the stub while they RUN, not merely while the
    module imports -- so an immediate restore (test_admin_nav's pattern) would
    take it away too early. Installed from setUpModule and dropped in
    tearDownModule, which is test_compute_cluster's pattern.

    Deferring installation from import time to setUpModule is the point: pytest
    imports every test module during COLLECTION, so a stub installed at import
    time is live while every OTHER module is collected. Installed in
    setUpModule it exists only while this module's own tests run.
    """

    def __init__(self):
        self._saved = {}

    def protect(self, *names):
        """Remember what sys.modules holds for these names, then get out of the
        way so the module's existing installer can plant its stubs.

        Saving rather than planting, because the installers in these files
        already know what their stubs must contain -- rewriting five of them to
        return dictionaries would be a larger edit than the defect warrants, and
        the thing that was wrong was never WHAT they installed.
        """
        for name in names:
            self._saved[name] = sys.modules.get(name, _ABSENT)

    def install(self, factory):
        """factory() -> {name: module}. Called once, at setUpModule time."""
        for name, module in factory().items():
            self._saved[name] = sys.modules.get(name, _ABSENT)
            sys.modules[name] = module

    def restore(self):
        for name, previous in self._saved.items():
            _restore(name, previous)
        self._saved.clear()


@contextlib.contextmanager
def real_module(name):
    """Make sys.modules[name] the module from DISK for this block, then put
    back whatever was there.

    For the other side of the leak: a test that needs the REAL module while 36
    others are busy replacing it. test_slip_deletion is the case -- it derives
    the set of tables referencing `slip` from `shared.db.metadata`, and a
    MagicMock stub answers every attribute, so the derivation silently produced
    nothing instead of failing.

    A hand-built types.ModuleType has no __file__ and a module imported from
    disk does, which is what tells the two apart. Nothing else here is
    reliable: a stub can carry any attribute it likes, including __name__.

    Restoring rather than leaving the real module in place, because the modules
    that installed a stub may still need it while THEIR tests run -- swapping
    it out permanently would just move the breakage.
    """
    previous = sys.modules.get(name, _ABSENT)
    current = sys.modules.get(name)
    if current is not None and getattr(current, "__file__", None) is None:
        del sys.modules[name]
    try:
        yield importlib.import_module(name)
    finally:
        _restore(name, previous)
