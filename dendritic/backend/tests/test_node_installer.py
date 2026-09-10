"""The one-line installer: `curl -fsSL https://syndichan.org/install.sh | sh`.

This is the only thing the site publishes that ends with a stranger running a
downloaded executable as root. Everything asserted here is a property somebody
is trusting when they paste that line:

  * the script is actually reachable at the URL the line names, and readable in
    a browser rather than dumped as a download;
  * it parses in the shells it claims to support, including the one Alpine has;
  * every architecture it is willing to install for is one the site can serve,
    so a machine it recognises never gets a 404 halfway through;
  * it checks what it downloaded, and stops if the check fails;
  * the readiness probe talks to the SAM bridge and not to a router console,
    which is the difference between a node that starts and one that dies.

The shell script is checked as text and with `sh -n`, because there is no way to
run the install side of it in a test: it wants root, a package manager, an I2P
router and a network.
"""

import ast
import contextlib
import importlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import unittest

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

INSTALLER = pathlib.Path(BACKEND) / "static" / "install.sh"

# What install.sh maps `uname -m` to, and what the site therefore has to be able
# to serve. Kept here rather than derived from the script so that changing the
# script alone cannot make this test agree with it by accident.
ARCH_MAP = {
    "x86_64": "amd64", "amd64": "amd64",
    "aarch64": "arm64", "arm64": "arm64",
    "armv6l": "arm", "armv7l": "arm", "armv8l": "arm",
}


def installer_source():
    return INSTALLER.read_text()


def code_only(source):
    """The script with its comment lines removed.

    Several assertions here are "this string must not appear", and every one of
    those strings appears in a comment explaining why it must not appear.
    """
    return "\n".join(line for line in source.splitlines()
                      if not line.strip().startswith("#"))


def linux_arches():
    """PLATFORMS out of services/node_release.py without importing the app.

    `from shared import app` at the top of that module pulls in the database and
    every extension; the same AST trick tests/test_node_release.py uses keeps
    this to the one constant that matters.
    """
    source = (pathlib.Path(BACKEND) / "services" / "node_release.py").read_text()
    for node in ast.parse(source).body:
        if isinstance(node, ast.Assign) and any(
                getattr(target, "id", None) == "PLATFORMS" for target in node.targets):
            platforms = ast.literal_eval(node.value)
            return {p["arch"] for p in platforms if p["os"] == "linux"}
    raise AssertionError("node_release.py has no PLATFORMS")


@contextlib.contextmanager
def real_flask():
    """The installed Flask, even when another test has left a stub in sys.modules.

    tests/test_codeplay.py installs a fake `flask` module so code-runner's
    runner.py can be imported, via sys.modules.setdefault — so it wins whenever
    it happens to run before anything has imported the real package, which
    depends on the order pytest chose. Routing cannot be proved against a stub
    whose Flask has no url_map.

    A context manager rather than a function because Flask imports parts of
    itself lazily: `test_client()` reaches for flask.testing on first use, and
    restoring the stub before then turns that into "flask is not a package".
    """
    existing = sys.modules.get("flask")
    if existing is not None and hasattr(existing, "__path__"):
        yield existing          # already the real thing; touch nothing
        return

    before = {name: module for name, module in sys.modules.items()
              if name == "flask" or name.startswith("flask.")}
    for name in before:
        del sys.modules[name]
    try:
        yield importlib.import_module("flask")
    finally:
        for name in [n for n in sys.modules
                     if n == "flask" or n.startswith("flask.")]:
            del sys.modules[name]
        sys.modules.update(before)


class ItIsServedTest(unittest.TestCase):
    """https://syndichan.org/install.sh has to resolve, with no route to add.

    The app is created with static_url_path='', which mounts static/ at the
    domain root — so a file dropped in backend/static IS the published URL. That
    is load-bearing and invisible, hence a test: a later `Flask(__name__)`
    without that argument would move every static asset under /static/ and turn
    the published install line into a 404 without touching this file.
    """

    def test_the_root_static_mount_serves_the_installer(self):
        with real_flask() as flask:
            app = flask.Flask("installer-mount-check", static_url_path="",
                              static_folder=str(INSTALLER.parent))
            response = app.test_client().get("/install.sh")
            self.assertEqual(200, response.status_code)
            self.assertEqual(installer_source().encode(), response.get_data())

    def test_the_app_is_still_mounted_at_the_root(self):
        source = (pathlib.Path(BACKEND) / "shared.py").read_text()
        self.assertIn("static_url_path=''", source)

    def test_shell_scripts_are_served_as_readable_text(self):
        """text/plain, not the guessed text/x-sh.

        Anybody sensible opens a `curl … | sh` script before running it. With
        text/x-sh a browser offers a download instead of showing the file, which
        turns "read it first" into a chore most people will skip.
        """
        source = (pathlib.Path(BACKEND) / "shared.py").read_text()
        self.assertRegex(source, r'mimetypes\.add_type\(\s*"text/plain",\s*"\.sh"\s*\)')


class BinaryRouteTest(unittest.TestCase):
    """/dl/<binary> and /dl/<binary>.sha256, the two URLs the script hardcodes."""

    def rule(self):
        """The route string as actually written on main.download_node_binary."""
        source = (pathlib.Path(BACKEND) / "blueprints" / "main.py").read_text()
        tree = ast.parse(source)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name == "download_node_binary":
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and decorator.args:
                        return ast.literal_eval(decorator.args[0])
        self.fail("main.py has no download_node_binary route")

    def test_the_rule_matches_both_shapes(self):
        with real_flask() as flask:
            app = flask.Flask("dl-route-check")
            app.add_url_rule(self.rule(), "dl", lambda name: name)
            adapter = app.url_map.bind("syndichan.org")
            for path, name in (
                ("/dl/syndichan-node-linux-amd64", "syndichan-node-linux-amd64"),
                ("/dl/syndichan-node-linux-arm64.sha256",
                 "syndichan-node-linux-arm64.sha256"),
                ("/dl/syndichan-node-linux-arm.sha256",
                 "syndichan-node-linux-arm.sha256"),
            ):
                with self.subTest(path=path):
                    endpoint, args = adapter.match(path)
                    self.assertEqual("dl", endpoint)
                    self.assertEqual(name, args["name"])

    def test_the_root_static_mount_does_not_swallow_it(self):
        """static_url_path='' registers /<path:filename> over the whole domain.

        That is what serves /install.sh, and it is also a catch-all that /dl/
        has to beat. Werkzeug weights an explicit rule above a converter, but
        "it should" is not a thing to find out from a 404 on somebody's Pi.
        """
        with real_flask() as flask:
            app = flask.Flask("shadow-check", static_url_path="",
                              static_folder=str(INSTALLER.parent))
            app.add_url_rule(self.rule(), "dl", lambda name: name)
            adapter = app.url_map.bind("syndichan.org")
            self.assertEqual("dl", adapter.match("/dl/syndichan-node-linux-amd64")[0])
            self.assertEqual("static", adapter.match("/install.sh")[0])

    def test_the_script_asks_for_exactly_that(self):
        source = installer_source()
        self.assertIn('BIN_URL="$BASE_URL/dl/$BINARY"', source)
        self.assertIn('SUM_URL="$BASE_URL/dl/$BINARY.sha256"', source)
        self.assertIn('BINARY="syndichan-node-linux-$ARCH"', source)

    def test_the_checksum_is_served_in_a_checkable_format(self):
        """`<hex>  <name>` is sha256sum's own format.

        Serving a bare hash would mean an operator verifying by hand has to
        assemble the line themselves, and `sha256sum -c` on the file as served
        would not work at all.
        """
        source = (pathlib.Path(BACKEND) / "blueprints" / "main.py").read_text()
        body = source[source.index("def download_node_binary"):]
        body = body[:body.index("\n@main_blueprint")]
        self.assertIn('"%s  %s\\n" % (entry["sha256"], wanted)', body)


class ArchitectureTest(unittest.TestCase):
    def test_every_arch_the_script_accepts_can_be_published(self):
        """A recognised machine must never reach a 404.

        Stopping on an unknown architecture is correct. Accepting one the site
        cannot serve is worse than stopping: the plan promises a download, the
        operator consents, and the failure lands after they have said yes.
        """
        buildable = linux_arches()
        for machine, arch in ARCH_MAP.items():
            with self.subTest(machine=machine):
                self.assertIn(arch, buildable)

    def test_the_script_maps_those_machines_and_stops_on_the_rest(self):
        source = installer_source()
        case = source[source.index('case "$MACHINE" in'):]
        case = case[:case.index("esac")]
        for machine in ARCH_MAP:
            with self.subTest(machine=machine):
                self.assertIn(machine, case)
        # The catch-all must die, not default to amd64.
        self.assertRegex(case, r'\*\)\s*die ')


class ShellTest(unittest.TestCase):
    """It has to parse where it has to run, which includes Alpine's busybox ash."""

    def shells(self):
        found = [name for name in ("sh", "dash", "bash") if shutil.which(name)]
        if shutil.which("busybox"):
            found.append("busybox ash")
        return found

    def test_it_parses(self):
        shells = self.shells()
        self.assertTrue(shells, "no POSIX shell to check with")
        for shell in shells:
            with self.subTest(shell=shell):
                result = subprocess.run(shell.split() + ["-n", str(INSTALLER)],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(0, result.returncode, result.stderr)

    def test_it_stays_posix(self):
        """The constructs busybox ash accepts at parse time and then mishandles.

        `sh -n` catches syntax, not semantics: `local`, arrays and /dev/tcp all
        parse and then behave differently or not at all. The installer's whole
        reason for being one file instead of a bash shim plus a bash script is
        that it does not use them.
        """
        source = installer_source()
        # Inside the wait-for-sam helper, /dev/tcp is used deliberately — but
        # only ever through an explicit `bash -c`, never by this script itself.
        for line in source.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            with self.subTest(line=stripped[:70]):
                self.assertNotRegex(stripped, r"^local\s")
                self.assertNotIn("[[ ", stripped)
                self.assertNotRegex(stripped, r"\w+=\(")

    def test_the_help_path_never_installs(self):
        result = subprocess.run(["sh", str(INSTALLER), "--help"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("--check", result.stdout)
        self.assertIn("curl -fsSL", result.stdout)

    def test_an_unknown_flag_is_refused_rather_than_ignored(self):
        result = subprocess.run(["sh", str(INSTALLER), "--wat"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(2, result.returncode)

    def test_a_flag_cannot_swallow_the_next_one(self):
        """`--payout --yes` must not save "--yes" as somebody's wallet address."""
        result = subprocess.run(["sh", str(INSTALLER), "--payout", "--yes"],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(2, result.returncode)
        self.assertIn("needs a value", result.stderr)


class SafetyTest(unittest.TestCase):
    """The properties that make a root-run curl|sh script defensible."""

    def test_the_download_is_verified_and_a_mismatch_stops_everything(self):
        source = installer_source()
        self.assertIn('if [ "$GOT_SHA" != "$WANT_SHA" ]; then', source)
        mismatch = source[source.index('if [ "$GOT_SHA" != "$WANT_SHA" ]'):]
        mismatch = mismatch[:mismatch.index("\n  fi")]
        self.assertIn("die ", mismatch)
        self.assertIn("CHECKSUM MISMATCH", mismatch)
        # The install must come after the check, not beside it.
        self.assertLess(source.index('if [ "$GOT_SHA" != "$WANT_SHA" ]'),
                        source.index('run install -m 0755 "$WORK/node" "$BIN_DEST"'))

    def test_a_checksum_that_is_not_a_checksum_is_not_believed(self):
        """An error page or a captive portal must not become the expected hash."""
        source = installer_source()
        self.assertIn('[ "${#WANT_SHA}" != "64" ]', source)
        self.assertIn("tr -d '0-9a-f'", source)

    def test_it_downloads_over_https_and_never_disables_verification(self):
        source = installer_source()
        self.assertIn("--proto =https --proto-redir =https", source)
        for forbidden in (" -k ", "--insecure", "--no-check-certificate"):
            self.assertNotIn(forbidden, code_only(source))

    def test_the_node_never_runs_as_root(self):
        source = installer_source()
        self.assertIn("User=$NODE_USER", source)
        self.assertIn("NoNewPrivileges=true", source)
        self.assertRegex(source, r"useradd --system|adduser -S")

    def test_consent_is_read_from_the_terminal_not_from_stdin(self):
        """Under `curl … | sh` stdin IS the script.

        A plain `read` there consumes the rest of the file: the answer is
        whatever the next line of the installer happens to be, and the install
        then runs half a script. /dev/tty is the only thing that asks a human.
        """
        source = installer_source()
        self.assertIn("read -r ANSWER </dev/tty", source)
        self.assertNotRegex(source, r"^\s*read -r ANSWER\s*$")
        # And with no terminal at all it must stop rather than assume yes.
        self.assertIn("[ -r /dev/tty ] ||", source)

    def test_check_asks_for_nothing_and_installs_nothing(self):
        source = installer_source()
        report = source.index("# REPORT, then ask")
        act = source.index("# ACT\n")
        early = source[:report]
        self.assertNotIn("install -m", early)
        self.assertNotIn("systemctl enable", early)
        # --check exits before ACT begins.
        self.assertLess(source.index('if [ "$DRY_RUN" = "1" ]; then\n  [ "$BLOCKED"'), act)


class SamReadinessTest(unittest.TestCase):
    """The lesson that cost a node every reboot: 7656, never a console port."""

    def helper(self):
        source = installer_source()
        start = source.index("cat >\"$PROBE\" <<'HELPER'")
        return source[start:source.index("\nHELPER\n", start)]

    def test_the_probe_speaks_sam_on_7656(self):
        helper = self.helper()
        self.assertIn("HELLO VERSION MIN=3.1 MAX=3.3", helper)
        self.assertIn("HELLO REPLY", helper)
        self.assertIn("RESULT=OK", helper)
        self.assertIn("127.0.0.1/7656", helper)

    def test_it_never_probes_a_router_console(self):
        """7657 (Java) and 7070 (i2pd) bind immediately; SAM can be 120s behind.

        A console check reports ready, systemd starts the node, connectSAM gets
        ECONNREFUSED and main.go calls logger.Fatal. There is no startup retry,
        so the node is simply gone until somebody looks.
        """
        helper = self.helper()
        for port in ("7657", "7070"):
            for line in helper.splitlines():
                if line.strip().startswith("#"):
                    continue
                self.assertNotIn(port, line)

    def test_localhost_is_never_used_as_a_name(self):
        """Where the resolver prefers ::1, "localhost" can reach a console on
        [::1] and miss the bridge entirely."""
        helper = self.helper()
        for line in helper.splitlines():
            if line.strip().startswith("#"):
                continue
            self.assertNotIn("localhost", line)

    def test_the_service_waits_for_it_before_starting(self):
        source = installer_source()
        self.assertIn("ExecStartPre=$WAIT_HELPER $SAM_WAIT", source)
        # Generous enough for a Java router's ~120s SAM delay on top of the wait.
        self.assertIn("TimeoutStartSec=$((SAM_WAIT + 120))", source)
        budget = re.search(r"^SAM_WAIT=(\d+)$", source, re.M)
        self.assertIsNotNone(budget)
        self.assertGreaterEqual(int(budget.group(1)), 240)

    def test_one_handshake_implementation_serves_both_uses(self):
        """Probing and waiting are the same question.

        Two copies is how one of them ends up checking the console port. The
        installer runs the helper with a budget of 0 to probe, and systemd runs
        the same installed file with a real budget.
        """
        source = installer_source()
        # The handshake string appears only inside the helper. It appears twice
        # there — once for bash /dev/tcp, once for nc — because those are two
        # ways to open a socket, not two ideas about what readiness means.
        outside = source.replace(self.helper(), "")
        self.assertNotIn("HELLO VERSION", outside)
        self.assertIn('"$PROBE" 0 >/dev/null 2>&1 || SAM_RC=$?', source)
        self.assertIn('run install -m 0755 "$PROBE" "$WAIT_HELPER"', source)


class UnitTest(unittest.TestCase):
    def unit(self):
        source = installer_source()
        start = source.index('cat >"$WORK/unit-body" <<EOF')
        return source[start:source.index("\nEOF\n", start)]

    def test_readwritepaths_names_the_data_directory_itself(self):
        """Not <dir>/storage.

        i2p.destination, p2p.key and content.key are written BESIDE storage/, so
        a unit that sandboxes only the subdirectory fails on the second file
        with a "read-only file system" error that names a filesystem which is
        mounted rw and never mentions the sandbox.
        """
        unit = self.unit()
        self.assertIn("ReadWritePaths=$RW_PATHS", unit)
        self.assertNotIn("$DATA_DIR/storage", unit)
        source = installer_source()
        self.assertIn('RW_PATHS="\\"$DATA_DIR\\""', source)

    def test_it_is_ordered_after_the_router_without_sharing_its_fate(self):
        """Requires=i2pd.service fails the node outright where the router is
        i2p.service, and takes the node down with the router on every restart."""
        unit = self.unit()
        self.assertIn("Wants=$ORDER", unit)
        self.assertIn("After=$ORDER", unit)
        self.assertNotIn("Requires=", code_only(unit))

    def test_it_is_enabled_so_the_node_survives_a_reboot(self):
        source = installer_source()
        self.assertIn("WantedBy=multi-user.target", source)
        self.assertIn("run systemctl enable syndichan-node.service", source)
        self.assertIn('run systemctl enable "$ROUTER_UNIT"', source)

    def test_a_unit_somebody_else_wrote_is_not_overwritten(self):
        """The marker carries the hash of the body it was written with.

        A prefix match alone would treat a unit somebody hand-fixed as this
        installer's own and replace their fix. The hash is what distinguishes
        "an installer wrote this and nobody has touched it" from "somebody has".
        """
        source = installer_source()
        self.assertIn('RECORDED="$(sed -n "s|^$MARKER[^=]*sha256=||p"', source)
        self.assertIn('[ "$RECORDED" = "$(sha256_of "$WORK/unit-installed")" ]', source)
        self.assertIn("if ! unit_is_ours; then", source)
        self.assertIn("NOT overwriting it", source)

    def test_the_marker_also_recognises_the_older_installers_unit(self):
        """A machine upgrading from the build-from-source installer wrote
        `# managed-by: syndichan install.sh v2 sha256=…`; the pattern has to
        accept that, or every such machine is treated as a stranger's."""
        source = installer_source()
        self.assertIn('MARKER="# managed-by: syndichan install.sh"', source)
        self.assertIn("[^=]*sha256=", source)

    def test_no_systemd_is_reported_rather_than_crashed_on(self):
        source = installer_source()
        self.assertIn("[ -d /run/systemd/system ] && have systemctl", source)
        self.assertIn("no systemd here", source)


class FinalReportTest(unittest.TestCase):
    """What the operator is left holding."""

    def test_it_prints_the_dashboard_the_password_and_the_payout_warning(self):
        source = installer_source()
        tail = source[source.index("# What the operator needs to know now"):]
        self.assertIn("Dashboard:", tail)
        self.assertIn("Password:", tail)
        self.assertIn("NO PAYOUT ADDRESS IS SET", tail)
        self.assertIn("payout_address", tail)

    def test_the_password_is_read_from_the_config_not_from_show_config(self):
        """-show-config REDACTS ui_password, deliberately: it is what people
        paste into support threads. The file is the only source."""
        source = installer_source()
        self.assertIn('UI_PASS="$(config_field ui_password)"', source)


if __name__ == "__main__":
    unittest.main()
