"""Downloadable node binaries: the ways a download could betray the person who ran it.

This is the one feature on the site that ends with somebody executing a file on
their own machine. So the tests are about the claims made to them at that moment:

  * the published hash is of a thing they can actually compare against;
  * the file they get is the file the platform they picked can run;
  * the configuration built from their choices matches what they chose, and
    does not quietly enable something they did not ask for.
"""

import ast
import io
import json
import os
import pathlib
import sys
import unittest
import zipfile

BACKEND = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _load_pure(relative_path, wanted, extra=None):
    """Exec only the named definitions, skipping module-level app imports."""
    source = (pathlib.Path(BACKEND) / relative_path).read_text()
    tree = ast.parse(source)
    keep = [node for node in tree.body
            if (isinstance(node, ast.Assign)
                and {t.id for t in node.targets if isinstance(t, ast.Name)} & wanted)
            or (isinstance(node, ast.FunctionDef) and node.name in wanted)]
    module = ast.Module(body=keep, type_ignores=[])
    ast.fix_missing_locations(module)
    namespace = dict(extra or {})
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


RELEASE = _load_pure(
    "services/node_release.py",
    {"PLATFORMS", "ROLES", "binary_name", "detect_platform", "executable_platform",
     "build_config", "bundle", "_verify_text", "_build_command",
     "_base_archive", "_BASE_ARCHIVES", "_BASE_ARCHIVE_LIMIT", "_pinned_wallet",
     "_coordinator_key"},
    extra={"io": io, "os": os, "json": json},
)

# The one thing _load_pure cannot isolate: _pinned_wallet reaches into the app's
# model layer at CALL time (`from model.Slip import ...`), so what it returns
# depends on whether that import happens to succeed in this process. It used to
# fail here, and the config therefore carried an empty wallet -- but only by
# accident, because another test module replaces `flask` with a stub and left it
# replaced, so model.Slip could not import. The moment any test imported the real
# flask first, model.Slip loaded against a MagicMock `shared`, the wallet became
# a MagicMock and json.dumps of the bundle's config.json failed.
#
# Pinned deterministically instead, and restored afterwards so the stub does not
# become the next module's surprise.
_SAVED_SLIP = None
PINNED_WALLET = "0x00000000000000000000000000000000deadbeef"


def setUpModule():
    global _SAVED_SLIP
    import types

    _SAVED_SLIP = sys.modules.get("model.Slip")
    stub = types.ModuleType("model.Slip")
    stub.configured_admin_wallet_address = lambda: PINNED_WALLET
    sys.modules["model.Slip"] = stub


def tearDownModule():
    if _SAVED_SLIP is None:
        sys.modules.pop("model.Slip", None)
    else:
        sys.modules["model.Slip"] = _SAVED_SLIP


def _elf(machine):
    """A minimal ELF header carrying an e_machine — enough for the sniffer."""
    head = bytearray(64)
    head[0:4] = b"\x7fELF"
    head[4] = 2          # 64-bit
    head[5] = 1          # little-endian
    head[18] = machine & 0xFF
    head[19] = (machine >> 8) & 0xFF
    return bytes(head)


def _macho(cputype):
    return b"\xcf\xfa\xed\xfe" + cputype.to_bytes(4, "little") + bytes(56)


def _pe(machine):
    head = bytearray(0x80)
    head[0:2] = b"MZ"
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    head[0x40:0x44] = b"PE\x00\x00"
    head[0x44:0x46] = machine.to_bytes(2, "little")
    return bytes(head)


class ExecutablePlatformTest(unittest.TestCase):
    """Uploading is manual and six-way. The file has to be asked what it is."""

    def test_recognises_each_platform(self):
        for body, expected in (
            (_elf(0x3E), "linux-amd64"),
            (_elf(0xB7), "linux-arm64"),
            (_macho(0x01000007), "darwin-amd64"),
            (_macho(0x0100000C), "darwin-arm64"),
            (_pe(0x8664), "windows-amd64"),
            (_pe(0xAA64), "windows-arm64"),
        ):
            self.assertEqual(RELEASE["executable_platform"](body), expected)

    def test_real_binaries_identify_themselves(self):
        """The actual builds, when they are present. Skipped if dist/ is empty.

        dist/ is gitignored, so this cannot be a required fixture — but when it
        is there it is the only test that proves the sniffer agrees with a real
        Go cross-compile rather than with a header this file wrote itself.
        """
        dist = pathlib.Path(BACKEND).parent / "dendritic-node" / "dist"
        # Exclude the sidecars a release build writes beside each binary.
        # publish-node-release.sh drops "<binary>.sha256" next to it, and the
        # bare glob matched those too -- so this test failed on any machine that
        # had ever cut a release, complaining that a checksum file is not an ELF.
        found = sorted(
            path for path in dist.glob("syndichan-node-*")
            if path.suffix not in (".sha256", ".sig", ".asc") and path.is_file()
        ) if dist.is_dir() else []
        if not found:
            self.skipTest("no built binaries in dendritic-node/dist")
        for path in found:
            expected = path.name.replace("syndichan-node-", "").replace(".exe", "")
            with self.subTest(binary=path.name):
                self.assertEqual(
                    RELEASE["executable_platform"](path.read_bytes()), expected)

    def test_rejects_what_is_not_an_executable(self):
        for body in (b"", b"x" * 10, b"#!/bin/sh\necho hi\n" + b"y" * 200,
                     b"MZ" + bytes(200), b"\x7fELF" + bytes(60)):
            self.assertIsNone(RELEASE["executable_platform"](body))

    def test_a_wrong_arch_is_not_silently_accepted(self):
        """An ELF for an architecture this project does not build is not linux-*.

        The failure this guards against is publishing an arm64 build under the
        amd64 key, which produces a file that will not start on a machine
        nobody involved can see.
        """
        self.assertIsNone(RELEASE["executable_platform"](_elf(0xF3)))  # RISC-V
        self.assertNotEqual(RELEASE["executable_platform"](_elf(0xB7)), "linux-amd64")
        self.assertNotEqual(RELEASE["executable_platform"](_elf(0x28)), "linux-arm64")

    def test_every_architecture_install_sh_can_ask_for_is_buildable(self):
        """install.sh maps `uname -m` to a name; every name must be publishable.

        The installer stops on an architecture it does not recognise, which is
        right — but a name it DOES recognise and the site cannot serve is worse
        than stopping: it is a plan that promises a download and then 404s.
        """
        keys = {"%s-%s" % (p["os"], p["arch"]) for p in RELEASE["PLATFORMS"]}
        for machine, elf in (("x86_64", 0x3E), ("aarch64", 0xB7), ("armv7l", 0x28)):
            with self.subTest(machine=machine):
                platform = RELEASE["executable_platform"](_elf(elf))
                self.assertIn(platform, keys)


class ConfigTest(unittest.TestCase):
    """A config is built from choices. It must contain those and not others."""

    def test_roles_drive_the_config(self):
        config = RELEASE["build_config"]({"roles": ["gateway"], "storage_gb": 0})
        self.assertTrue(config["gateway"]["enabled"])
        self.assertFalse(config["gateway"]["probe_enabled"])
        self.assertEqual(config["run_mode"], "gateway-only")
        self.assertTrue(config["cache_only"])

    def test_storage_capacity_is_what_was_chosen(self):
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 40})
        self.assertEqual(config["capacity_bytes"], 40 * 1024 ** 3)
        self.assertFalse(config["cache_only"])
        self.assertEqual(config["run_mode"], "storage")

    def test_unknown_roles_are_dropped_not_trusted(self):
        """Roles arrive in a query string, which anyone can write by hand."""
        config = RELEASE["build_config"]({"roles": ["gateway", "root", "../etc"],
                                          "storage_gb": 1})
        self.assertTrue(config["gateway"]["enabled"])
        self.assertNotIn("root", str(config.get("roles", "")))

    def test_capacity_cannot_be_absurd_or_negative(self):
        self.assertEqual(
            RELEASE["build_config"]({"storage_gb": -50})["capacity_bytes"], 0)
        self.assertLessEqual(
            RELEASE["build_config"]({"storage_gb": 10 ** 9})["capacity_bytes"],
            65536 * 1024 ** 3)

    def test_no_payout_address_still_produces_a_working_config(self):
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 5})
        self.assertNotIn("payout_address", config)
        self.assertEqual(config["capacity_bytes"], 5 * 1024 ** 3)

    def test_choosing_validator_changes_the_config(self):
        """It used to change nothing at all — a validator-only download was
        byte-identical to choosing no role, with nothing to notice it by."""
        chosen = RELEASE["build_config"]({"roles": ["validator"]})
        nothing = RELEASE["build_config"]({"roles": []})
        self.assertTrue(chosen["gateway"]["validator"]["enabled"])
        self.assertFalse(nothing["gateway"]["validator"]["enabled"])
        self.assertNotEqual(chosen, nothing)
        self.assertTrue(chosen["gateway"]["validator"]["origin_url"])

    def test_the_coordinator_key_is_pinned_at_download_time(self):
        """Until now a node read this key OUT of the bootstrap document and
        trusted it — so whoever served that document chose which key the node
        accepted for storage leases. Survivable while one host under our own
        TLS served it; not survivable once gateways do, which is the point of
        spreading it.

        Empty is tolerated: it means falling back to today's behaviour rather
        than refusing to start, so a node stays usable on an instance with no
        coordinator configured.
        """
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 1})
        bootstrap = config["bootstrap"]
        self.assertIn("coordinator_key", bootstrap)
        self.assertTrue(bootstrap["srv_name"])
        self.assertTrue(bootstrap["urls"])

    def test_bootstrap_can_be_discovered_rather_than_hardcoded(self):
        """One hardcoded host is one host that can be offline. The SRV name is
        what lets a node try another gateway instead of giving up."""
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 1})
        self.assertIn("_tcp", config["bootstrap"]["srv_name"])

    def test_the_directive_wallet_is_pinned_at_download_time(self):
        """A node that asked the origin who may replace the origin would be
        asking the thing being replaced. Whoever seized the domain would serve
        their own address next to their own directive and the check would pass.

        An empty wallet is valid and means "follow no directives" — the safe
        direction, since the node keeps pointing where it was told at install.
        """
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 1})
        directive = config["network_directive"]
        self.assertIn("wallet", directive)
        self.assertTrue(directive["sources"])

    def test_remote_directive_sources_are_https_and_local_ones_may_not_be(self):
        """Plaintext to a REMOTE host would let anyone on the path feed a node
        a document. Plaintext to 127.0.0.1 is the node talking to itself, where
        there is no path — and the node's own S3 endpoint serves plain HTTP
        unless an operator adds a certificate.

        Neither case relies on the transport for authenticity: the directive's
        authority is the wallet signature, checked whatever carried it.
        """
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 1})
        for source in config["network_directive"]["sources"]:
            with self.subTest(source=source):
                local = "127.0.0.1" in source or "localhost" in source
                self.assertTrue(source.startswith("https://") or local,
                                "%s is plaintext to a remote host" % source)

    def test_a_node_can_learn_of_a_move_without_the_origin(self):
        """The whole point of the second source. If every source runs through
        the domain, the only way to hear that the domain is gone is to ask it.
        """
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 1})
        sources = config["network_directive"]["sources"]
        self.assertTrue(any("127.0.0.1" in source for source in sources),
                        "no source survives losing the domain: %s" % sources)

    def test_external_verification_starts_off(self):
        """A fresh node must not announce itself as verified before it is.

        Turning this on at install time would have every new gateway publish a
        registration it cannot yet satisfy, which is how one of them ended up
        registering and unregistering in a loop.
        """
        config = RELEASE["build_config"]({"roles": ["gateway", "probe"]})
        self.assertFalse(config["gateway"]["external_verification"]["enabled"])
        self.assertTrue(config["gateway"]["probe_enabled"])


class BundleTest(unittest.TestCase):
    """What lands on somebody's disk."""

    PLATFORM = {"os": "linux", "arch": "amd64", "label": "Linux", "suffix": ""}

    def setUp(self):
        RELEASE["_BASE_ARCHIVES"].clear()

    def _bundle(self, body=b"\x7fELF-pretend-binary", config=None, digest="a" * 64):
        return RELEASE["bundle"](self.PLATFORM, body, config or {"run_mode": "storage"},
                                 digest, "go1.25.12")

    def test_the_binary_is_actually_compressed(self):
        """A hand-made ZipInfo defaults to STORED and silently ignores the
        archive's ZIP_DEFLATED, which shipped 30 MB where 11 MB would do.

        Asserted on the member's own compress_type rather than on output size,
        because a short test payload compresses unpredictably and the defect is
        a flag, not a ratio.
        """
        with zipfile.ZipFile(io.BytesIO(self._bundle(b"\x7fELF" + b"A" * 4096))) as archive:
            for member in archive.infolist():
                with self.subTest(member=member.filename):
                    self.assertEqual(member.compress_type, zipfile.ZIP_DEFLATED)

    def test_the_compressed_binary_is_reused_across_downloads(self):
        """Deflating 30 MB takes over a second of C-level CPU, which in a gevent
        worker stalls every other greenlet behind one person's download. The
        binary is identical for everyone, so it is compressed once.
        """
        self._bundle(b"\x7fELF" + b"A" * 4096)
        self._bundle(b"\x7fELF" + b"A" * 4096, config={"run_mode": "gateway-only"})
        self.assertEqual(len(RELEASE["_BASE_ARCHIVES"]), 1)

    def test_the_cache_stays_bounded(self):
        """Six platforms held at once would be a resident cost nobody chose."""
        for index in range(5):
            self._bundle(b"\x7fELF" + bytes([index]) * 512, digest=str(index) * 64)
        self.assertLessEqual(len(RELEASE["_BASE_ARCHIVES"]),
                             RELEASE["_BASE_ARCHIVE_LIMIT"])

    def test_two_platforms_do_not_get_each_others_binaries(self):
        """The cache is keyed by the binary's hash, which is what distinguishes
        them — keying it by anything else would hand a macOS download to
        somebody on Windows and still pass every other test here.
        """
        first = self._bundle(b"\x7fELF-one", digest="1" * 64)
        second = self._bundle(b"\x7fELF-two", digest="2" * 64)
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertEqual(archive.read("syndichan-node-linux-amd64"), b"\x7fELF-one")
        with zipfile.ZipFile(io.BytesIO(second)) as archive:
            self.assertEqual(archive.read("syndichan-node-linux-amd64"), b"\x7fELF-two")

    def test_contains_binary_config_and_instructions(self):
        with zipfile.ZipFile(io.BytesIO(self._bundle())) as archive:
            names = archive.namelist()
        for expected in ("syndichan-node-linux-amd64", "config.json",
                         "VERIFY.txt", "README.txt"):
            self.assertIn(expected, names)

    def test_a_linux_download_can_be_run_every_supported_way(self):
        """One config.json is only correct for running the binary by hand.

        A container cannot reach 127.0.0.1:7656, so shipping a single config
        beside a list of run methods means everyone using Docker hits the same
        failure and works out the same fix.
        """
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 10})
        with zipfile.ZipFile(io.BytesIO(self._bundle(config=config))) as archive:
            names = archive.namelist()
            docker = json.loads(archive.read("docker/config.json"))
            host = json.loads(archive.read("config.json"))
        for expected in ("systemd/syndichan-node.service", "systemd/install.sh",
                         "docker/Dockerfile", "docker/docker-compose.yml",
                         "docker/config.json"):
            self.assertIn(expected, names)
        self.assertEqual(host["i2p_sam"], "127.0.0.1:7656")
        self.assertEqual(docker["i2p_sam"], "i2pd:7656")
        # Binding 127.0.0.1 inside a container publishes to nothing; the compose
        # port mapping is what keeps the dashboard host-only.
        self.assertTrue(docker["ui_listen"].startswith("0.0.0.0"))

    def test_docker_files_ship_only_with_a_linux_build(self):
        """An image needs a Linux binary. Shipping compose beside a .exe would
        describe something the archive cannot build."""
        windows = {"os": "windows", "arch": "amd64", "label": "Windows",
                   "suffix": ".exe"}
        archive_bytes = RELEASE["bundle"](windows, b"MZ-pretend", {"run_mode": "storage"},
                                          "f" * 64, "go1.25.12")
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            names = archive.namelist()
        self.assertIn("windows/install.ps1", names)
        self.assertFalse([n for n in names if n.startswith("docker/")])
        self.assertFalse([n for n in names if n.startswith("systemd/")])

    def test_a_gateway_unit_can_actually_bind_443(self):
        """Without the capability, systemd starts it as an unprivileged user
        and it fails on the one port the role exists to serve."""
        config = RELEASE["build_config"]({"roles": ["gateway"]})
        with zipfile.ZipFile(io.BytesIO(self._bundle(config=config))) as archive:
            unit = archive.read("systemd/syndichan-node.service").decode()
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)
        # config.json is read from the working directory, so this is load-bearing.
        self.assertIn("WorkingDirectory=", unit)

    def test_a_storage_only_unit_gets_no_extra_capability(self):
        config = RELEASE["build_config"]({"roles": ["storage"], "storage_gb": 10})
        with zipfile.ZipFile(io.BytesIO(self._bundle(config=config))) as archive:
            unit = archive.read("systemd/syndichan-node.service").decode()
        self.assertNotIn("CAP_NET_BIND_SERVICE", unit)

    def test_the_readme_names_the_roles_the_config_actually_has(self):
        """Read back out of the config, so it describes the file rather than
        the request — that is what makes it checkable."""
        config = RELEASE["build_config"]({"roles": ["validator"]})
        with zipfile.ZipFile(io.BytesIO(self._bundle(config=config))) as archive:
            readme = archive.read("README.txt").decode()
        self.assertIn("validator", readme)
        self.assertNotIn("no role selected", readme)

    def test_binary_is_executable(self):
        """Otherwise the first thing every Linux and macOS user hits is chmod."""
        with zipfile.ZipFile(io.BytesIO(self._bundle())) as archive:
            info = archive.getinfo("syndichan-node-linux-amd64")
            self.assertTrue((info.external_attr >> 16) & 0o111)

    def test_verify_text_names_the_binary_hash_not_the_archive(self):
        """The whole point: a per-person archive's hash cannot be checked.

        If VERIFY.txt ever tells somebody to hash the zip, it is instructing
        them to compare a value that matches nobody else's download against a
        published value it can never equal.
        """
        with zipfile.ZipFile(io.BytesIO(self._bundle())) as archive:
            text = archive.read("VERIFY.txt").decode()
        self.assertIn("a" * 64, text)
        self.assertIn("syndichan-node-linux-amd64", text)
        self.assertIn("Check the BINARY, not this archive", text)
        self.assertNotIn(".zip", text)

    def test_verify_text_admits_the_toolchain_matters(self):
        """A mismatch from a different Go version is not evidence of tampering.

        Telling people to rebuild and compare, without saying that, manufactures
        false alarms about the one thing they were asked to be careful about.
        """
        with zipfile.ZipFile(io.BytesIO(self._bundle())) as archive:
            text = archive.read("VERIFY.txt").decode()
        self.assertIn("go1.25.12", text)
        self.assertIn("-trimpath", text)
        self.assertIn("reproducible for a given compiler version", text)

    def test_config_is_the_one_that_was_built(self):
        import json

        config = RELEASE["build_config"]({"roles": ["gateway"], "storage_gb": 12,
                                          "payout": "0xabc"})
        with zipfile.ZipFile(io.BytesIO(self._bundle(config=config))) as archive:
            written = json.loads(archive.read("config.json"))
        self.assertEqual(written["payout_address"], "0xabc")
        self.assertEqual(written["capacity_bytes"], 12 * 1024 ** 3)

    def test_archives_are_reproducible_for_the_same_choices(self):
        """No timestamp of the moment somebody clicked.

        A zip that embeds the download time is a different file for every
        request, which makes the archive unhashable in exactly the way the
        binary is not — and invites someone to try comparing it anyway.
        """
        self.assertEqual(self._bundle(), self._bundle())


class DetectPlatformTest(unittest.TestCase):
    """A guess, and it must present itself as one."""

    def test_common_agents(self):
        cases = [
            ("Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "windows", "amd64"),
            ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "darwin", "amd64"),
            ("Mozilla/5.0 (X11; Linux x86_64)", "linux", "amd64"),
            ("Mozilla/5.0 (X11; Linux aarch64)", "linux", "arm64"),
        ]
        for agent, expected_os, expected_arch in cases:
            with self.subTest(agent=agent):
                guess = RELEASE["detect_platform"](agent)
                self.assertEqual(guess["os"], expected_os)
                self.assertEqual(guess["arch"], expected_arch)

    def test_never_claims_confidence(self):
        """User agents are frozen, lie, and omit CPU architecture entirely.

        Any caller that treats the guess as known would download the wrong
        binary for a real fraction of visitors, on machines nobody can inspect.
        """
        for agent in ("", None, "curl/8.0", "Mozilla/5.0 (Windows NT 10.0)"):
            self.assertFalse(RELEASE["detect_platform"](agent)["confident"])

    def test_always_returns_a_buildable_platform(self):
        keys = {(p["os"], p["arch"]) for p in RELEASE["PLATFORMS"]}
        for agent in ("", "nonsense", "Mozilla/5.0 (SomethingNew)", "Android 14"):
            guess = RELEASE["detect_platform"](agent)
            self.assertIn((guess["os"], guess["arch"]), keys)


class RolesTest(unittest.TestCase):
    def test_port_requiring_roles_say_so(self):
        """The page's warning is generated from this, not written twice."""
        roles = RELEASE["ROLES"]
        self.assertTrue(roles["gateway"]["needs_port"])
        self.assertTrue(roles["probe"]["needs_port"])
        self.assertFalse(roles["storage"]["needs_port"])
        self.assertFalse(roles["validator"]["needs_port"])

    def test_every_role_explains_itself(self):
        for name, role in RELEASE["ROLES"].items():
            with self.subTest(role=name):
                self.assertTrue(role["label"])
                self.assertGreater(len(role["summary"]), 40)


if __name__ == "__main__":
    unittest.main()


class MonitorRoleTest(unittest.TestCase):
    """The monitor role, and the cross-language contract it depends on.

    The config this generates is parsed by a Go struct in another repository.
    Nothing checks that they agree at build time, and a key that drifts does not
    fail loudly — Go silently leaves the field at its zero value, so a monitor
    would quietly never probe and the status page would show "no data" forever
    while every machine involved reported success.
    """

    GO_MONITOR_KEYS = {"enabled", "targets_url", "report_url", "interval_seconds"}

    def build(self, roles, storage_gb=0):
        return RELEASE["build_config"]({"roles": roles, "storage_gb": storage_gb})

    def test_the_config_keys_match_the_go_struct_exactly(self):
        block = self.build(["monitor"])["monitor"]
        self.assertEqual(set(block), self.GO_MONITOR_KEYS)

    def test_choosing_the_role_switches_it_on(self):
        self.assertTrue(self.build(["monitor"])["monitor"]["enabled"])

    def test_not_choosing_it_leaves_it_off(self):
        # A node upgraded to a version that knows about monitoring must not
        # start making scheduled outbound requests nobody asked for.
        self.assertFalse(self.build(["storage"], storage_gb=10)["monitor"]["enabled"])

    def test_the_config_carries_no_board_serving_fields(self):
        # The page lives at /status on the main site, not on a subdomain, so
        # there is nothing for a node to host. A leftover key here would be a
        # promise the client no longer reads and nothing would ever honour.
        block = self.build(["monitor", "gateway"])["monitor"]
        self.assertNotIn("serves_status", block)
        self.assertNotIn("board_url", block)

    def test_the_role_is_offered_and_needs_no_port(self):
        roles = RELEASE["ROLES"]
        self.assertIn("monitor", roles)
        self.assertFalse(roles["monitor"]["needs_port"])
