"""Downloadable node binaries: which platform, which hash, and what config.

Someone who is about to run a program on their own machine, from a site they
have just met, deserves to be able to check it. So the hash is published, and it
is the hash of the BINARY.

WHY NOT HASH THE DOWNLOAD
-------------------------
The download is a per-person archive: the same binary plus a configuration built
from the choices they made on the page. Its hash is therefore unique to them —
and a hash nobody else can reproduce is a hash nobody can check. It would look
like verification while proving nothing.

The binary is identical for everyone on a platform. Its hash can be compared
against what every other person downloaded, against the published value, and
against a build made from source. That is a check worth offering.

So the archive contains the binary, the config, and a README that says: verify
THIS file, here is the expected value, here is the command for your platform.

WHERE THE BINARIES LIVE
-----------------------
In the object store, not in the image. They are ~30 MB each and six platforms is
180 MB — carried in every deploy, on a host that has already hit disk pressure,
for files that change only when the node is rebuilt. `dist/` is gitignored, so
they were never in the image to begin with.

The store is content-addressed, which means the key IS the hash. The thing that
has to be published and the thing that has to be looked up are the same string,
so they cannot drift apart.
"""

import hashlib
import io
import json
import os
import re

from shared import app

BUCKET = "releases"

# Platforms build-release.sh produces. Named here so the page can offer exactly
# what exists rather than guessing and 404ing after somebody has made choices.
PLATFORMS = (
    {"os": "linux", "arch": "amd64", "label": "Linux (64-bit Intel/AMD)", "suffix": ""},
    {"os": "linux", "arch": "arm64", "label": "Linux (ARM64)", "suffix": ""},
    # Built with GOARM=6 so one file covers armv6l and armv7l — a Raspberry Pi
    # Zero and a Pi 3 on a 32-bit OS both report through `uname -m` to
    # install.sh, and an installer that had to refuse one of them would refuse
    # the cheapest hardware anybody actually volunteers.
    {"os": "linux", "arch": "arm", "label": "Linux (32-bit ARM, Pi/armv6-7)", "suffix": ""},
    {"os": "darwin", "arch": "arm64", "label": "macOS (Apple Silicon)", "suffix": ""},
    {"os": "darwin", "arch": "amd64", "label": "macOS (Intel)", "suffix": ""},
    {"os": "windows", "arch": "amd64", "label": "Windows (64-bit)", "suffix": ".exe"},
    {"os": "windows", "arch": "arm64", "label": "Windows (ARM64)", "suffix": ".exe"},
)

SETTING_RELEASES = "node_release_index"
SETTING_RELEASES_SERIAL = SETTING_RELEASES + "_serial"


def binary_name(platform):
    return "syndichan-node-%s-%s%s" % (platform["os"], platform["arch"],
                                       platform["suffix"])


def detect_platform(user_agent):
    """Best guess at the visitor's platform, for a sensible default.

    A GUESS, never a decision. The page always shows every platform and lets
    somebody pick — user agents lie, are frozen for privacy, and say nothing at
    all about CPU architecture on Windows and Linux. Downloading the wrong
    binary is a confusing failure on a machine we cannot see, so the guess only
    pre-selects.
    """
    agent = (user_agent or "").lower()
    if "windows" in agent:
        arch = "arm64" if "arm64" in agent or "aarch64" in agent else "amd64"
        return {"os": "windows", "arch": arch, "confident": False}
    if "mac os" in agent or "macintosh" in agent or "darwin" in agent:
        # Apple Silicon is invisible in Safari's user agent — it still reports
        # Intel — so this leans ARM only when something says so outright.
        arch = "arm64" if ("arm64" in agent or "aarch64" in agent) else "amd64"
        return {"os": "darwin", "arch": arch, "confident": False}
    if "android" in agent:
        return {"os": "linux", "arch": "arm64", "confident": False}
    if "linux" in agent or "x11" in agent:
        arch = "arm64" if ("aarch64" in agent or "arm64" in agent) else "amd64"
        return {"os": "linux", "arch": arch, "confident": False}
    return {"os": "linux", "arch": "amd64", "confident": False}


def executable_platform(body):
    """Which platform a binary is actually FOR, read from its own header.

    Uploading is done by hand, six times, with a platform picked from a form —
    which is exactly the shape of mistake that puts the Linux build under the
    Windows key. The consequence lands on somebody else's machine, days later,
    as a file that will not start and a hash that matches what was published.

    So the file is asked what it is. Executable formats declare their OS and CPU
    in the first bytes and lying about it would break loading, which makes this
    cheap to check and impossible to get wrong by accident.

    Returns "os-arch", or None if it is not an executable this project builds.
    """
    if not body or len(body) < 64:
        return None
    head = bytes(body[:1024])

    # ELF: e_machine is a little-endian half at offset 18, in the same place in
    # ELF32 and ELF64, which is what lets the 32-bit ARM build be sniffed here
    # alongside the 64-bit ones.
    if head[:4] == b"\x7fELF":
        machine = head[18] | (head[19] << 8)
        return {0x3E: "linux-amd64", 0xB7: "linux-arm64",
                0x28: "linux-arm"}.get(machine)

    # Mach-O 64-bit, little-endian. cputype is a little-endian word at offset 4;
    # bit 24 (CPU_ARCH_ABI64) is set on both of the ones built here.
    if head[:4] == b"\xcf\xfa\xed\xfe":
        cputype = int.from_bytes(head[4:8], "little")
        return {0x01000007: "darwin-amd64", 0x0100000C: "darwin-arm64"}.get(cputype)

    # PE: "MZ", then e_lfanew at 0x3C points at "PE\0\0" followed by the machine.
    if head[:2] == b"MZ":
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if 0 < offset < len(body) - 6 and bytes(body[offset:offset + 4]) == b"PE\x00\x00":
            machine = int.from_bytes(bytes(body[offset + 4:offset + 6]), "little")
            return {0x8664: "windows-amd64", 0xAA64: "windows-arm64"}.get(machine)
    return None


def _client():
    from services.snapshot_dht import _client as build_client

    return build_client()


def _bucket():
    prefix = app.config.get("S3_UUID_PREFIX") or ""
    return "%s%s" % (prefix, BUCKET)


def index():
    """Published releases: platform -> {hash, size}. Empty until one is uploaded."""
    from model.SiteSetting import get_setting

    try:
        return json.loads(get_setting(SETTING_RELEASES, "") or "{}")
    except ValueError:
        return {}


def index_serial():
    """A counter that only ever rises, bumped by publish().

    WHY A SERIAL AND NOT A TIMESTAMP. The index is signed (§18.14), and a
    signature alone stops forgery but NOT REPLAY: without a version inside the
    signed bytes, an adversary who can answer for the origin serves an OLDER,
    genuinely-signed index pointing at a binary whose flaw is now public, and
    every check a client makes passes. A monotonic serial makes that visible --
    a client that has seen serial N refuses anything below it.

    A wall-clock timestamp would do the same job only if the clock never went
    backwards, which is not a property worth depending on for this.
    """
    from model.SiteSetting import get_setting

    try:
        return int(get_setting(SETTING_RELEASES_SERIAL, "0") or 0)
    except ValueError:
        return 0


def publish(platform_key, body, version="", toolchain=""):
    """Store one binary and record its hash. Returns the entry, or None.

    The hash is computed here, from the bytes actually stored, rather than taken
    from whoever uploaded. A published hash that came from the same place as the
    file proves only that the two agree.

    `toolchain` is recorded because the page tells people they can rebuild from
    source and compare. That is only true against the same compiler: these are
    built with -trimpath and CGO disabled, which makes the output reproducible
    for a given Go version and not across versions. Publishing the version turns
    "you could check this" into something somebody can actually do.
    """
    from model.SiteSetting import get_setting, set_setting
    from shared import db

    actual = executable_platform(body)
    if actual is None:
        app.logger.error("release: %s is not a recognised executable", platform_key)
        return None
    if actual != platform_key:
        # Refused rather than corrected: a mismatch means the upload and the
        # form disagree, and quietly believing the file would publish a binary
        # under a platform nobody chose to publish it under.
        app.logger.error("release: refused %s — the file is %s", platform_key, actual)
        return None

    digest = hashlib.sha256(body).hexdigest()
    try:
        client = _client()
        try:
            client.head_bucket(Bucket=_bucket())
        except Exception:
            client.create_bucket(Bucket=_bucket())
        client.put_object(Bucket=_bucket(), Key=digest, Body=body)
        # Read back before publishing the hash: a hash announced for bytes that
        # are not retrievable sends people to a download that does not exist.
        fetched = client.get_object(Bucket=_bucket(), Key=digest)["Body"].read()
        if hashlib.sha256(fetched).hexdigest() != digest:
            app.logger.error("release: %s did not read back correctly", platform_key)
            return None
    except Exception:
        app.logger.exception("release: could not store %s", platform_key)
        return None

    try:
        current = json.loads(get_setting(SETTING_RELEASES, "") or "{}")
    except ValueError:
        current = {}
    current[platform_key] = {"sha256": digest, "size": len(body),
                             "version": version or "", "toolchain": toolchain or ""}
    set_setting(SETTING_RELEASES, json.dumps(current))
    # Bump the serial in the same transaction as the index it describes, so a
    # commit cannot leave a new index carrying an old serial -- which would make
    # the new release look like a replay and be refused by careful clients.
    try:
        serial = int(get_setting(SETTING_RELEASES_SERIAL, "0") or 0)
    except ValueError:
        serial = 0
    set_setting(SETTING_RELEASES_SERIAL, str(serial + 1))
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("release: could not record the index")
        return None
    return current[platform_key]


def fetch(digest):
    """The binary for a hash, verified on the way out."""
    if not re.fullmatch(r"[0-9a-f]{64}", digest or ""):
        return None
    try:
        body = _client().get_object(Bucket=_bucket(), Key=digest)["Body"].read()
    except Exception:
        return None
    if hashlib.sha256(body).hexdigest() != digest:
        # Content addressing makes a wrong answer detectable rather than
        # something a visitor has to trust. This is a program people will RUN.
        app.logger.error("release: object store returned wrong bytes for %s",
                         digest[:12])
        return None
    return body


# -- configuration ---------------------------------------------------------

# Roles a visitor can choose, and what each actually asks of them. Stated plainly
# because the cost is real: a gateway needs an open port, which for most people
# means changing a setting on a router they may not control.
ROLES = {
    "storage": {
        "label": "Storage node",
        "needs_port": False,
        "summary": "Store encrypted shards for other people. Reaches the network "
                   "over I2P, so no router changes are needed.",
    },
    "gateway": {
        "label": "Gateway",
        "needs_port": True,
        "summary": "Serve syndichan to readers under your own hostname. Requires "
                   "inbound TCP 443 — usually a port-forwarding rule on your "
                   "router, and not possible behind carrier-grade NAT.",
    },
    "probe": {
        "label": "Verification probe",
        "needs_port": True,
        "summary": "Independently check that other gateways are reachable. "
                   "Requires an inbound port so candidates can be answered.",
    },
    "validator": {
        "label": "Validator",
        "needs_port": False,
        "summary": "Re-fetch published content and confirm it matches what "
                   "syndichan signed. Outbound only.",
    },
    # Payment roles (roadmap P15). Both are about carrying OTHER PEOPLE'S
    # payments, and they are listed separately because the difference between
    # them is the whole security question: a mailbox holds no key and can do
    # nothing but forward, while a delegated signer holds a key that recipients
    # have authorised ON CHAIN for one narrow operation.
    #
    # Neither ever holds anyone's money. Every payout in AxonChannels goes
    # to the channel party, and a volunteer is not a party.
    "mailbox": {
        "label": "Tipping mailbox",
        "needs_port": True,
        "port_note": "a payment port, not 443",
        "summary": "Hold tip messages for creators who do not run a node, so "
                   "they can be tipped while offline and collect later. You "
                   "hold no keys and no money \u2014 the mailbox only forwards. "
                   "Requires an inbound port so tippers can reach you.",
    },
    "delegate": {
        "label": "Delegated signer",
        "needs_port": True,
        "port_note": "a payment port, not 443",
        "summary": "Creators may authorise you, on chain, to co-sign incoming "
                   "tips for them while they are offline. You hold a signing "
                   "key for that one purpose only: the contract refuses to let "
                   "you withdraw, close a channel, or be paid, and the creator "
                   "can revoke you at any moment. More responsibility than a "
                   "mailbox \u2014 choose it deliberately.",
    },
    "monitor": {
        "label": "Status monitor",
        "needs_port": False,
        # Outbound only, which is the point: the more places check from, the
        # more the status page is worth reading, and requiring an open port
        # would exclude most of the people who could usefully check from
        # somewhere we cannot see.
        "summary": "Check that the site and the network answer from where you "
                   "are, and publish the result to the public status page at "
                   "/status. Outbound only \u2014 no router changes, and no disk.",
    },
}


def _pinned_wallet():
    """The wallet a downloaded node will trust for network directives.

    Baked into the config AT DOWNLOAD TIME, on purpose. A node that fetched the
    authorised address from the origin would be asking the thing a directive can
    replace who is allowed to replace it — whoever seized the domain would serve
    their own address alongside their own directive, and the check would pass.

    Empty is a valid answer and means the node follows no directives at all,
    which is the safe direction: it keeps pointing where it was told at install.
    """
    try:
        from model.Slip import configured_admin_wallet_address

        return (configured_admin_wallet_address() or "").strip().lower()
    except Exception:
        return ""


def _coordinator_key():
    """The coordinator public key a node should pin, base64, or "".

    Pinned at download time for the same reason the directive wallet is. Until
    now a node read this key OUT of the bootstrap document and trusted it, which
    means whoever served that document chose which key the node would accept for
    storage leases. That was survivable while exactly one host under our own TLS
    served it, and stops being survivable the moment gateways do.

    Empty means the node falls back to trusting the document, which is the
    behaviour that exists today — worse, but not a regression, and it keeps a
    node usable on an instance that has no coordinator configured.
    """
    try:
        from services.storage_coordination import _signing_key

        key = _signing_key()
        if key is None:
            return ""
        import base64 as _base64

        return _base64.b64encode(
            key.verify_key.encode()).decode("ascii").rstrip("=")
    except Exception:
        return ""


def build_config(choices):
    """Turn page selections into a config file.

    Deliberately builds the SAME shape the node already validates rather than a
    reduced one: a config that works here and fails on the machine it was
    downloaded to would be discovered by somebody with no way to debug it.
    """
    roles = [role for role in (choices.get("roles") or []) if role in ROLES]
    gigabytes = max(0, min(int(choices.get("storage_gb") or 0), 65536))
    payout = (choices.get("payout") or "").strip()

    wants_gateway = "gateway" in roles
    wants_probe = "probe" in roles
    wants_validator = "validator" in roles
    wants_monitor = "monitor" in roles
    wants_storage = "storage" in roles or gigabytes > 0

    config = {
        "run_mode": "storage" if wants_storage else "gateway-only",
        "capacity_bytes": gigabytes * 1024 ** 3,
        # Off unless storage was chosen: a node that hosts nothing for others
        # should say so rather than accept shards it will not keep.
        "cache_only": not wants_storage,
        "s3_listen": "127.0.0.1:9000",
        "ui_listen": "127.0.0.1:9090",
        "i2p_sam": "127.0.0.1:7656",
        "i2p_http_proxy": "http://127.0.0.1:4444",
        # How this node joins the DHT, and who it believes about it.
        #
        # `srv_name` is resolved to find gateways serving the bootstrap
        # document, so a single host going offline costs nothing — the node
        # simply tries the next. `coordinator_key` is what makes that safe:
        # without it a node adopts whichever coordinator key the document
        # carries, which would let any gateway serving one decide what that
        # node accepts as a storage lease.
        "bootstrap": {
            "coordinator_key": _coordinator_key(),
            "srv_name": "_syndichan-bootstrap._tcp.syndichan.org",
            "urls": [
                "https://node.syndichan.org/.well-known/syndichan/storage-node.json",
            ],
        },
        "data_shards": 6, "parity_shards": 3, "chunk_bytes": 1048576,
        # Status monitoring. The check list is FETCHED rather than compiled in:
        # a monitoring fleet whose checks live in the binary can only ever be as
        # current as its slowest operator, and the whole point of monitoring
        # from many machines is that no single one has to be trusted or updated.
        #
        # `serve_listen` is what makes status.<domain> work when the origin does
        # not — the node renders the board from its own copy of the JSON, so the
        # page describing an outage is not served by the thing that is out.
        "monitor": {
            "enabled": wants_monitor,
            "targets_url": "https://syndichan.org/api/v1/status/targets",
            "report_url": "https://syndichan.org/api/v1/status/report",
            "interval_seconds": 60,
        },
        # Where this node learns the network has moved, and who is allowed to
        # tell it. More than one source because the one that depends on the
        # current domain is exactly the one that fails in the case this exists
        # for; a node that can only hear about the move from the thing that
        # moved has heard nothing.
        "network_directive": {
            "wallet": _pinned_wallet(),
            # Ordered by how much they depend on the thing a directive might be
            # announcing the loss of. The well-known URL needs the origin up,
            # its domain resolving and its certificate valid — all three of
            # which can be exactly what has gone. The object-store copy needs
            # none of them: a storage node reads it through its own local
            # endpoint, which is backed by the DHT.
            #
            # Listed second rather than first because it is only present on a
            # node that runs storage, and a fetch failure there is normal for a
            # gateway-only node rather than a problem.
            "sources": [
                "https://syndichan.org/.well-known/syndichan/network.json",
                "http://127.0.0.1:9000/directives/current",
            ],
            "poll_seconds": 900,
        },
        "gateway": {
            "enabled": wants_gateway,
            "probe_enabled": wants_probe,
            "listen_address": "0.0.0.0",
            "listen_port": 443,
            "public_hostname": "",
            "advertise_ipv4": True,
            "advertise_ipv6": False,
            "reverse_proxy": False,
            "tls": {"mode": "acme", "acme_email": (choices.get("email") or "").strip(),
                    "acme_http_address": "0.0.0.0:80"},
            "external_verification": {
                "enabled": False, "minimum_successful_probes": 3,
                "minimum_distinct_networks": 2, "verification_timeout_seconds": 15,
                "registration_validity_seconds": 300,
                "probe_result_validity_seconds": 120, "reverify_interval_seconds": 60,
            },
            "health": {"failure_threshold": 3, "recovery_threshold": 2,
                       "check_interval_seconds": 30, "drain_seconds": 60},
            "eligibility": {"minimum_upload_mbps": 10, "minimum_free_memory_mb": 512,
                            "minimum_free_disk_mb": 1024, "maximum_cpu_percent": 90,
                            "require_public_address": True, "reject_cgnat": True},
            # Selecting "validator" used to change NOTHING in the generated
            # config, so somebody who chose only that got a node identical to
            # choosing nothing and no way to notice.
            "validator": {
                "enabled": wants_validator,
                "origin_url": "https://syndichan.org",
                "interval_seconds": 300,
                # Small on purpose: a validator is a background contributor, not
                # a load generator aimed at volunteers' home connections.
                "sample_size": 5,
            },
            "public_addresses": [],
            "registration_api": "https://syndichan.org/api/v1/gateways",
        },
    }
    if payout:
        config["payout_address"] = payout
    return config


# One compressed archive per binary, reused across downloads.
#
# Deflating a 30 MB Go binary takes ~1.2 s and shrinks it to ~11 MB. Both halves
# of that matter: 19 MB saved per download is worth having, and 1.2 s of CPU is
# not something to spend inside a gevent worker — zlib is a C call, so it blocks
# the whole hub, and every other greenlet in that worker stalls behind somebody
# else's download.
#
# The binary is identical for everyone on a platform, so the expensive part is
# done once and the per-request work is copying it and appending two small text
# files (~20 ms). Two entries, because that is ~25 MB resident and one visitor
# clicking through platforms should not evict the one everybody else is using.
_BASE_ARCHIVES = {}
_BASE_ARCHIVE_LIMIT = 2


def _base_archive(name, body, digest):
    """A zip holding just the binary, compressed once and remembered."""
    import zipfile

    # Keyed by hash AND filename. The member name is baked into the cached zip,
    # so a key that ignored it would hand out an archive whose binary is named
    # for another platform the moment anything reuses a digest.
    key = (digest, name)
    cached = _BASE_ARCHIVES.get(key)
    if cached is not None:
        return cached

    info = zipfile.ZipInfo(name)
    # Executable bit, so a Linux or macOS download runs without a chmod that
    # nobody mentions until it fails.
    info.external_attr = 0o755 << 16
    info.date_time = (2026, 1, 1, 0, 0, 0)
    # Set on the ZipInfo, not just on the ZipFile: writestr honours the member's
    # own compress_type when it is given one, and ZipInfo defaults to STORED. So
    # the archive-level ZIP_DEFLATED is quietly ignored here, and this shipped
    # 30 MB where 11 MB would do until the numbers were actually measured.
    info.compress_type = zipfile.ZIP_DEFLATED
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr(info, body)
    built = buffer.getvalue()

    while len(_BASE_ARCHIVES) >= _BASE_ARCHIVE_LIMIT:
        _BASE_ARCHIVES.pop(next(iter(_BASE_ARCHIVES)))
    _BASE_ARCHIVES[key] = built
    return built


def bundle(platform, body, config, expected_hash, toolchain=""):
    """A zip containing the binary, the config, and how to check the binary."""
    import zipfile

    name = binary_name(platform)

    def entry(filename, mode):
        # Every member gets a fixed timestamp, not just the binary. Default
        # `writestr` stamps the current clock, which would make two downloads of
        # identical choices differ — and the whole page rests on explaining what
        # is comparable and what is not. An archive that changes every second is
        # a thing people will try to compare anyway.
        info = zipfile.ZipInfo(filename)
        info.external_attr = mode << 16
        info.date_time = (2026, 1, 1, 0, 0, 0)
        info.compress_type = zipfile.ZIP_DEFLATED
        return info

    from services.node_runtargets import artifacts, executable_paths

    # One config.json is only right for one way of running it. A container
    # cannot reach 127.0.0.1:7656, so the Docker target gets its own config with
    # the addresses it needs — generated from the same choices, not hand-kept.
    extras = artifacts(platform, name, config)
    scripts = executable_paths(extras)

    archive = io.BytesIO(_base_archive(name, body, expected_hash))
    archive.seek(0, io.SEEK_END)
    with zipfile.ZipFile(archive, "a", zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr(entry("config.json", 0o644),
                        json.dumps(config, indent=2, sort_keys=True) + "\n")
        zipped.writestr(entry("VERIFY.txt", 0o644),
                        _verify_text(name, expected_hash, platform, toolchain))
        for path in sorted(extras):
            # Install scripts arrive executable. "sh install.sh" works either
            # way, but ./install.sh failing on a fresh download is a bad first
            # five minutes for somebody doing us a favour.
            zipped.writestr(entry(path, 0o755 if path in scripts else 0o644),
                            extras[path])
    return archive.getvalue()


def _verify_text(name, expected_hash, platform=None, toolchain=""):
    return """Verifying this download
=======================

Check the BINARY, not this archive.

This archive is unique to you: it contains a configuration built from the
choices you made, so its hash matches nobody else's and there is nothing to
compare it against. The binary inside is identical for everyone on your
platform, which is what makes it checkable.

Expected SHA-256 of %(name)s:

    %(hash)s

  Linux    sha256sum %(name)s
  macOS    shasum -a 256 %(name)s
  Windows  certutil -hashfile %(name)s SHA256

The same value is published at https://syndichan.org/api/v1/node/releases and
should match what you see there. If the two disagree, or if either disagrees
with what you computed, do not run it.

Building it yourself
--------------------
%(build)s
The build is reproducible for a given compiler version and not across versions,
so a different toolchain will produce a different — and perfectly legitimate —
hash. That is worth knowing before concluding anything from a mismatch.

config.json sits beside the binary and is read from the working directory. Every
setting in it can be changed later; nothing here is permanent.
""" % {"name": name, "hash": expected_hash,
       "build": _build_command(platform, toolchain)}


def _build_command(platform, toolchain):
    if platform is None:
        return "Build ./cmd/syndichan-node from the storage-client source.\n"
    return ("""%(tool)sFrom the storage-client source tree:

    CGO_ENABLED=0 GOOS=%(os)s GOARCH=%(arch)s \\
      go build -trimpath -ldflags="-s -w" -o %(name)s ./cmd/syndichan-node
""" % {"os": platform["os"], "arch": platform["arch"],
       "name": binary_name(platform),
       "tool": ("Built with %s.\n\n" % toolchain) if toolchain else ""})
