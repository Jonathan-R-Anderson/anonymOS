"""Publish built node binaries so /dl/ and install.sh can serve them.

Usage (inside the maniwani container/pod, from /maniwani):

    python3 scripts/publish_node_release.py /tmp/dist
    python3 scripts/publish_node_release.py /tmp/dist --only linux-amd64
    python3 scripts/publish_node_release.py /tmp/dist --dry-run

Normally driven by ../scripts/publish-node-release.sh, which builds the
binaries on the host and copies them in. Run it directly when the binaries are
already somewhere the app can read.

WHY THIS EXISTS RATHER THAN THE ADMIN PAGE
------------------------------------------
/admin/node-releases uploads ONE file at a time through a form, and a release is
four platforms for Linux alone. Publishing by hand, four times, from a form
whose platform dropdown is separate from the file picker, is exactly the shape
of mistake services.node_release.executable_platform exists to catch — and
catching a mistake is worse than not making it. Here the platform is derived
from the filename AND confirmed against the file's own ELF header by publish(),
so the two cannot disagree because somebody clicked the wrong row at midnight.

It writes to the object store and to one SiteSetting. It does NOT touch the
binaries on disk, and re-publishing the same bytes is a no-op with a new index
entry: the store is content-addressed, so the key is the hash either way.
"""

import gevent.monkey

gevent.monkey.patch_all()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import app  # noqa: E402
from services.node_release import PLATFORMS, binary_name, index, publish  # noqa: E402


def toolchain_version():
    """The Go that built these, recorded so a rebuild can be compared.

    -trimpath with CGO disabled makes the output reproducible for a GIVEN Go
    version and not across versions, so "you can rebuild this and compare" is
    only true next to the version. Best effort: if go is not on this machine
    (it usually is not — this runs in the app container) the field is empty,
    which is honest, rather than a version guessed from somewhere else.
    """
    try:
        out = subprocess.run(["go", "version"], capture_output=True, text=True,
                             timeout=10)
    except Exception:
        return ""
    parts = (out.stdout or "").split()
    return parts[2] if len(parts) > 2 else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", help="where build-release.sh left its output")
    parser.add_argument("--only", action="append", default=[],
                        help="publish just this platform key, e.g. linux-arm64")
    parser.add_argument("--version", default="", help="release label, e.g. 2026.08.07")
    parser.add_argument("--toolchain", default="", help="override the recorded Go version")
    parser.add_argument("--dry-run", action="store_true",
                        help="say what would be published; store nothing")
    args = parser.parse_args()

    toolchain = args.toolchain or toolchain_version()
    published = 0
    missing = []

    with app.app_context():
        before = index()
        for platform in PLATFORMS:
            key = "%s-%s" % (platform["os"], platform["arch"])
            if args.only and key not in args.only:
                continue
            path = os.path.join(args.directory, binary_name(platform))
            if not os.path.isfile(path):
                missing.append(os.path.basename(path))
                continue
            with open(path, "rb") as handle:
                body = handle.read()
            digest = hashlib.sha256(body).hexdigest()
            if before.get(key, {}).get("sha256") == digest:
                print("%-14s unchanged (%s)" % (key, digest[:16]))
                continue
            if args.dry_run:
                print("%-14s would publish %s (%d bytes)" % (key, digest[:16], len(body)))
                continue
            entry = publish(key, body, version=args.version, toolchain=toolchain)
            if entry is None:
                # publish() refuses a file whose ELF header disagrees with the
                # name, and refuses bytes the store did not hand back. Both are
                # reasons to stop the whole release, not to carry on and leave
                # half of it published.
                print("%-14s REFUSED — see the log; nothing further published" % key,
                      file=sys.stderr)
                return 1
            print("%-14s published %s (%d bytes)" % (key, entry["sha256"][:16],
                                                     entry["size"]))
            published += 1

    if missing:
        # Not fatal: a Linux-only release is a normal thing to publish, and the
        # ones that ARE there are already stored. But it is said out loud,
        # because a silently skipped platform is a 404 in somebody's installer.
        print("not in %s, so left alone: %s" % (args.directory, ", ".join(missing)),
              file=sys.stderr)
    print("%d published." % published)
    return 0


if __name__ == "__main__":
    sys.exit(main())
