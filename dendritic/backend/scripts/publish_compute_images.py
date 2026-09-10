"""Publish catalogue image tarballs so /dl/ can serve them to volunteer nodes.

Usage (inside the maniwani container/pod, from /maniwani):

    python3 scripts/publish_compute_images.py /tmp/compute-images
    python3 scripts/publish_compute_images.py /tmp/compute-images --only embed
    python3 scripts/publish_compute_images.py /tmp/compute-images --dry-run

Normally driven by ../scripts/publish-compute-images.sh, which builds and saves
the images on a host with Docker and copies them in.

WHY A SCRIPT AND NOT AN ADMIN FORM
----------------------------------
Same reason scripts/publish_node_release.py exists: the artefact is ~186 MB and
the thing that must be right about it is a hash nobody can eyeball. Here the
digest is not merely computed — it is CHECKED against the value the catalogue
declares, which is the same value compiled into every node's binary. So this
either publishes the bytes the fleet was built to accept, or it publishes
nothing and says which.

That check is the whole reason the site keeps a copy of a digest it does not
enforce at serve time. Without it, publishing a rebuilt image would succeed, and
the failure would appear as every compute node in the network quietly refusing
to advertise compute, for a reason visible only in their journals.
"""

import gevent.monkey

gevent.monkey.patch_all()

import argparse  # noqa: E402
import hashlib  # noqa: E402
import os  # noqa: E402
import sys  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from shared import app  # noqa: E402
from services import compute_catalogue  # noqa: E402
from services.compute_image_release import (archive_repo_tags, index,  # noqa: E402
                                            looks_like_image_archive, publish)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("directory", help="where the .tar files were saved")
    parser.add_argument("--only", action="append", default=[],
                        help="publish just this workload, e.g. embed")
    parser.add_argument("--version", default="", help="release label, e.g. 2026.08.09")
    parser.add_argument("--dry-run", action="store_true",
                        help="say what would be published; store nothing")
    args = parser.parse_args()

    published = 0
    missing = []

    with app.app_context():
        before = index()
        for name in compute_catalogue.workload_names():
            if args.only and name not in args.only:
                continue
            artifact = compute_catalogue.image_artifact(name)
            if not artifact:
                print("%-10s has no image_artifact in the catalogue — nothing to "
                      "publish, and a node that did not build it by hand can "
                      "never obtain it" % name, file=sys.stderr)
                return 1
            path = os.path.join(args.directory, artifact)
            if not os.path.isfile(path):
                missing.append(artifact)
                continue

            with open(path, "rb") as handle:
                body = handle.read()
            digest = hashlib.sha256(body).hexdigest()
            declared = (compute_catalogue.image_digest(name) or "").strip().lower()

            if before.get(name, {}).get("sha256") == digest:
                print("%-10s unchanged (%s, %d bytes)" % (name, digest[:16], len(body)))
                continue

            if args.dry_run:
                # A dry run still does every check publish() does, because the
                # point of running it is to find out whether the real one will
                # work — a dry run that only reported sizes would be reassurance
                # rather than information.
                verdict = "would publish"
                if not looks_like_image_archive(body):
                    verdict = "REFUSED: not a docker save archive"
                elif declared and digest != declared:
                    verdict = "REFUSED: catalogue declares %s" % declared[:16]
                else:
                    tags = archive_repo_tags(body)
                    wanted = (compute_catalogue.workload(name) or {}).get("image")
                    if wanted and tags and wanted not in tags:
                        verdict = "REFUSED: archive carries %s" % ", ".join(tags)
                print("%-10s %s (%s, %d bytes)" % (name, verdict, digest[:16], len(body)))
                continue

            entry = publish(name, body, version=args.version)
            if entry is None:
                # Refused. Stop the whole release rather than carry on: a
                # half-published catalogue is a set of nodes that can run some of
                # it, and the node treats the catalogue as all-or-nothing.
                print("%-10s REFUSED — see the log; nothing further published"
                      % name, file=sys.stderr)
                return 1
            print("%-10s published %s (%d bytes)" % (name, entry["sha256"][:16],
                                                     entry["size"]))
            published += 1

    if missing:
        # Not fatal on its own — publishing one workload at a time is normal —
        # but said out loud, because a silently skipped image is a 404 on every
        # node that needs it, and those nodes then stop advertising compute.
        print("not in %s, so left alone: %s" % (args.directory, ", ".join(missing)),
              file=sys.stderr)
    print("%d published." % published)
    return 0


if __name__ == "__main__":
    sys.exit(main())
