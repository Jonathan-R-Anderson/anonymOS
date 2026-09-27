"""Import an Edabit challenge export into codeplay's `problems` collection.

    python import_edabit.py questions.json            # census, changes nothing
    python import_edabit.py questions.json --yes      # import
    python import_edabit.py questions.json --yes --publish   # and push to the DHT

Dry run by default. This writes several thousand rows, and a destructive-adjacent
one-shot that runs on invocation is one shell-history arrow-up away from running
twice.

WHAT IT DOES
------------
1. Upgrades the existing problems to the merged schema (services/edabit_import
   .upgrade_legacy) so there is one shape rather than two.
2. Converts and upserts every challenge from the export, keyed on item_id, so
   re-running updates rather than duplicating.
3. Optionally publishes. Publishing is REQUIRED for these to be durable — the
   DHT is this project's store — but it is a separate flag because a failed
   publish should not roll back a good import, and the hourly sweep in
   services/arcade_publish_loop will pick it up regardless.
"""

import argparse
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from shared import app, db  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("export", help="path to the export JSON")
    parser.add_argument("--yes", action="store_true", help="actually write (default is a census)")
    parser.add_argument("--publish", action="store_true", help="publish to the DHT afterwards")
    parser.add_argument("--limit", type=int, default=0, help="import at most N (for a trial run)")
    args = parser.parse_args()

    if not os.path.exists(args.export):
        print("no such file: %s" % args.export, file=sys.stderr)
        return 2

    with app.app_context():
        import json

        from model.CodeplayContent import CodeplayContent
        from services import edabit_import

        existing = {
            row.item_id: row
            for row in db.session.query(CodeplayContent)
            .filter(CodeplayContent.collection == "problems").all()
        }
        print("problems already stored: %d" % len(existing))

        converted = []
        judgeable = 0
        for item in edabit_import.load_export(args.export):
            converted.append(item)
            judgeable += bool(item.get("judgeable"))
            if args.limit and len(converted) >= args.limit:
                break

        new = sum(1 for i in converted if i["id"] not in existing)
        print("in the export:           %d" % len(converted))
        print("  new:                   %d" % new)
        print("  updating:              %d" % (len(converted) - new))
        print("  auto-gradeable here:   %d  (the rest are practice only —" % judgeable)
        print("                             no python in the export, and the")
        print("                             runner does not do ruby/cpp/java)")

        legacy = [row for row in existing.values() if not row.item_id.startswith("edabit_")]
        print("existing to upgrade:     %d" % len(legacy))

        if not args.yes:
            print("\nDry run — nothing written. Re-run with --yes.")
            return 0

        print("\nUpgrading existing problems to the merged schema…")
        for row in legacy:
            row.payload = json.dumps(edabit_import.upgrade_legacy(row.item()),
                                     ensure_ascii=False)
        db.session.commit()

        print("Writing %d imported problems…" % len(converted))
        written = 0
        for index, item in enumerate(converted):
            row = existing.get(item["id"])
            payload = json.dumps(item, ensure_ascii=False)
            if row is None:
                db.session.add(CodeplayContent(
                    collection="problems", item_id=item["id"],
                    category=(item.get("category") or "")[:64],
                    difficulty=(item.get("difficulty") or "")[:16],
                    payload=payload, position=index, active=True))
            else:
                row.category = (item.get("category") or "")[:64]
                row.difficulty = (item.get("difficulty") or "")[:16]
                row.payload = payload
            written += 1
            # Commit in batches. One transaction holding 8,500 inserts is a long
            # lock on a table the site reads on every codeplay page load.
            if written % 500 == 0:
                db.session.commit()
                print("  %d/%d" % (written, len(converted)))
        db.session.commit()
        print("Wrote %d." % written)

        if args.publish:
            from services import codeplay_content

            print("\nPublishing to the DHT…")
            result = codeplay_content.publish_to_dht()
            if not result:
                print("  nothing published — no DHT endpoint configured here.")
                print("  The hourly sweep will publish once one is.")
            for collection, digest in sorted(result.items()):
                print("  %-12s %s" % (collection, digest))
        else:
            print("\nNot published. These are not durable until they are on the "
                  "DHT — run again with --publish, or wait for the hourly sweep.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
