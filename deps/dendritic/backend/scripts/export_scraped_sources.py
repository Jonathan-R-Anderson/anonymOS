"""Export every configured scrape source to a reviewable text file.

Reviewing sources through the admin UI takes hours; this renders all of them as
one file, sorted worst-first, so the broken ones are obvious.

Usage (inside the maniwani container, from /maniwani):

    python3 scripts/export_scraped_sources.py                 # -> <repo root>/aggregated_chans.txt
    python3 scripts/export_scraped_sources.py -o /tmp/x.txt   # explicit path
    python3 scripts/export_scraped_sources.py --stdout        # print, write nothing
                                                              # (NB: the app logs one
                                                              # "Logging to ..." line to
                                                              # stdout at import, so prefer
                                                              # -o when capturing to a file)
    python3 scripts/export_scraped_sources.py --tsv           # machine-readable columns

NOTE ON THE CONTAINER: the repo is NOT bind-mounted into the maniwani container
(only .env, runtime-config.cfg and maniwani_logs are), so the default path writes
inside the container and disappears with it. To land the file on the host, either
write into a mounted directory or copy it out:

    sudo docker compose exec -T maniwani \
        python3 scripts/export_scraped_sources.py -o /tmp/aggregated_chans.txt
    sudo docker compose cp maniwani:/tmp/aggregated_chans.txt ./aggregated_chans.txt

Use -o + `cp` rather than `--stdout >`: the app writes a logging line to stdout
when shared.py is imported, which would end up as the first line of the file.

`SCRAPED_SOURCE_EXPORT_PATH` overrides the default target if you would rather
point it at a mounted directory.

Read-only with respect to the database, and it performs NO network I/O —
reachability is read from the cached ping columns. See
services/scraped_source_export.py for why that matters.
"""

import gevent.monkey
gevent.monkey.patch_all()
try:
    import psycogreen.gevent
    psycogreen.gevent.patch_psycopg()
except Exception:
    pass

import argparse
import os
import sys

_BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

from shared import app, db  # noqa: E402
from services.scraped_source_export import (  # noqa: E402
    build_export,
    default_export_path,
    write_export,
)


def _load_all_models():
    """Import every module under model/ so the SQLAlchemy registry is complete.

    Importing only the handful of models this export touches is NOT enough:
    Thread declares relationship("Tag", ...) by NAME, and SQLAlchemy resolves
    those names lazily at first query, against whatever classes have been
    imported. A partial import therefore fails with

        InvalidRequestError: When initializing mapper Mapper[Thread(thread)],
        expression 'Tag' failed to locate a name ('Tag')

    The app itself never hits this because app.py imports everything. Importing
    the model package wholesale is the fix; importing `app` instead would also
    work but would start every background sync loop inside a one-shot CLI.
    """
    import importlib
    import pkgutil

    import model

    failed = []
    for module in pkgutil.iter_modules(model.__path__):
        try:
            importlib.import_module("model.%s" % module.name)
        except Exception as exc:  # a model that cannot import must not kill the export
            failed.append("%s (%s)" % (module.name, exc))
    return failed


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument(
        "-o", "--output", default=None,
        help="Where to write (default: <repo root>/aggregated_chans.txt)",
    )
    parser.add_argument(
        "--stdout", action="store_true",
        help="Print the export instead of writing a file",
    )
    parser.add_argument(
        "--tsv", action="store_true",
        help="Tab-separated columns with no header block, for scripting",
    )
    args = parser.parse_args(argv)

    with app.app_context():
        failed = _load_all_models()
        if failed:
            sys.stderr.write("warning: some model modules did not import: %s\n"
                             % ", ".join(failed))
        try:
            if args.stdout:
                text, rows, summary = build_export(tsv=args.tsv)
                sys.stdout.write(text)
            else:
                target, rows, summary = write_export(path=args.output, tsv=args.tsv)
                sys.stderr.write("wrote %s\n" % target)
            # To stderr so `--stdout | grep` stays clean.
            sys.stderr.write(
                "%d source rows -> %d lines across %d sites; "
                "%d importing, %d importing nothing; "
                "%d generic site(s) never crawled\n"
                % (
                    summary["source_rows"], summary["lines"], summary["sites"],
                    summary["importing"], summary["importing_nothing"],
                    summary["never_crawled_sites"],
                )
            )
            for verdict, count in sorted(summary["by_verdict"].items()):
                sys.stderr.write("  %-14s %d\n" % (verdict, count))
        finally:
            # Give the connection back explicitly: this runs outside the request
            # lifecycle, so nothing else will.
            try:
                db.session.remove()
            except Exception:
                pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
