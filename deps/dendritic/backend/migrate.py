"""Run database migrations without starting the application.

    python3 migrate.py            # upgrade to head
    python3 migrate.py current    # what revision is applied
    python3 migrate.py history    # what revisions exist

WHY THIS EXISTS
---------------
`python3 -m flask db upgrade` loads app.py, which registers every blueprint and
starts every background thread — chan discovery, the arcade publisher, the
scraper pool. In a memory-limited container that is enough to get the process
SIGKILLed: exit 137, which is what happened to the last two migrations here.

Both of them applied anyway, purely because the kill landed AFTER the upgrade
committed. That is luck, not design. A kill landing DURING an upgrade leaves a
half-applied schema with alembic's version row possibly already advanced, which
is far worse to recover from than a clean failure — the tooling then believes a
migration ran that only partly did.

So this imports `shared` (the app object and db) and registers Migrate against
it, and stops there. migrations/env.py needs `current_app` with the `migrate`
extension and the model metadata, which that provides; it does not need
routes, and it certainly does not need a scraper pool.

WHAT IT DELIBERATELY DOES NOT DO
--------------------------------
No `db.create_all()`. app.py calls that at boot, which is how the compute_rental
tables appeared before their migration was confirmed — convenient, and it means
the schema can silently diverge from what the migrations describe. Migrations
are the record; this runs them and nothing else.
"""

import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# `shared` builds the Flask app and SQLAlchemy. app.py is NOT imported — that is
# the entire point of this file.
from shared import app, db  # noqa: E402


def main():
    from flask_migrate import Migrate
    from flask_migrate import current as alembic_current
    from flask_migrate import history as alembic_history
    from flask_migrate import upgrade as alembic_upgrade

    Migrate(app, db)
    command = (sys.argv[1] if len(sys.argv) > 1 else "upgrade").lower()

    with app.app_context():
        if command == "current":
            alembic_current()
        elif command == "history":
            alembic_history()
        elif command == "upgrade":
            target = sys.argv[2] if len(sys.argv) > 2 else "head"
            print("migrating to %s ..." % target)
            alembic_upgrade(revision=target)
            print("done. current revision:")
            alembic_current()
        else:
            print("unknown command: %s (upgrade|current|history)" % command,
                  file=sys.stderr)
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
