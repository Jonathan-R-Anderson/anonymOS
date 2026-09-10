"""Moving off an emergency origin onto the permanent one, without losing posts.

Phase 4 of roadmap/domain-and-origin-succession.md.

THE TRAP THIS EXISTS TO AVOID
-----------------------------
A cold restore and a cutover look like the same job and are not. A cold restore
starts from a backup because the old server is gone. A cutover starts from an
emergency origin that has been ACCEPTING POSTS — so it holds data newer than any
backup, and "restore the backup on the new server and switch" quietly discards
every post, sign-up and transaction made during the emergency. Nothing errors.
The site comes up looking healthy and hours of other people's writing are gone.

So the order is: freeze writes, THEN take a backup, then restore, then switch.
The freeze is what makes the backup a complete record rather than a moving one.

WHY THE FREEZE IS AT THE ORIGIN AND NOT IN DEFENSIVE MODE
---------------------------------------------------------
`services/snapshot_control.declare_defensive_mode` sheds READ traffic to
gateways. It is about load, and readers who reach the origin directly can still
post through it. This refuses the writes themselves, at the origin, which is the
only place that can actually stop them.

WHAT STAYS OPEN WHILE FROZEN
----------------------------
Admin, always. A freeze that can lock the operator out of the page that lifts it
is a freeze that turns a planned cutover into an outage — the same reason the
threat-scoring work insists on a bypass that survives the scorer being wrong.
Health probes, ACME, and the directive document stay open too: a frozen origin
that fails its probes gets restarted, and one that cannot renew its certificate
stops serving before anyone can finish the move.
"""

import datetime as _datetime
import json

from shared import app

SETTING = "cutover_write_freeze"

# A freeze is meant to last minutes. Bounded so that an operator who starts one
# and is then pulled away does not leave the site read-only indefinitely — the
# expiry is the thing that recovers it, not somebody remembering.
MAX_FREEZE_SECONDS = 6 * 3600
DEFAULT_FREEZE_SECONDS = 1800

# Methods that change something. HEAD and OPTIONS are not here on purpose: a
# frozen origin that refuses OPTIONS breaks CORS preflight and therefore breaks
# reading, which is the half that is supposed to keep working.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Paths that keep accepting writes while frozen, and why each one must.
#
# A trailing slash means PREFIX; anything else is an EXACT path. The distinction
# is load-bearing: matching "/health" as a prefix also exempts "/healthy-boards"
# and every other path that merely begins with those letters, which is a freeze
# somebody can walk straight through by choosing a URL.
ALWAYS_OPEN = (
    # The operator has to be able to lift this. A freeze that locks out the
    # page that ends it converts a planned cutover into a real outage.
    "/admin/",
    # Probes do not read a 503 as "deliberately read-only", they read it as
    # unhealthy, and a restarted origin mid-cutover is a worse problem.
    "/health",
    "/healthz",
    "/readyz",
    # Without renewal the old origin stops serving HTTPS before the move ends.
    "/.well-known/acme-challenge/",
    # How nodes learn where the network is going. Freezing it would strand them
    # on the origin being retired.
    "/.well-known/syndichan/",
)


def current():
    """The freeze in force, or None. An expired freeze is None, not expired.

    Returned as absent rather than as a record with a past expiry, because a
    caller that has to remember to check the timestamp is a caller that will
    one day forget, and the site stays read-only for no reason.
    """
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING, "") or "{}")
    except ValueError:
        return None
    if not stored:
        return None
    if int(stored.get("expires_at") or 0) <= _now():
        return None
    return stored


def _now():
    return int(_datetime.datetime.utcnow().timestamp())


def freeze(seconds=None, reason="cutover", note=""):
    """Stop accepting writes, for a bounded time."""
    from model.SiteSetting import set_setting
    from shared import db

    seconds = int(seconds or DEFAULT_FREEZE_SECONDS)
    # Clamped here rather than trusted from the caller: an operator typing an
    # extra zero under pressure should not be able to take the site read-only
    # for a week.
    seconds = max(60, min(seconds, MAX_FREEZE_SECONDS))
    record = {
        "reason": str(reason or "")[:64],
        "note": str(note or "")[:200],
        "issued_at": _now(),
        "expires_at": _now() + seconds,
    }
    set_setting(SETTING, json.dumps(record))
    db.session.commit()
    app.logger.warning(
        "cutover: writes frozen for %ds (%s). Reads continue; admin stays open.",
        seconds, record["reason"])
    return record


def thaw():
    """Accept writes again. Expiry still applies if this is never called."""
    from model.SiteSetting import set_setting
    from shared import db

    set_setting(SETTING, "")
    db.session.commit()
    app.logger.warning("cutover: writes resumed")


def blocks(method, path):
    """Whether this request should be refused while frozen.

    Pure, so the decision can be reasoned about and tested without a request
    context — this sits in front of every write on the site.
    """
    if (method or "").upper() not in WRITE_METHODS:
        return False
    path = path or "/"
    for entry in ALWAYS_OPEN:
        if entry.endswith("/"):
            if path == entry.rstrip("/") or path.startswith(entry):
                return False
        elif path == entry:
            return False
    return True


def refusal():
    """What to tell somebody whose post was refused.

    It says the writing was not saved. A read-only site that implies otherwise
    is worse than one that is plainly down: the person walks away believing
    their post exists.
    """
    record = current()
    remaining = max(0, int((record or {}).get("expires_at") or 0) - _now())
    return {
        "error": "This server is being moved and is not accepting posts right "
                 "now. What you wrote was NOT saved — copy it somewhere before "
                 "leaving this page.",
        "reason": (record or {}).get("reason") or "cutover",
        "note": (record or {}).get("note") or "",
        "retry_after_seconds": remaining,
    }


def plan(new_server="", new_domain=""):
    """The cutover, in the order that does not lose data.

    Written down because the sequence is not guessable and the expensive
    mistake — taking the backup before freezing writes — produces no error at
    all. It is only visible later, as posts that are simply missing.
    """
    where = new_server or "the permanent server"
    return [
        {
            "step": "Freeze writes on the emergency origin.",
            "why": "Everything after this point is a moving target. A backup "
                   "taken while posts are still landing is missing whatever "
                   "arrived after it started, and nothing anywhere reports "
                   "that.",
            "reversible": True,
        },
        {
            "step": "Take a FRESH backup. Do not reuse the one the emergency "
                    "origin was restored from.",
            "why": "That backup predates the emergency. Restoring it discards "
                   "every post, sign-up and transaction made while the "
                   "emergency origin was serving — which is the entire period "
                   "anyone was relying on it.",
            "reversible": True,
        },
        {
            "step": "On %s: empty database, run migrations, restore." % where,
            "why": "The dump carries rows, not schema, and the restore refuses "
                   "a database that already has any.",
            "reversible": True,
        },
        {
            "step": "Copy the carried settings across and confirm media loads.",
            "why": "Media is fetched from the DHT by hash rather than copied, "
                   "so a new server that cannot reach the DHT looks fine until "
                   "somebody opens a thread.",
            "reversible": True,
        },
        {
            "step": "Compare row counts between the two servers before "
                    "switching anything.",
            "why": "The last moment the old data still exists in a place you "
                   "can look at. After the directive, nodes are pointed away "
                   "and this comparison needs somebody to go and find the old "
                   "machine.",
            "reversible": True,
        },
        {
            "step": "Issue the directive%s." % (" naming %s" % new_domain
                                                if new_domain else ""),
            "why": "The switch. Nodes restart against it and the emergency "
                   "node stops being the origin. Reversible only by issuing "
                   "another directive at a higher sequence, which every node "
                   "then has to see.",
            "reversible": False,
        },
        {
            "step": "Thaw writes on %s — and only there." % where,
            "why": "Thawing the emergency origin instead would accept posts "
                   "onto a server nothing points at any more. They would be "
                   "real, saved, and invisible.",
            "reversible": True,
        },
        {
            "step": "Demote the emergency node back to a gateway.",
            "why": "It is holding an origin's configuration and, if it was "
                   "promoted with one, an origin's signing key. Left as it is, "
                   "a machine that can sign as the site keeps running with "
                   "nobody watching it.",
            "reversible": True,
        },
    ]
