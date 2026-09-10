"""Watch traffic, score it, record what would have happened. Enforce nothing.

This runs in the request path of a live site, which shapes every decision here
more than the detection logic does:

  * it must never raise — a security log that can 500 a request has become the
    outage it was meant to prevent;
  * it must never block — phase 1 of `roadmap/wall-of-shame.md` exists to
    produce the evidence from which thresholds are chosen, and a scorer shipped
    with guessed thresholds turns readers away before it turns away attackers;
  * it must not write a row per request. At any real rate that is a write
    amplification nobody asked for, so ordinary traffic is sampled and only
    interesting traffic is kept in full.

THE COUNTERS ARE IN REDIS, NOT POSTGRES
---------------------------------------
Rate and 404 counts need a read and a write on every request. Doing that in
Postgres would put the busiest write in the system inside the request
transaction — which is how this deployment has already produced a lock pileup
once. Redis is already here, already used for presence, and losing these
counters costs a few minutes of detection rather than anything durable.
"""

import time

from shared import app

# Window for the rate and enumeration counters.
WINDOW_SECONDS = 60

# Ordinary traffic is sampled: one row in this many. Anything that scores above
# the safe band is always kept, so sampling loses only the boring rows.
SAFE_SAMPLE_RATE = 100

# Paths that are noise in a threat log — the site's own polling.
_IGNORED_PREFIXES = ("/static/", "/presence/ping", "/events", "/updates.json",
                     "/analytics/", "/favicon")


def enabled():
    return bool(app.config.get("THREAT_WATCH_ENABLED"))


def _redis():
    import cache

    return cache.Cache()


def _client_address():
    from flask import request

    forwarded = request.headers.get("X-Forwarded-For") or ""
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or ""


def _bump(key, window=WINDOW_SECONDS):
    """Increment a windowed counter and return its value.

    Bucketed by window rather than a sliding log: a sorted set per client is
    precise and costs memory proportional to traffic, which is the wrong thing
    to spend during the flood this is meant to notice.
    """
    try:
        connection = _redis()
        bucket = int(time.time()) // window
        name = "tw:%s:%d" % (key, bucket)
        raw = connection.get(name)
        current = int(raw) + 1 if raw else 1
        connection.set(name, str(current))
        return current
    except Exception:
        return 0


def observe():
    """Score the current request. Returns the verdict, or None if not watching."""
    if not enabled():
        return None
    from flask import request

    path = request.path or ""
    if any(path.startswith(prefix) for prefix in _IGNORED_PREFIXES):
        return None

    from services.threat_score import is_exempt, score_request

    if is_exempt(path):
        # Skipped before any counter is touched: a gateway registering every
        # sixty seconds must not accumulate a rate score it can never shed.
        return None

    address = _client_address()
    if not address:
        return None

    features = {
        "path": path,
        "query": request.query_string.decode("latin-1", "replace")[:512],
        "user_agent": request.headers.get("User-Agent") or "",
        "headers": {k: v for k, v in request.headers.items()},
        "address": address,
        "method": request.method,
        "recent_requests": _bump("r:%s" % address),
        "recent_404s": _count("n:%s" % address),
        "recent_failed_logins": _count("f:%s" % address),
        "window_seconds": WINDOW_SECONDS,
    }
    verdict = score_request(features)

    from flask import g

    # Stashed rather than written here: the status code is not known until the
    # response exists, and a threat log without it cannot tell enumeration from
    # ordinary browsing.
    g.threat_features = features
    g.threat_verdict = verdict
    return verdict


def _count(key, window=WINDOW_SECONDS):
    try:
        connection = _redis()
        raw = connection.get("tw:%s:%d" % (key, int(time.time()) // window))
        return int(raw) if raw else 0
    except Exception:
        return 0


def note_not_found():
    """Called when a request 404s, so enumeration accumulates."""
    try:
        from flask import g

        address = getattr(g, "threat_features", {}).get("address")
        if address:
            _bump("n:%s" % address)
    except Exception:
        pass


def note_failed_login():
    """Called on a failed authentication, so brute force accumulates."""
    try:
        from flask import g

        address = getattr(g, "threat_features", {}).get("address")
        if address:
            _bump("f:%s" % address)
    except Exception:
        pass


def record_outcome(status):
    """Persist the observation once the response is known.

    Sampled for safe traffic, complete for anything else. A row per request at
    any real rate is a write amplification nobody asked for, and the rows that
    matter are exactly the ones that are not boring.
    """
    if not enabled():
        return
    try:
        from flask import g

        features = getattr(g, "threat_features", None)
        verdict = getattr(g, "threat_verdict", None)
        if not features or not verdict:
            return
        if status == 404:
            note_not_found()
        if verdict["band"] == "safe":
            import random

            if random.randint(1, SAFE_SAMPLE_RATE) != 1:
                return
        from model.ThreatEvent import record

        # enforced=False, always, in phase 1. The column exists so that when
        # enforcement arrives the log can distinguish "would have blocked" from
        # "did block" — which is the difference between a tuning record and an
        # incident record.
        record(features, verdict, status=status, enforced=False)
    except Exception:
        app.logger.debug("threat log: could not record an outcome", exc_info=True)
