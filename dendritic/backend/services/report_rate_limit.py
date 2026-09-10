"""Rate limiting for public-interest intake, without keeping a list of IPs.

WHY THIS DOES NOT STORE AN IP
-----------------------------
Rate limiting normally means "remember who has been here". For this feature that
would mean the site holds a list of addresses belonging to people reporting
police misconduct -- created by the abuse control, defeating the encryption the
rest of the design exists to provide, and available to anyone who reaches the
key store or subpoenas it.

So the bucket is keyed by `poster_privacy.poster_ip_token()`, which is already in
this codebase for the same reason: an HMAC of the address under the app secret.
Stable enough to count against, not reversible without the server key, and
useless to anyone who takes the database. The window is short, so even the tokens
age out.

WHAT THIS CAN AND CANNOT DO -- AND THE I2P PROBLEM
--------------------------------------------------
The site is reachable over I2P, and traffic arriving that way shares one internal
address. IP-derived limiting therefore lumps every I2P visitor into a single
bucket: it cannot tell them apart, and a limit tight enough to matter would throttle
all of them together. Those are exactly the people most likely to need this form.

Two consequences, both deliberate:

* the limits are GENEROUS. This is a backstop against a script filing ten
  thousand submissions, not a fine-grained quota. The captcha is the primary
  control and this is the thing that catches what gets past it.
* the limiter FAILS OPEN. If the key store is unreachable, submissions are
  allowed. A rate limiter that takes intake offline when Redis blips has done
  more harm than the abuse it prevents -- for a board post, failing closed is
  fine; for someone reporting an assault, losing the submission is not.

The genuinely hard case -- a determined person filing malicious reports through
I2P -- is not solved here and cannot be solved at this layer. It is a review
problem, which is why nothing is published without a human reading it.
"""

import json
import time

from shared import app


# Generous on purpose; see the module docstring.
WINDOW_SECONDS = 3600
MAX_PER_WINDOW = 6

# A second, longer window so a script cannot simply pace itself just under the
# hourly limit and run all day.
DAY_SECONDS = 86400
MAX_PER_DAY = 20

_KEY_PREFIX = "public-interest-intake:"


def _token():
    """A non-reversible identifier for the caller, or None if unavailable."""
    try:
        from flask import request
        from poster_privacy import poster_ip_token

        forwarded = request.headers.get("X-Forwarded-For")
        address = (forwarded.split(",")[0].strip() if forwarded
                   else request.environ.get("REMOTE_ADDR") or "")
        return poster_ip_token(address)
    except Exception:
        return None


def _load(store, key):
    try:
        raw = store.get(key)
    except Exception:
        raise
    if not raw:
        return []
    try:
        stamps = json.loads(raw)
        return [float(s) for s in stamps if isinstance(s, (int, float))]
    except (ValueError, TypeError):
        # A corrupt bucket is treated as empty rather than as a reason to
        # refuse: the failure mode of this module must always be "allow".
        return []


def check(now=None):
    """(allowed, retry_after_seconds). Never raises.

    Read-only -- call `record()` after a submission actually succeeds, so a
    person whose submission failed for our reasons is not charged for it.
    """
    now = now or time.time()
    token = _token()
    if not token:
        return True, 0

    try:
        import keystore
        store = keystore.Keystore()
        stamps = _load(store, _KEY_PREFIX + token)
    except Exception:
        app.logger.warning("report rate limit: key store unavailable, allowing")
        return True, 0

    recent = [s for s in stamps if now - s < WINDOW_SECONDS]
    daily = [s for s in stamps if now - s < DAY_SECONDS]

    if len(recent) >= MAX_PER_WINDOW:
        return False, int(WINDOW_SECONDS - (now - min(recent)))
    if len(daily) >= MAX_PER_DAY:
        return False, int(DAY_SECONDS - (now - min(daily)))
    return True, 0


def record(now=None):
    """Count one accepted submission. Never raises."""
    now = now or time.time()
    token = _token()
    if not token:
        return

    try:
        import keystore
        store = keystore.Keystore()
        key = _KEY_PREFIX + token
        stamps = _load(store, key)
        # Pruned on write, because the key store here has no TTL and an
        # unpruned bucket would grow without bound for a persistent visitor.
        stamps = [s for s in stamps if now - s < DAY_SECONDS]
        stamps.append(now)
        store.set(key, json.dumps(stamps[-(MAX_PER_DAY + 5):]))
    except Exception:
        app.logger.warning("report rate limit: could not record a submission")


def message(retry_after):
    """What to tell somebody who has hit the limit.

    Says how long and why, and does not imply they have done something wrong --
    a person filing a second report about a continuing situation is the expected
    case, not an attacker.
    """
    minutes = max(1, int(retry_after // 60))
    return ("You have sent several submissions recently, so this one was not "
            "accepted. Please try again in about %d minute%s. If this is "
            "urgent, that limit is not a judgement about what you sent."
            % (minutes, "" if minutes == 1 else "s"))
