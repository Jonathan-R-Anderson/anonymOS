"""Client for the headless Orange3 workflow engine (ml-runner service).

The engine runs in its own pod with no network egress and hard limits on what a
workflow may cost. This module is the only thing that talks to it, and it adds
the one control the engine cannot: a per-caller rate limit, because /ml needs no
account and "how often" is decided entirely by whoever is asking.
"""

import os
import time

import requests

from shared import app

RUNNER_URL = os.environ.get("ML_RUNNER_URL", "http://ml-runner:8000")

# Longer than the engine's own wall clock, so a workflow that the engine kills
# comes back as ITS honest timeout message rather than as our connection giving
# up first — the difference between "your workflow was too slow" and "the
# machine-learning service is down", which are not the same thing to a user.
TIMEOUT = int(os.environ.get("ML_RUNNER_TIMEOUT", "35"))

# Per-IP rate limit. Deliberately generous for a person clicking Run and
# restrictive for a script: an anonymous ML endpoint is CPU somebody else is
# paying for, and the cost of being wrong in the strict direction is one
# apologetic message.
RATE_WINDOW_SECONDS = 60
RATE_MAX_RUNS = 20

_recent = {}


class MLRunnerError(RuntimeError):
    pass


def configured():
    return bool(RUNNER_URL)


def rate_limit(key):
    """(allowed, retry_after_seconds).

    Kept in memory on purpose: a rate limiter that needs a round trip to Redis
    to decide whether to do work is itself work, and losing the counts on a
    restart costs one burst rather than anything that matters.
    """
    now = time.time()
    cutoff = now - RATE_WINDOW_SECONDS
    hits = [stamp for stamp in _recent.get(key, ()) if stamp > cutoff]
    if len(hits) >= RATE_MAX_RUNS:
        _recent[key] = hits
        return False, int(RATE_WINDOW_SECONDS - (now - hits[0])) + 1
    hits.append(now)
    _recent[key] = hits
    # Opportunistic sweep so an endpoint nobody rate-limits does not accumulate
    # a key per visitor forever.
    if len(_recent) > 4096:
        for other, stamps in list(_recent.items()):
            if not [s for s in stamps if s > cutoff]:
                _recent.pop(other, None)
    return True, 0


def catalogue():
    """Datasets and learners the engine offers. None if it cannot be reached."""
    try:
        response = requests.get(RUNNER_URL + "/catalogue", timeout=8)
        response.raise_for_status()
        return response.json()
    except Exception as exc:
        app.logger.warning("ml-runner catalogue unavailable: %s", exc)
        return None


def run(workflow):
    """Execute a workflow. Raises MLRunnerError when the engine cannot answer."""
    try:
        response = requests.post(RUNNER_URL + "/run", json=workflow, timeout=TIMEOUT)
    except requests.Timeout:
        raise MLRunnerError(
            "The workflow engine did not answer in time. Try a smaller dataset "
            "or fewer folds.")
    except Exception as exc:
        raise MLRunnerError("The workflow engine is not reachable: %s" % exc)

    try:
        body = response.json()
    except ValueError:
        raise MLRunnerError("The workflow engine returned something unreadable.")
    if response.status_code >= 400 and not body.get("error"):
        raise MLRunnerError("The workflow engine refused the request (HTTP %d)."
                            % response.status_code)
    return body
