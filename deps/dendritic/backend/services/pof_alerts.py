"""Telling the operator an epoch is waiting to be settled.

An epoch whose challenge window has closed with no disputes can be finalized by
anyone, and until somebody does, `rewardRootOf` returns zero and nothing is
claimable. Nothing in this system was watching for that. Epoch 0 sat a full day
past its deadline because the page described the call without ever offering it
and no code path made it — a settlement that silently does not happen.

WHY THIS IS CACHED AND NOT READ PER REQUEST
-------------------------------------------
The bell polls. Reading the chain on every poll would put a JSON-RPC round trip
to an external node inside a navbar render, on every page, for every admin — and
this project has already taken an outage from putting a network call inside a
page render. A slow or unreachable RPC would then make the whole site feel
broken rather than making one badge stale.

So the answer is computed at most once every REFRESH_SECONDS and cached in
memory. Stale by minutes is fine: the thing being watched has a challenge window
measured in a day.

WHAT IT DOES NOT DO
-------------------
It does not finalize. That is a transaction, and this server holds no signing
key — deliberately, because automating it would mean a funded hot wallet on the
origin. The alert exists so a human with a wallet knows to act.
"""

import threading
import time

from shared import app

# The bell polls every few seconds; the chain moves in epochs. Anything under a
# minute is pure waste against an external RPC.
REFRESH_SECONDS = 180

_lock = threading.Lock()
_cached = {"at": 0.0, "alerts": []}


def _epoch_manager():
    try:
        from services.pof_chain import pof_addresses

        return (pof_addresses() or {}).get("EpochManager") or ""
    except Exception:
        return ""


def _compute(now):
    """Epochs that can be finalized right now. Never raises."""
    manager = _epoch_manager()
    if not manager:
        return []
    try:
        from services.pof_chain import epoch_chain

        rows = epoch_chain(manager, limit=25) or []
    except Exception:
        # An unreachable RPC is not an alert. Reporting "no epochs need
        # finalizing" when the truth is "we could not look" would be worse than
        # silence, but so would inventing an alarm — so this stays quiet and
        # tries again on the next refresh.
        app.logger.debug("pof alerts: could not read the epoch chain",
                         exc_info=True)
        return []

    alerts = []
    for row in rows:
        try:
            if row.get("finalized") or row.get("open_disputes"):
                continue
            deadline = int(row.get("challenge_deadline") or 0)
            if not deadline or deadline > now:
                continue
            rewards = int(row.get("total_rewards") or 0)
            alerts.append({
                "epoch": int(row.get("epoch") or 0),
                "deadline": deadline,
                "overdue_seconds": max(0, int(now) - deadline),
                # Carried so the operator is not sent to sign a transaction
                # that pays nobody without being told first. An epoch with no
                # rewards is still worth closing, but it is not urgent and
                # saying otherwise wastes their attention and their gas.
                "total_rewards": rewards,
                "pays_anyone": rewards > 0,
            })
        except (TypeError, ValueError):
            continue
    return alerts


def finalizable(now=None, force=False):
    """Epochs awaiting finalization, from cache. Refreshes at most rarely."""
    now = int(now or time.time())
    with _lock:
        fresh = (now - _cached["at"]) < REFRESH_SECONDS
        if fresh and not force:
            return list(_cached["alerts"])
    alerts = _compute(now)
    with _lock:
        _cached["at"] = now
        _cached["alerts"] = alerts
    return list(alerts)


def describe(alert):
    """One line an operator can act on, without opening a block explorer."""
    overdue = int(alert.get("overdue_seconds") or 0)
    if overdue < 3600:
        when = "%d minutes" % max(1, overdue // 60)
    elif overdue < 172800:
        when = "%d hours" % (overdue // 3600)
    else:
        when = "%d days" % (overdue // 86400)
    if alert.get("pays_anyone"):
        return ("Epoch %d has been finalizable for %s. Until it is finalized "
                "nothing from it is claimable." % (alert.get("epoch"), when))
    return ("Epoch %d has been finalizable for %s. It carries no rewards, so "
            "finalizing closes it but pays nobody." % (alert.get("epoch"), when))
