"""Whether a peer's I2P destination still answers, measured over I2P.

WHY THIS TABLE EXISTS
---------------------
Everything the site knew about a node came from its heartbeat, and the heartbeat
is deliberately CLEARNET -- the storage client documents it as "the one
connection that does not go through I2P". A heartbeat therefore proves the
process is running and its clearnet egress works. It proves nothing at all about
whether the node's garlic destination still publishes a LeaseSet.

That gap is not theoretical. Five volunteer nodes heartbeated perfectly, all
appeared in the `compute` list, and every one of them failed to reach the two
destinations the bootstrap document handed them:

    I2P stream connect failed: RESULT=CANT_REACH_PEER MESSAGE="LeaseSet not found"

This table holds the signal the heartbeat cannot carry.

A ROW IS A DESTINATION, NOT A NODE
----------------------------------
The configured bootstrap seed has no storage_node row at all, and two rows can
name the same destination. Keying on the destination means one dial per distinct
address, and no way for two rows about the same address to disagree.

NOTHING HERE DELETES A NODE
---------------------------
A withheld node still counts for active_nodes, capacity and the compute market.
Only its dialable address is suppressed, only while it keeps failing, and one
successful probe puts it straight back -- see apply_probe.
"""

import datetime as _datetime

from shared import db


# Three strikes, and the number is deliberately a name rather than a literal in
# a loop: it is the whole eviction policy. A probe can legitimately fail once --
# the node's I2P listener issues STREAM ACCEPT serially and sleeps after an
# accept error, so a probe can arrive in a gap on a perfectly healthy node.
# Three consecutive failures across three sweeps is ~15 minutes of a destination
# refusing to answer anybody, which is no longer a blip.
MAX_CONSECUTIVE_FAILURES = 3

# How old a verdict may be and still be acted on. If the prober stops (its
# worker died, the leader lock moved, the I2P proxy went away) the verdicts it
# left behind must expire, or peers stay withheld forever on the strength of a
# measurement nobody is taking any more. Past this age every peer is served
# again -- failing OPEN is the whole safety posture of this feature.
VERDICT_MAX_AGE_SECONDS = 3600

# The three outcomes a probe can have. GONE and UNHEALTHY both count as
# failures, but they mean very different things to whoever debugs this next:
#   GONE      -- the LeaseSet did not resolve. The node behind the destination
#                is not on the network at all.
#   UNHEALTHY -- the stream came up, so the destination is published and the
#                router reached it, but the peer said nothing. Reachable and
#                broken, which is a node to look at rather than a node to
#                forget.
STATE_LIVE = "live"
STATE_GONE = "gone"
STATE_UNHEALTHY = "unhealthy"


class PeerLiveness(db.Model):
    __tablename__ = "peer_liveness"

    # The bare 52-character base32 garlic destination, exactly as a node reports
    # it in its heartbeat and exactly as it appears inside a /garlic32/ multiaddr.
    destination = db.Column(db.String(70), primary_key=True)
    first_probed_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow
    )
    last_probe_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True
    )
    # Null until the destination has answered once. A destination that has NEVER
    # answered is still served until it has failed MAX_CONSECUTIVE_FAILURES
    # times, because "we have never managed to probe it" is a statement about
    # the prober as much as about the peer.
    last_ok_at = db.Column(db.DateTime, nullable=True)
    consecutive_failures = db.Column(
        db.Integer, nullable=False, default=0, server_default="0"
    )
    last_state = db.Column(db.String(16), nullable=False, default=STATE_LIVE)


def apply_probe(row, state, now=None):
    """Fold one probe result into a liveness row, in place.

    Pure bookkeeping so the eviction policy can be read (and tested) without a
    database. The counter RESETS on any success: a count that only ever rose
    would evict every peer on the network eventually, which is precisely the
    failure this whole change exists to prevent.
    """
    now = now or _datetime.datetime.utcnow()
    row.last_probe_at = now
    row.last_state = state
    if state == STATE_LIVE:
        row.consecutive_failures = 0
        row.last_ok_at = now
    else:
        row.consecutive_failures = int(row.consecutive_failures or 0) + 1
    return row


def is_unreachable(row, now=None):
    """True once a destination has missed MAX_CONSECUTIVE_FAILURES probes in a
    row AND that verdict is recent enough to still mean something."""
    if row is None:
        return False
    if int(row.consecutive_failures or 0) < MAX_CONSECUTIVE_FAILURES:
        return False
    now = now or _datetime.datetime.utcnow()
    last = row.last_probe_at
    if last is None:
        return False
    return (now - last).total_seconds() <= VERDICT_MAX_AGE_SECONDS


def record_probe(destination, state, now=None):
    """Persist one probe result. Caller commits."""
    destination = (destination or "").strip().lower()
    if not destination:
        return None
    now = now or _datetime.datetime.utcnow()
    row = db.session.query(PeerLiveness).get(destination)
    if row is None:
        row = PeerLiveness(
            destination=destination,
            first_probed_at=now,
            last_probe_at=now,
            consecutive_failures=0,
            last_state=state,
        )
    apply_probe(row, state, now=now)
    db.session.add(row)
    return row


def unreachable_destinations(now=None):
    """The destinations to withhold: struck out three times, recently measured.

    Mirrors is_unreachable() in SQL so the request path is one indexed query
    rather than a scan through Python objects.
    """
    now = now or _datetime.datetime.utcnow()
    cutoff = now - _datetime.timedelta(seconds=VERDICT_MAX_AGE_SECONDS)
    rows = (
        db.session.query(PeerLiveness.destination)
        .filter(
            PeerLiveness.consecutive_failures >= MAX_CONSECUTIVE_FAILURES,
            PeerLiveness.last_probe_at >= cutoff,
        )
        .all()
    )
    return {row[0] for row in rows}


def liveness_states(now=None):
    """Every current verdict, for the admin/debug view. Never raises callers."""
    rows = db.session.query(PeerLiveness).all()
    return [
        {
            "destination": row.destination,
            "state": row.last_state,
            "consecutive_failures": int(row.consecutive_failures or 0),
            "withheld": is_unreachable(row, now=now),
            "last_probe_at": row.last_probe_at,
            "last_ok_at": row.last_ok_at,
        }
        for row in rows
    ]
