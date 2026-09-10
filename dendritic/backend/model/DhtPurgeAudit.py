"""Who purged what out of the storage DHT, when, and how far it actually got.

WHY THIS IS ITS OWN TABLE
-------------------------
Nothing else in the codebase records an admin action. GatewayAudit is a record
of what a gateway SERVED (an observation about a peer, deduplicated so it cannot
be farmed); ThreatEvent and SourceStrikeEvent are about visitors and scraped
sources. None of them can answer "who deleted this, and what did they see before
they clicked".

WHY THE RESULT IS STORED VERBATIM
---------------------------------
A purge touches several independent layers and reaches some of them and not
others -- and "not others" is permanent. Collapsing that into a boolean would
turn the one fact worth keeping ("the remote shards were never recalled") into
"purged: true", which is the exact misreading this whole feature exists to
prevent. So the per-layer outcome is stored as JSON, as reported at the time,
and the row is written whether the purge succeeded, half-succeeded or failed.

The audit row is written EVEN WHEN NOTHING WAS DELETED. An attempted purge that
found nothing is still an admin reaching for the destructive button, and a log
that only records successes cannot be used to reconstruct what happened.
"""

import datetime as _datetime
import json as _json

from shared import db


class DhtPurgeAudit(db.Model):
    __tablename__ = "dht_purge_audit"

    id = db.Column(db.Integer, primary_key=True)

    # The canonical target string the admin confirmed, e.g. "media:4821" or
    # "attachments/1/2/3/4821.png". Stored as typed-and-normalised rather than
    # split into columns: a target that cannot be reproduced verbatim cannot be
    # checked against later.
    target = db.Column(db.String(512), nullable=False, index=True)
    target_kind = db.Column(db.String(16), nullable=False, default="object")

    # Who. Both are recorded because they answer different questions: the slip
    # is the session, the wallet is the human the admin gate actually trusts.
    acting_slip_id = db.Column(db.Integer, nullable=True, index=True)
    acting_wallet = db.Column(db.String(64), nullable=True)
    acting_ip = db.Column(db.String(64), nullable=True)

    reason = db.Column(db.String(512), nullable=True)

    # Highest-level summary, for filtering. NOT a substitute for `layers`.
    #   purged          -- at least one object was actually deleted somewhere
    #   partial         -- a recall reached some holders and not others
    #   nothing_found   -- the target resolved but held nothing to delete
    #   failed          -- every layer that was attempted errored
    #   refused         -- confirmation did not match; nothing was touched
    outcome = db.Column(db.String(24), nullable=False, default="purged", index=True)

    # The per-layer report, verbatim. See services/dht_object_purge.py.
    layers_json = db.Column(db.Text, nullable=False, default="[]")

    # TRUE only when a holder CONFIRMED it removed a shard.
    #
    # Written false for every row until the recall protocol existed, which is
    # what makes historic rows still readable: a row with this false is a purge
    # that provably never reached the network, whether because the verb did not
    # exist yet or because no holder answered. It is deliberately not set by
    # "a recall was attempted" or "the endpoint replied" -- a generous reading
    # would destroy the only thing the column is for. Never backfilled.
    remote_shards_recalled = db.Column(
        db.Boolean, nullable=False, default=False, server_default="false"
    )

    created_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True
    )

    @property
    def layers(self):
        try:
            return _json.loads(self.layers_json or "[]")
        except ValueError:
            return []


def record(target, target_kind, layers, outcome, reason=None,
           acting_slip_id=None, acting_wallet=None, acting_ip=None,
           remote_shards_recalled=False):
    """Write one audit row. Never raises into the caller.

    A purge that succeeded and an audit write that failed is worse than either
    alone, so the exception is logged and swallowed -- but it is logged at
    ERROR, because an unaudited purge is a real hole and not a cosmetic one.
    """
    from shared import app

    row = DhtPurgeAudit(
        target=(target or "")[:512],
        target_kind=(target_kind or "object")[:16],
        acting_slip_id=acting_slip_id,
        acting_wallet=(acting_wallet or None) and str(acting_wallet)[:64],
        acting_ip=(acting_ip or None) and str(acting_ip)[:64],
        reason=(reason or None) and str(reason)[:512],
        outcome=(outcome or "purged")[:24],
        layers_json=_json.dumps(layers or [])[:1000000],
        remote_shards_recalled=bool(remote_shards_recalled),
    )
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.error("dht purge: AUDIT WRITE FAILED for target %s", target,
                         exc_info=True)
        return None
    return row


def recent(limit=50):
    return (
        db.session.query(DhtPurgeAudit)
        .order_by(DhtPurgeAudit.id.desc())
        .limit(limit)
        .all()
    )
