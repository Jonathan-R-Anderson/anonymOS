"""Which origin gateway placed a DHT object. First write wins.

WHY THIS EXISTS
---------------
The coordinator signs two kinds of token for storage nodes: a lease ("this peer
may hold these bytes") and a revocation ("this peer must drop them"). Until this
table existed the site persisted no DHT object id at all, so the coordinator had
no way to answer the only question a delete token needs answered -- does the
peer asking for it own the object? -- and `_check_object_origin` was reduced to a
tautology: with one authorised origin the requester is necessarily the owner, so
sign; with two or more, refuse everything.

The moment the coordinator ever learns who placed an object is the lease request.
`issue_lease` is handed (requester, object_id, shard_id) for every shard of every
object and used to discard all three. It now writes a row here on the first
lease for an object, and `_check_object_origin` reads it.

WHY FIRST WRITE WINS, AND WHAT A SECOND CLAIMANT GETS
-----------------------------------------------------
An object id is `sha256(canonical manifest)` on the node
(storage-client/internal/store/store.go), and the manifest includes `CreatedAt`
at nanosecond resolution -- so two origins storing byte-identical content do NOT
collide, and a second origin arriving with an object id that already has a row
is an anomaly rather than deduplication.

It is still not refused. A lease authorises a WRITE, and refusing writes is the
direction that loses data: if there is ever a legitimate second writer (a
topology where repair or rebalance is driven by a peer other than the original
placer, a gateway identity rotated mid-dispersal) then refusing turns an
ownership question into an under-replicated object. The lease is signed, the
ownership row is left alone, and the attempt is counted on the row so an operator
can see a contested object without grepping logs. The consequence for the second
origin is exactly the one that matters: it can add bytes, and it can never obtain
a delete token for them, because the row still names somebody else.

The write side cannot be abused into granting delete authority either. There is
no path here that ever REPLACES `requester`; the only way to become the owner of
an object id is to be the first to lease it, which for a
`sha256(manifest-with-timestamp)` means to have actually created it.
"""

import datetime as _datetime
import logging as _logging

from sqlalchemy.exc import IntegrityError

from shared import db


# stdlib logging rather than app.logger, deliberately: the root logger is
# configured by maniwani_logging.setup_logging() so the lines land in the same
# place, and this module stays exercisable without booting the Flask app.
_logger = _logging.getLogger(__name__)


class DhtObjectOwner(db.Model):
    __tablename__ = "dht_object_owner"

    # The DHT object id: 64 lowercase hex characters, validated by the caller
    # (services/storage_coordination.HEX_ID) before it ever reaches here.
    object_id = db.Column(db.String(64), primary_key=True)

    # The libp2p peer id of the origin gateway that first leased this object.
    # Indexed so "what does this origin own" is answerable, which is what an
    # operator asks when an origin key has to be retired.
    requester = db.Column(db.String(128), nullable=False, index=True)

    first_leased_at = db.Column(
        db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True
    )

    # A different origin asked for a lease on an object this row already owns.
    # Recorded rather than merely logged: a contested object is the shape an
    # attempt to hijack delete authority would take, and a fact that only exists
    # in a log line is a fact nobody reads. `contested()` below is the query;
    # nothing renders it on the admin page yet.
    contested_count = db.Column(
        db.Integer, nullable=False, default=0, server_default="0"
    )
    contested_by = db.Column(db.String(128), nullable=True)
    contested_at = db.Column(db.DateTime, nullable=True)


def owner_of(object_id):
    """The peer id that owns this object, or None if no row was ever written.

    Raises whatever the database raises. The caller MUST NOT collapse that into
    None: "the table could not be read" is not "nobody owns this", and the
    difference decides whether a delete token gets signed. That exact conflation
    -- a read failure rendered as an empty record -- is fault F6 of this feature's
    own security review, on the node side. It is not repeated here.
    """
    row = (
        db.session.query(DhtObjectOwner)
        .filter(DhtObjectOwner.object_id == str(object_id or ""))
        .one_or_none()
    )
    return row.requester if row is not None else None


def record_owner(object_id, requester):
    """Record `requester` as the owner of `object_id` unless somebody already is.

    Returns (owner, outcome) where outcome is one of:
        "recorded"   -- this call created the row
        "unchanged"  -- the row already named this requester
        "contested"  -- the row names a DIFFERENT origin; it was NOT changed

    First-write-wins is enforced by the primary key rather than by a read
    followed by a write: several shards of one object are leased concurrently
    (a 40 MB object is hundreds of shards, and the site runs 200 gevent workers),
    so the read-then-insert race is the normal case here, not an edge one. The
    loser of that race gets an IntegrityError and re-reads.
    """
    object_id = str(object_id or "")
    requester = str(requester or "")
    if not object_id or not requester:
        raise ValueError("an ownership record needs both an object id and a requester")

    row = (
        db.session.query(DhtObjectOwner)
        .filter(DhtObjectOwner.object_id == object_id)
        .one_or_none()
    )
    if row is None:
        db.session.add(DhtObjectOwner(object_id=object_id, requester=requester))
        try:
            db.session.commit()
            return requester, "recorded"
        except IntegrityError:
            # Somebody inserted the same object id between the read and the
            # commit. That peer is the owner now; fall through and treat this
            # call as a later lease.
            db.session.rollback()
            row = (
                db.session.query(DhtObjectOwner)
                .filter(DhtObjectOwner.object_id == object_id)
                .one_or_none()
            )
            if row is None:
                # The insert was refused for some reason other than the primary
                # key. Do not pretend an owner was recorded.
                raise

    if row.requester == requester:
        return row.requester, "unchanged"

    row.contested_count = (row.contested_count or 0) + 1
    row.contested_by = requester
    row.contested_at = _datetime.datetime.utcnow()
    db.session.commit()
    _logger.warning(
        "dht ownership: %s requested a lease for object %s, which %s owns; "
        "the lease stands and ownership does not move (contested %d time(s))",
        requester, object_id, row.requester, row.contested_count,
    )
    return row.requester, "contested"


def contested(limit=50):
    """Objects a second origin has tried to lease. For an operator, not a caller."""
    return (
        db.session.query(DhtObjectOwner)
        .filter(DhtObjectOwner.contested_count > 0)
        .order_by(DhtObjectOwner.contested_at.desc())
        .limit(limit)
        .all()
    )
