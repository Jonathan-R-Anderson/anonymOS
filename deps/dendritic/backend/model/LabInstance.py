"""A user's Attack Range lab instance, spun up on the decentralized container
service (DCS) and reachable only over its private I2P address.

This is the SITE's record of a lab instance. The container itself runs on a
volunteer DCS worker somewhere on the network; the site holds the lifecycle
state a user sees: queued/running/expired, their place in line, the countdown,
and the private .b32.i2p the researcher points their tools at.

The rules the user asked for are enforced HERE, at the site, on top of whatever
the worker also enforces:

  * ONE active instance per slip (single_active_for).
  * Auto spin-down after 24h (expires_at; the reaper query returns the expired).
  * Many users may run the SAME image at once (the uniqueness is per-slip, not
    per-image).
"""
import datetime as _datetime

from shared import db

# The hard lifetime of any lab instance. Mirrors the DCS worker's general TTL;
# the site also refuses to show/return an instance past this, so a forgotten
# vulnerable box disappears from the UI even if a worker were slow to reap it.
LAB_TTL = _datetime.timedelta(hours=24)

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_EXPIRED = "expired"
STATUS_FAILED = "failed"


class LabInstance(db.Model):
    __tablename__ = "lab_instance"

    id = db.Column(db.Integer, primary_key=True)
    slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=False, index=True)

    # What was requested. image_key names an Attack Range profile (see
    # services.attack_range.PROFILES); build_digest is the DHT-sharded build
    # context the worker builds.
    image_key = db.Column(db.String(64), nullable=False)
    build_digest = db.Column(db.String(80), nullable=True)

    status = db.Column(db.String(16), nullable=False, default=STATUS_QUEUED, index=True)

    # Where it landed and how to reach it. i2p_address is the private
    # destination disclosed to this user alone. worker_destination is the
    # worker's OWN garlic address (not the container's) -- the bridge needs it,
    # alongside worker_node_id, to reopen an RPC stream to that exact worker when
    # polling the queue or destroying the container. container_id is the id the
    # worker assigned; destroy targets it (NOT the site's row id).
    worker_node_id = db.Column(db.String(80), nullable=True)
    worker_destination = db.Column(db.String(70), nullable=True)
    container_id = db.Column(db.String(80), nullable=True)
    i2p_address = db.Column(db.String(70), nullable=True)

    # Queue state, shown as a live countdown while status == queued.
    ticket = db.Column(db.String(64), nullable=True)
    queue_position = db.Column(db.Integer, nullable=True)
    eta_seconds = db.Column(db.Integer, nullable=True)

    note = db.Column(db.String(255), nullable=True)

    # A per-boot random secret the worker injects into this instance's container
    # as an env var. The correct answer to an "instance_secret" lab question is
    # checked against this, so the answer is unique per boot and can't be shared
    # (see services.attack_range.spin_up and model.LabQuestion).
    container_password = db.Column(db.String(64), nullable=True)

    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)
    # When the site will consider it spun down. Set on transition to running.
    expires_at = db.Column(db.DateTime, nullable=True)

    slip = db.relationship("Slip", backref=db.backref("lab_instances", cascade="all, delete-orphan"))

    @property
    def is_active(self):
        """Queued or running and not past its TTL."""
        if self.status not in (STATUS_QUEUED, STATUS_RUNNING):
            return False
        if self.expires_at and self.expires_at <= _datetime.datetime.utcnow():
            return False
        return True

    @property
    def seconds_remaining(self):
        """Seconds until auto spin-down, or None while still queued."""
        if not self.expires_at:
            return None
        delta = (self.expires_at - _datetime.datetime.utcnow()).total_seconds()
        return max(0, int(delta))

    def to_dict(self):
        return {
            "id": self.id,
            "image_key": self.image_key,
            "status": self.status,
            "worker_node_id": self.worker_node_id,
            "i2p_address": self.i2p_address,
            "queue_position": self.queue_position,
            "eta_seconds": self.eta_seconds,
            "seconds_remaining": self.seconds_remaining,
            "note": self.note,
            "expires_at": self.expires_at.isoformat() + "Z" if self.expires_at else None,
        }


def single_active_for(slip_id):
    """The slip's one active lab instance, or None. Enforces the per-user limit:
    callers refuse to spin up a second while this returns non-None."""
    now = _datetime.datetime.utcnow()
    return (
        db.session.query(LabInstance)
        .filter(
            LabInstance.slip_id == slip_id,
            LabInstance.status.in_((STATUS_QUEUED, STATUS_RUNNING)),
            db.or_(LabInstance.expires_at.is_(None), LabInstance.expires_at > now),
        )
        .order_by(LabInstance.created_at.desc())
        .first()
    )


def expired_active_instances(limit=100):
    """Active rows whose TTL has passed -- the site-side reaper marks these
    spun-down so the UI never shows a box that should be gone."""
    now = _datetime.datetime.utcnow()
    return (
        db.session.query(LabInstance)
        .filter(
            LabInstance.status.in_((STATUS_QUEUED, STATUS_RUNNING)),
            LabInstance.expires_at.isnot(None),
            LabInstance.expires_at <= now,
        )
        .limit(limit)
        .all()
    )
