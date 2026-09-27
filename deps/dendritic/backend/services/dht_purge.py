"""Delete the LOCAL copy of media that is already on the DHT.

This is the destructive half of the migration, so the gate is per-object rather
than per-run: an object's local bytes are removed only after ITS OWN bytes have
been read back through the DHT path and matched against the digest recorded in
the database. A batch that verifies 40 objects and deletes 41 is the failure
mode worth designing against, so nothing is deleted on aggregate confidence.

WHAT THIS DOES NOT PROVE. Reads are served by the storage node, which still
holds every shard in its own local store; FetchShard only goes to a peer for a
shard it lacks. So a pass here shows the bytes are retrievable, not that they
would survive the storage node losing them. See services/dht_validation.py --
that is the tier-2 question, and it is not answered by anything in this file.

Idempotent: verification reads come from the DHT, so re-running after a
successful purge verifies and finds nothing left to delete locally.
"""
import hashlib

from shared import app, db


def _offloaded_batch(limit):
    from model.Media import Media

    return (
        db.session.query(Media)
        .filter(Media.dht_offloaded_at.isnot(None))
        .order_by(Media.id.asc())
        .limit(limit)
        .all()
    )


def purge_offloaded(limit=200, dry_run=True):
    """Verify then delete local copies. Dry run by default -- deleting is the
    kind of thing that should have to be asked for explicitly."""
    import services.media_read as media_read
    from model.Media import storage as primary

    summary = {
        "examined": 0, "verified": 0, "deleted": 0,
        "skipped_unreadable": 0, "skipped_digest": 0,
        "skipped_no_digest": 0, "delete_failed": 0,
        "dry_run": bool(dry_run), "freed_bytes": 0,
    }
    for media in _offloaded_batch(limit):
        summary["examined"] += 1
        try:
            data = media_read.attachment_bytes(media.id, media.ext)
        except Exception:
            summary["skipped_unreadable"] += 1
            continue
        if not data:
            # Marked offloaded but not retrievable. Deleting the local copy
            # here is exactly how the migration would lose a file.
            summary["skipped_unreadable"] += 1
            continue
        if not media.sha256:
            # Readable but nothing to compare against. Not proof, so not
            # grounds for deleting the only other copy.
            summary["skipped_no_digest"] += 1
            continue
        if hashlib.sha256(data).hexdigest() != media.sha256:
            summary["skipped_digest"] += 1
            app.logger.error(
                "dht purge: digest mismatch for media %s -- NOT deleting", media.id
            )
            continue
        summary["verified"] += 1
        if dry_run:
            continue
        try:
            primary.delete_attachment(media.id, media.ext)
        except Exception:
            summary["delete_failed"] += 1
            app.logger.exception("dht purge: could not delete local media %s", media.id)
            continue
        summary["deleted"] += 1
        summary["freed_bytes"] += len(data)
    return summary
