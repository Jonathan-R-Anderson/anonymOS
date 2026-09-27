"""
Purge media DB records that have no backing S3 object.

Clears ImportedMedia mappings and nullifies post.media references so the
aggregator will re-scrape and re-upload those images directly to S3.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from shared import app, db
from model.Media import Media, S3Storage, MissingAttachmentError


def purge_orphans():
    with app.app_context():
        s3 = S3Storage()

        medias = db.session.query(Media).all()
        print(f"[purge] Found {len(medias)} total media records.")

        orphan_ids = []
        for media in medias:
            try:
                s3.read_attachment_bytes(media.id, media.ext)
                print(f"[purge] OK  media_id={media.id} ({media.id}.{media.ext}) — exists in S3")
            except MissingAttachmentError:
                print(f"[purge] ORPHAN media_id={media.id} ({media.id}.{media.ext}) — missing from S3")
                orphan_ids.append(media.id)
            except Exception as exc:
                print(f"[purge] ERROR media_id={media.id}: {exc}")
                orphan_ids.append(media.id)

        if not orphan_ids:
            print("[purge] No orphans found. Nothing to clean up.")
            return

        print(f"\n[purge] Purging {len(orphan_ids)} orphaned media records: {orphan_ids}")

        # 1. Nullify Post.media FK references
        try:
            from model.Post import Post
            updated = db.session.query(Post).filter(Post.media.in_(orphan_ids)).update(
                {Post.media: None}, synchronize_session=False
            )
            print(f"[purge] Nullified {updated} post.media references.")
        except Exception as exc:
            print(f"[purge] WARNING: could not nullify post.media: {exc}")

        # 2. Delete ImportedMedia mappings that reference these media IDs
        try:
            from model.ImportedMedia import ImportedMedia
            deleted_im = db.session.query(ImportedMedia).filter(
                ImportedMedia.media_id.in_(orphan_ids)
            ).delete(synchronize_session=False)
            print(f"[purge] Deleted {deleted_im} ImportedMedia mappings.")
        except Exception as exc:
            print(f"[purge] WARNING: could not delete ImportedMedia: {exc}")

        # 3. Delete ImageMagnet entries
        try:
            from model.ImageMagnet import ImageMagnet
            deleted_mag = db.session.query(ImageMagnet).filter(
                ImageMagnet.media_id.in_(orphan_ids)
            ).delete(synchronize_session=False)
            print(f"[purge] Deleted {deleted_mag} ImageMagnet entries.")
        except Exception as exc:
            print(f"[purge] WARNING: could not delete ImageMagnet: {exc}")

        # 4. Delete the orphaned Media rows themselves
        deleted_m = db.session.query(Media).filter(Media.id.in_(orphan_ids)).delete(
            synchronize_session=False
        )
        print(f"[purge] Deleted {deleted_m} Media rows.")

        db.session.commit()
        print("\n[purge] Done. The aggregator will re-scrape and upload these images to S3 on next sync.")


if __name__ == "__main__":
    purge_orphans()
