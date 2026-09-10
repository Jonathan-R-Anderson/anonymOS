"""Publishing the arcade's static content to the DHT, and keeping it there.

WHAT THIS EXISTS FOR
--------------------
The arcade accumulated a lot of content that lived only on this server: the
codeplay collections (admin-editable, generated, and NOT in git), and the
school's ten courses and vocabulary (in git, but only servable from here). The
DHT is this project's store — see the codeplay publisher this is modelled on —
and content that is not on it is content one disk failure away from gone, or one
outage away from unreachable.

This publishes:

  codeplay/<collection>.json   via services.codeplay_content (already existed,
                               was simply never being called)
  arcade/school/<slug>.json    one document per course, chapters included
  arcade/vocabulary.json       the 205 graded terms
  arcade/index.json            what was published, when, and with what digest

WHY EACH DOCUMENT IS CONTENT-ADDRESSED AND RECORDED
---------------------------------------------------
Every document's sha256 is stored in a SiteSetting after a successful put. That
gives two things: a publish that has not changed anything can skip the upload,
and there is a local record of exactly which bytes are supposed to be out there.
Without the digest a "published" flag means only "we once called put", which is
the weaker claim and the one that rots silently.

WHAT THIS DELIBERATELY DOES NOT DO
----------------------------------
It does not delete the local copy of anything. The node bridge exposes PUT on
/dcs/blob and no GET, so nothing here can read a published object back to
confirm it is retrievable. Publishing without a read-back is a one-way
assertion, and deleting a local copy on the strength of one would be trading a
verified copy for an unverified one. When a fetch endpoint exists, the reclaim
step belongs next to this and not before it.
"""

import hashlib
import json

from shared import app, db

_BUCKET = "arcade"
_DIGEST_KEY = "arcade_dht_%s"


def _client():
    """The S3-compatible DHT gateway client, or None when unconfigured.

    Reuses the codeplay publisher's client so there is one place that knows the
    endpoint, the credentials and the addressing style.
    """
    from services.codeplay_content import _s3_client
    return _s3_client()


def _bucket_name():
    prefix = (app.config.get("DHT_S3_UUID_PREFIX") or "").strip()
    return (prefix + _BUCKET) if prefix else _BUCKET


def _ensure_bucket(client, bucket):
    try:
        client.head_bucket(Bucket=bucket)
        return True
    except Exception:
        try:
            client.create_bucket(Bucket=bucket)
            return True
        except Exception:
            app.logger.exception("arcade_publish: cannot ensure bucket %s", bucket)
            return False


def _documents():
    """[(key, bytes)] — everything this module publishes.

    Serialised with sort_keys so the same content always produces the same
    bytes and therefore the same digest. Without that, an unchanged course
    would republish on every sweep because a dict iterated differently.
    """
    from services import school as course
    from services import vocab as glossary

    docs = []
    index = {"school": [], "vocabulary": None}

    for subject in course.subjects():
        body = json.dumps({
            "slug": subject["slug"],
            "title": subject["title"],
            "subtitle": subject.get("subtitle", ""),
            "blurb": subject.get("blurb", ""),
            "reference": subject.get("reference", ""),
            "provenance": subject.get("provenance", ""),
            "parts": subject["parts"],
        }, ensure_ascii=False, sort_keys=True).encode("utf-8")
        key = "school/%s.json" % subject["slug"]
        docs.append((key, body))
        index["school"].append({
            "slug": subject["slug"],
            "title": subject["title"],
            "chapters": course.total_chapters(subject),
            "key": key,
            "sha256": hashlib.sha256(body).hexdigest(),
        })

    terms = json.dumps({"terms": glossary.all_terms()},
                       ensure_ascii=False, sort_keys=True).encode("utf-8")
    docs.append(("vocabulary.json", terms))
    index["vocabulary"] = {
        "key": "vocabulary.json",
        "terms": len(glossary.all_terms()),
        "sha256": hashlib.sha256(terms).hexdigest(),
    }

    # The index goes last and names everything above, so a reader fetching one
    # object learns what else exists without listing the bucket.
    docs.append(("index.json",
                 json.dumps(index, ensure_ascii=False, sort_keys=True).encode("utf-8")))
    return docs


def publish(force=False):
    """Publish the arcade's static content. Returns {key: sha256} for what went.

    Unchanged documents are skipped unless `force`, because this runs on a timer
    and re-uploading ten identical courses every sweep is load on the network
    for no gain.
    """
    from model.SiteSetting import get_setting, set_setting

    client = _client()
    if client is None:
        app.logger.info("arcade_publish: no DHT gateway configured; skipping")
        return {}
    bucket = _bucket_name()
    if not _ensure_bucket(client, bucket):
        return {}

    published, skipped = {}, 0
    for key, body in _documents():
        digest = hashlib.sha256(body).hexdigest()
        setting = _DIGEST_KEY % key
        if not force and get_setting(setting, "") == digest:
            skipped += 1
            continue
        try:
            client.put_object(Bucket=bucket, Key=key, Body=body,
                              ContentType="application/json")
        except Exception:
            app.logger.exception("arcade_publish: failed to publish %s", key)
            continue
        set_setting(setting, digest)
        published[key] = digest

    if published:
        db.session.commit()
    app.logger.info("arcade_publish: %d published, %d unchanged", len(published), skipped)
    return published


def status():
    """What this believes is on the DHT, for the admin page."""
    from model.SiteSetting import get_setting

    rows = []
    for key, body in _documents():
        recorded = get_setting(_DIGEST_KEY % key, "")
        current = hashlib.sha256(body).hexdigest()
        rows.append({
            "key": key,
            "bytes": len(body),
            "published_sha256": recorded,
            "current_sha256": current,
            "in_sync": bool(recorded) and recorded == current,
        })
    return rows


def publish_everything():
    """One sweep: arcade documents, codeplay collections, and lab contexts.

    Grouped here so the maintenance loop and the admin button do exactly the
    same thing, and so there is one obvious place to add the next collection —
    which is the failure this whole module exists because of. The codeplay
    publisher had been written, wired to a button, and never called.
    """
    result = {"arcade": {}, "codeplay": {}, "lab_contexts": 0}
    try:
        result["arcade"] = publish()
    except Exception:
        app.logger.exception("arcade_publish: arcade documents failed")
    try:
        from services import codeplay_content
        result["codeplay"] = codeplay_content.publish_to_dht()
    except Exception:
        app.logger.exception("arcade_publish: codeplay collections failed")
    try:
        from services import attack_range
        # Sweeps whatever is still unpublished, including anything that failed
        # an earlier pass — 18 challenges were sitting unpublished when this
        # was written, with nothing scheduled to retry them.
        result["lab_contexts"] = attack_range.publish_pending_contexts(limit=1000)
    except Exception:
        app.logger.exception("arcade_publish: lab contexts failed")
    return result
