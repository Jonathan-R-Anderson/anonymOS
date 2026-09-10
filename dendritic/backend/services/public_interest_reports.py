"""Accepting a submission: validate, seal, store, verify, index.

This module owns the one question the whole feature turns on -- **was this
actually submitted?** -- and it answers it from `stored_at`, which is set only
after the sealed payload has been written to the DHT and read back.

THE ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE
-----------------------------------------------
The row is created BEFORE the write, with `stored_at` NULL, and is kept even when
the write fails. Three reasons:

1. It reserves the reference code, so a code can never be handed out twice.
2. A failed submission leaves a record. "Storage was down between 14:00 and
   14:40 and eleven people lost what they had written" is a fact worth being
   able to establish, and it is unrecoverable if failures leave nothing behind.
3. `stored_at` NULL is then a structural definition of failure rather than a
   convention. Every surface that tells a human "we have your report" reads that
   column; there is no path where a caller forgetting to check a return value
   produces a false confirmation.

WHAT IS NEVER DONE HERE
-----------------------
No plaintext is logged, ever -- not on the error path, not truncated, not
"just the first line for debugging". Logs are the one place this data reliably
escapes the encryption, and an exception handler written in a hurry is how it
gets there.
"""

import datetime

from shared import app, db

from model.PublicInterestReport import (
    PublicInterestReport,
    KIND_CIVIL_RIGHTS,
    STATUS_NEW,
    generate_report_id,
)
from model import PublicInterestReportAudit as audit
from services import report_crypto, report_dht, report_evidence, report_schema


class SubmissionRefused(Exception):
    """Intake is not available. The submitter is told, and told why."""


class SubmissionFailed(Exception):
    """We accepted it and could not store it. NEVER report this as success."""


def intake_available():
    """Whether a submission can be accepted at all, checked BEFORE the form.

    Both halves are required and neither has a safe fallback: without the report
    key a submission could only be stored unencrypted, and without an object
    store it could only be stored in the database this design exists to keep it
    out of. Discovering either after someone has typed out an account of being
    assaulted leaves no good option, so the form is closed up front instead.
    """
    return report_crypto.enabled() and report_dht.enabled()


def unavailable_reason():
    """A short operator-facing reason, for logs and the admin panel.

    Deliberately not shown to the submitter: which of two secrets is missing is
    information about the deployment, and the person filing a report can do
    nothing with it.
    """
    if not report_crypto.enabled():
        return "REPORT_CONTENT_MASTER_SECRET is not configured"
    if not report_dht.enabled():
        return "no object store is configured (S3_ENDPOINT unset)"
    return None


def _unique_report_id(attempts=8):
    for _ in range(attempts):
        candidate = generate_report_id()
        exists = (db.session.query(PublicInterestReport.id)
                  .filter(PublicInterestReport.report_id == candidate)
                  .first())
        if not exists:
            return candidate
    # 60 bits of entropy makes this essentially impossible; if it happens,
    # something is wrong with the random source and inventing a code anyway
    # would be worse than refusing.
    raise SubmissionFailed("could not allocate a unique reference code")


def submit(kind, values, categories=(), acknowledgements=(), evidence=None,
           actor="public"):
    """Validate and store one submission. Returns the persisted report row.

    Raises `report_schema.ValidationError` for a bad form, `SubmissionRefused`
    when intake is closed, and `SubmissionFailed` when storage did not complete.
    A caller that does not catch the last one shows an error page, which is the
    correct outcome -- the dangerous bug is a caller that carries on.
    """
    if not intake_available():
        app.logger.error("reports: intake unavailable -- %s", unavailable_reason())
        raise SubmissionRefused(
            "Submissions are temporarily closed. Please try again later.")

    payload = report_schema.validate(kind, values, categories=categories,
                                     acknowledgements=acknowledgements)

    if evidence:
        # References only -- digests and scrub manifests, never file bytes. The
        # files themselves are stored separately (phase 19) and the payload
        # points at them.
        payload["evidence"] = evidence

    report_id = _unique_report_id()
    now = datetime.datetime.utcnow()

    # Built by assignment rather than through the constructor. Every column set
    # here is one somebody had to write down deliberately, which is the property
    # worth having on the row that must not accumulate personal data: a
    # kwargs splat would let a field arrive in the index because it happened to
    # share a name with a form value.
    #
    # Note what is NOT copied across from `payload["fields"]`: the name, the
    # email, the phone, the description and the city. They exist only in the
    # sealed payload. `country` and `state` are the coarse jurisdiction a
    # reviewer filters by; see model.PublicInterestReport for why the city is
    # not among them.
    report = PublicInterestReport()
    report.report_id = report_id
    report.kind = kind
    report.schema_version = payload["schema_version"]
    report.status = STATUS_NEW
    report.categories = ",".join(payload["categories"])
    report.country = payload["fields"].get("country")
    report.state = payload["fields"].get("state")
    report.created_at = now
    report.updated_at = now
    report.status_changed_at = now
    report.dht_version = 1
    report.stored_at = None
    report.pinned = False
    report.story_source = False
    report.recompute_expiry(now=now)
    db.session.add(report)
    # Flush rather than commit: the code is reserved against a concurrent
    # submission, but nothing is durable yet and the transaction still rolls
    # forward into either the success or the failure path below.
    db.session.flush()

    try:
        blob, content_hash = report_crypto.seal(report_id, payload, version=1)
        expires = int(report.expires_at.timestamp()) if report.expires_at else None
        key = report_dht.store(report_id, blob, content_hash, version=1,
                               expires_at=expires)
    except Exception as exc:
        # Record the attempt, then re-raise. The row stays with stored_at NULL,
        # which is what makes it a failed submission rather than a pending one.
        #
        # str(exc) is safe here and is checked: report_crypto and report_dht
        # raise messages built from ids and hashes, never from payload content.
        audit.record(report_id, audit.ACTION_STORE_FAILED, actor,
                     new_status=STATUS_NEW,
                     detail={"error": str(exc)[:500]})
        db.session.commit()
        app.logger.exception("reports: storing %s failed", report_id)
        raise SubmissionFailed(
            "We could not store your report. Nothing was saved. Please try "
            "again shortly.")

    report.content_hash = content_hash
    report.dht_key = key
    report.stored_at = datetime.datetime.utcnow()

    audit.record(report_id, audit.ACTION_SUBMITTED, actor,
                 new_status=STATUS_NEW,
                 detail={"kind": kind, "dht_key": key,
                         "categories": payload["categories"],
                         "schema_version": payload["schema_version"]})
    db.session.commit()
    return report


def by_reference(report_id):
    """One report by its public code, or None.

    Returns rows whose storage failed too. A submitter quoting a code from a
    failed attempt should be told it did not go through, not that it does not
    exist -- those are different facts and only one of them is their fault.
    """
    if not report_id:
        return None
    return (db.session.query(PublicInterestReport)
            .filter(PublicInterestReport.report_id == report_id.strip().upper())
            .first())


def read_payload(report, actor, version=None, purpose=None):
    """Decrypt a stored submission. Every call writes an audit row.

    Reading IS the sensitive action here -- the payload holds a complainant's
    name, address and account of being harmed -- so "who read this" is recorded
    with the same weight other systems reserve for writes. The audit row is
    written BEFORE the decryption is returned, so an exception later cannot
    leave a read unrecorded.
    """
    if report is None or not report.is_stored:
        raise SubmissionFailed("this report was never stored")

    version = version or report.dht_version or 1

    audit.record(report.report_id, audit.ACTION_VIEWED, actor,
                 new_status=report.status,
                 detail={"version": version, "purpose": purpose or "review"})
    db.session.commit()

    blob = report_dht.fetch(report.report_id, version=version)
    if blob is None:
        raise SubmissionFailed(
            "the stored object for %s could not be fetched" % report.report_id)

    return report_crypto.unseal(report.report_id, blob, version=version,
                                expected_hash=report.content_hash)


def set_status(report, new_status, actor, detail=None):
    """Move a report and reset its retention clock. Audited either way.

    The audit row is written even when the status is unchanged -- a reviewer
    setting a report to what it already was is still a reviewer acting on it,
    and a trail that records only real transitions cannot show that somebody
    looked at a case and decided to leave it alone.
    """
    previous = report.status
    now = datetime.datetime.utcnow()

    if new_status != previous:
        report.status = new_status
        report.status_changed_at = now
        report.recompute_expiry(now=now)
    report.updated_at = now

    audit.record(report.report_id, audit.ACTION_STATUS_CHANGED, actor,
                 previous_status=previous, new_status=new_status,
                 detail=dict(detail or {},
                             changed=bool(new_status != previous),
                             expires_at=(report.expires_at.isoformat()
                                         if report.expires_at else None)))
    db.session.commit()
    return report


# --- evidence --------------------------------------------------------------

MAX_EVIDENCE_FILES = 40


def store_evidence(report_id, prepared, index, expires_at=None):
    """Seal and store one prepared attachment's three artefacts.

    `prepared` is what `report_evidence.prepare()` returned: the untouched
    original, the scrubbed copy, and a manifest of what was stripped out.

    ALL THREE ARE ENCRYPTED, including the manifest. The manifest is the most
    concentrated identifying material in a submission -- "authored by J. Smith
    at 14:02, GPS 34.53N 117.01W" is the metadata a scrubber removed precisely
    because it names people and places, and storing that in the clear because it
    is "only metadata" would hand a storage node the thing the scrubbing was
    for.

    Each artefact is sealed under its own object id, so one cannot be served in
    place of another: `report_crypto` binds the ciphertext to the id through the
    AEAD's additional data, and the ids differ by variant.

    Returns the reference to put in the payload. Raises on any failure -- an
    attachment the submitter was told arrived and which is not retrievable is
    worse than a refusal, because a source who believes a document was delivered
    will not send it again.
    """
    from services import report_dht

    reference = report_evidence.reference(prepared)
    stored = {}

    artefacts = (
        (report_dht.VARIANT_ORIGINAL, prepared["_original"]),
        (report_dht.VARIANT_SCRUBBED, prepared["_scrubbed"]),
        (report_dht.VARIANT_MANIFEST,
         report_evidence.manifest_json(prepared).encode("utf-8")),
    )

    for variant, raw in artefacts:
        object_id = "%s/e%d/%s" % (report_id, index, variant)
        blob, content_hash = report_crypto.seal_bytes(object_id, raw)
        stored[variant] = {
            "key": report_dht.store_evidence(report_id, index, variant, blob,
                                             content_hash,
                                             expires_at=expires_at),
            "content_hash": content_hash,
        }

    reference["index"] = index
    reference["stored"] = stored
    return reference


def read_evidence(report, index, variant, actor):
    """Fetch and decrypt one artefact. Audited, like every other read.

    `variant` decides what a reviewer gets, and the default everywhere in the UI
    is the SCRUBBED copy. Reaching for the original is a deliberate act: it is
    the untouched bytes from an anonymous stranger, and opening one on a
    newsroom machine is how a newsroom gets compromised.
    """
    from services import report_dht

    if report is None or not report.is_stored:
        raise SubmissionFailed("this report was never stored")

    audit.record(report.report_id, audit.ACTION_VIEWED, actor,
                 new_status=report.status,
                 detail={"evidence_index": index, "variant": variant,
                         "purpose": "evidence"})
    db.session.commit()

    blob = report_dht.fetch_evidence(report.report_id, index, variant)
    if blob is None:
        raise SubmissionFailed(
            "the stored attachment for %s could not be fetched" % report.report_id)

    object_id = "%s/e%d/%s" % (report.report_id, index, variant)
    return report_crypto.unseal_bytes(object_id, blob)


def attach_evidence(report, references, failed=None, actor="public"):
    """Record which attachments a stored submission has, as a NEW version.

    WHY A VERSION AND NOT A COLUMN. The references carry the filename the sender
    chose, and a filename is content: `my-arrest-record.pdf` describes a
    submission as surely as its description does. So they belong in the encrypted
    payload, and the payload is already sealed by the time the attachments have
    been stored -- their keys are derived from the reference code, which does not
    exist until the report does.

    Versions exist for exactly this. v1 is what the person wrote; v2 is that plus
    what they attached. v1 is left in place, because append-only is what makes an
    earlier version evidence of anything.

    A failure here leaves the report at v1 with its attachments in storage and
    nothing pointing at them. That is recorded rather than raised: the report
    itself is stored and the sender has been told so, and the recoverable state
    is a reviewer seeing "attachments were stored but not linked" rather than a
    submission that appears to have failed.
    """
    if report is None or not references:
        return report

    try:
        blob = report_dht.fetch(report.report_id, version=report.dht_version or 1)
        payload = report_crypto.unseal(report.report_id, blob,
                                       version=report.dht_version or 1,
                                       expected_hash=report.content_hash)
        payload["evidence"] = references
        if failed:
            # Kept in the payload rather than only in a flash message: a
            # reviewer reading this months later should be able to see that the
            # sender tried to attach something that did not arrive, or they will
            # read a gap as a sender who chose not to.
            payload["evidence_failed"] = list(failed)

        version = (report.dht_version or 1) + 1
        sealed, content_hash = report_crypto.seal(report.report_id, payload,
                                                 version=version)
        expires = int(report.expires_at.timestamp()) if report.expires_at else None
        key = report_dht.store(report.report_id, sealed, content_hash,
                               version=version, expires_at=expires)
    except Exception as exc:
        audit.record(report.report_id, "evidence_link_failed", actor,
                     new_status=report.status,
                     detail={"error": str(exc)[:500],
                             "attachments": len(references)})
        db.session.commit()
        app.logger.exception("reports: could not link evidence for %s",
                             report.report_id)
        return report

    report.dht_version = version
    report.dht_key = key
    report.content_hash = content_hash
    report.updated_at = datetime.datetime.utcnow()

    audit.record(report.report_id, "evidence_attached", actor,
                 new_status=report.status,
                 detail={"attachments": len(references),
                         "failed": list(failed or []),
                         "version": version})
    db.session.commit()
    return report
