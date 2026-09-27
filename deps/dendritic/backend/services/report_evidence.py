"""Accepting evidence files without identifying the person who sent them.

A leaked document names its source through METADATA far more often than through
its contents. This module is the pipeline between an upload and storage: check
the type, scan it, strip what identifies the sender, and keep three artefacts
with different purposes.

THE THREE ARTEFACTS, AND WHY NOT ONE
------------------------------------
Stripping everything destroys evidence. A memo whose creation timestamp matches
the events it describes is corroborated *by* the metadata a scrubber removes, so
"scrub it and move on" throws away the thing that proves the document real.

    original    encrypted, hashed on arrival, never opened casually.
                The evidentiary copy; the only thing that can later establish
                authenticity.
    scrubbed    what a reviewer reads day to day, with a manifest of what came
                out of it.
    manifest    the extracted metadata, as DATA. "This PDF was authored by
                J. Smith at 14:02" is often the most important fact in a tip,
                and it belongs somewhere a reviewer can read it rather than
                riding invisibly inside a file that might get republished.

The rule that falls out: **nothing derived from an original is ever published.**
Anything that goes into a story is built from the scrubbed copy.

WHAT THIS CANNOT REMOVE, AND MUST NOT CLAIM TO
-----------------------------------------------
Printer tracking dots -- the Machine Identification Code most colour laser
printers add -- live in the PIXELS of a scan, not in a metadata field. Nothing
here removes them, and removing them would mean degrading the image itself.
A document that was printed and then scanned can identify the printer and the
time of printing after every scrub in this module has run.

That is why the warning belongs BEFORE the file picker rather than in a
post-upload notice: the only effective intervention is a person deciding not to
send that particular file.

WHY SCANNING FAILS CLOSED HERE
------------------------------
`upload_security.scan_bytes_with_clamav` returns silently when no scanner is
configured, and fails open by default when one is configured but unreachable.
That is a defensible default for imageboard attachments and the wrong one for a
file a journalist will open on their own machine, so this module requires a
scanner to have actually run. It does not change the global setting -- flipping
`CLAMAV_FAIL_CLOSED` would also make every board attachment fail closed, which
is a different decision belonging to somebody else.
"""

import hashlib
import io
import json
import os
import zipfile

from shared import app
from services import upload_security


class EvidenceRefused(Exception):
    """The file was not accepted. The message is shown to the submitter."""


# Per-file and per-submission ceilings. Sized to what leaked material actually
# looks like -- a hundred-page colour scan is comfortably over 100 MB -- rather
# than to what is convenient, because a cap that forces a source to split a
# document set produces worse tips and more handling, not more safety.
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_SUBMISSION_BYTES = 2 * 1024 * 1024 * 1024
MAX_FILES = 40


# Declared type -> how it is scrubbed. A type with no scrubber is REFUSED rather
# than stored untouched: accepting a file whose metadata cannot be removed, and
# saying nothing, is the failure this module exists to prevent.
IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif", "image/tiff"}
OFFICE_TYPES = {
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}
PDF_TYPES = {"application/pdf"}
# Formats that carry no embedded metadata to begin with.
PLAIN_TYPES = {"text/plain", "text/csv", "application/json"}

ALLOWED_TYPES = IMAGE_TYPES | OFFICE_TYPES | PDF_TYPES | PLAIN_TYPES


# ---------------------------------------------------------------------------
# Scrubbers. Each returns (clean_bytes, manifest_dict).
# ---------------------------------------------------------------------------

def _scrub_image(payload):
    """Re-encode from pixel data, so nothing but the pixels survives."""
    from PIL import Image

    removed = {}
    try:
        image = Image.open(io.BytesIO(payload))
        image.load()
    except Exception as exc:
        raise EvidenceRefused("That image could not be read (%s)." % exc)

    try:
        exif = image.getexif()
        if exif:
            from PIL.ExifTags import GPSTAGS, TAGS

            for tag_id, value in exif.items():
                name = TAGS.get(tag_id, str(tag_id))
                removed[name] = str(value)[:200]
            # GPS is the one worth naming separately: it is the field most
            # likely to place a source at a scene, and a reviewer should see
            # that it WAS there even though it is now gone.
            gps = exif.get_ifd(0x8825) if hasattr(exif, "get_ifd") else None
            if gps:
                removed["GPS"] = {GPSTAGS.get(k, str(k)): str(v)[:120]
                                  for k, v in gps.items()}
    except Exception:
        # Unreadable EXIF is not a reason to refuse -- the rebuild below drops
        # it either way. It only means the manifest cannot list what was there.
        removed["_note"] = "metadata present but could not be parsed"

    # Rebuilt from raw pixels rather than re-saved. A plain save can carry ICC
    # profiles, XMP packets and format-specific chunks through; constructing a
    # new image from tobytes() cannot, because there is nowhere for them to hide.
    if image.mode in ("P", "PA"):
        image = image.convert("RGBA" if "A" in image.mode else "RGB")
    clean = _new_from_pixels(image)

    out = io.BytesIO()
    fmt = "PNG" if image.mode in ("RGBA", "LA") else "JPEG"
    clean.save(out, format=fmt, quality=95) if fmt == "JPEG" else clean.save(out, format=fmt)
    return out.getvalue(), {"kind": "image", "removed": removed,
                            "reencoded_as": fmt}


def _new_from_pixels(image):
    from PIL import Image
    return Image.frombytes(image.mode, image.size, image.tobytes())


# The metadata parts of an OOXML package. Everything else is document content.
_OFFICE_METADATA = (
    "docProps/core.xml",     # author, last modified by, revision, timestamps
    "docProps/app.xml",      # application, company, template, editing time
    "docProps/custom.xml",   # whatever the organisation added
)


def _scrub_office(payload):
    """Copy the package without its metadata parts.

    An OOXML file is a zip. Rewriting it entry by entry means the document
    content is passed through untouched while the parts that name the author,
    the company and the editing history are simply not carried over.
    """
    removed = {}
    try:
        source = zipfile.ZipFile(io.BytesIO(payload))
    except Exception as exc:
        raise EvidenceRefused("That file could not be read as a document (%s)." % exc)

    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for entry in source.infolist():
            if entry.filename in _OFFICE_METADATA:
                try:
                    removed[entry.filename] = source.read(entry).decode(
                        "utf-8", "replace")[:2000]
                except Exception:
                    removed[entry.filename] = "(unreadable)"
                continue
            target.writestr(entry, source.read(entry))

    return out.getvalue(), {
        "kind": "office",
        "removed": removed,
        # Said out loud because it is a real residual risk and a reviewer
        # should not assume otherwise.
        "note": "Tracked changes and comments live in the document body and "
                "are NOT removed; open the scrubbed copy and check.",
    }


def _scrub_pdf(payload):
    """Drop the document information dictionary and any XMP packet.

    Needs `pypdf`. If it is absent the file is REFUSED rather than stored
    unscrubbed -- a PDF carries the author, the producing application and often
    the full local path of the machine it was made on.
    """
    try:
        from pypdf import PdfReader, PdfWriter
    except ImportError:
        raise EvidenceRefused(
            "PDF uploads are not available on this server right now. You can "
            "send the same material as images, or as a plain-text description.")

    try:
        reader = PdfReader(io.BytesIO(payload))
        removed = {k.lstrip("/"): str(v)[:200]
                   for k, v in (reader.metadata or {}).items()}
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        # Written explicitly rather than left alone: an absent /Info is not the
        # same as one the writer copied forward.
        writer.add_metadata({})
        out = io.BytesIO()
        writer.write(out)
    except EvidenceRefused:
        raise
    except Exception as exc:
        raise EvidenceRefused("That PDF could not be processed (%s)." % exc)

    return out.getvalue(), {
        "kind": "pdf",
        "removed": removed,
        "note": "If this PDF is a scan of something printed, printer "
                "identification dots may remain in the page images.",
    }


def _scrub_plain(payload):
    return payload, {"kind": "plain", "removed": {}}


_SCRUBBERS = [
    (IMAGE_TYPES, _scrub_image),
    (OFFICE_TYPES, _scrub_office),
    (PDF_TYPES, _scrub_pdf),
    (PLAIN_TYPES, _scrub_plain),
]


def scrubber_for(mimetype):
    for types, scrubber in _SCRUBBERS:
        if mimetype in types:
            return scrubber
    return None


# ---------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------

def scanning_available():
    """Whether a virus scanner is actually reachable-configured.

    `upload_security.scan_bytes_with_clamav` returns silently with no scanner
    configured. For evidence that silence is indistinguishable from "clean",
    which is the wrong default for a file a journalist will open.
    """
    return bool(upload_security._clamav_scan_url())


def _scan_or_refuse(payload, filename):
    if not scanning_available():
        raise EvidenceRefused(
            "Attachments cannot be accepted right now because files cannot be "
            "virus-checked. Your written report can still be submitted.")
    # A LONGER TIMEOUT THAN THE SITE DEFAULT, for the duration of this scan.
    #
    # upload_security uses CLAMAV_TIMEOUT, default 8 seconds, chosen for board
    # attachments where a slow scanner should fail open fast rather than stall a
    # post. Evidence is the opposite case on both counts: a file may be 512 MB,
    # which cannot be streamed and scanned in eight seconds, and it fails CLOSED
    # -- so a timeout is a refusal, and an eight-second one would refuse every
    # large document while reporting only "could not be virus-checked".
    previous = os.environ.get("CLAMAV_TIMEOUT")
    os.environ["CLAMAV_TIMEOUT"] = os.environ.get("EVIDENCE_CLAMAV_TIMEOUT", "300")
    try:
        upload_security.scan_bytes_with_clamav(payload, filename=filename)
    except upload_security.UnsafeUploadError as unsafe:
        raise EvidenceRefused(str(unsafe))
    except Exception as exc:
        # Fail CLOSED here regardless of the global policy: an unscanned
        # attachment from an anonymous stranger is exactly the file that should
        # not reach a reviewer's machine.
        app.logger.warning("evidence: scan failed for %s (%s); refusing",
                           filename, exc)
        raise EvidenceRefused(
            "That file could not be virus-checked, so it was not accepted. "
            "Please try again shortly.")
    finally:
        # Restored so one evidence scan does not quietly raise the timeout for
        # every board attachment that follows in this worker.
        if previous is None:
            os.environ.pop("CLAMAV_TIMEOUT", None)
        else:
            os.environ["CLAMAV_TIMEOUT"] = previous


def prepare(payload, filename, declared_type):
    """Validate, scan and scrub one file.

    Returns a dict describing the artefacts. Storage is the caller's job -- this
    module does no I/O beyond the scanner, so it can be tested without one.
    """
    if not payload:
        raise EvidenceRefused("That file was empty.")
    if len(payload) > MAX_FILE_BYTES:
        raise EvidenceRefused(
            "That file is larger than the %d MB limit for a single file."
            % (MAX_FILE_BYTES // (1024 * 1024)))

    mimetype = upload_security._normalize_mime(declared_type or "")
    if mimetype not in ALLOWED_TYPES:
        raise EvidenceRefused(
            "We cannot accept that kind of file. Documents, images, PDFs and "
            "plain text are accepted.")

    # The declared type must match the bytes. Without this, a file simply
    # claims to be an allowed type and reaches whatever handles that type.
    if not upload_security.content_signature_matches(mimetype, payload):
        raise EvidenceRefused(
            "That file does not look like the kind of file it says it is, so "
            "it was not accepted.")

    _scan_or_refuse(payload, filename)

    scrubber = scrubber_for(mimetype)
    if scrubber is None:
        # Unreachable while ALLOWED_TYPES and _SCRUBBERS agree; kept because
        # the failure if they ever diverge must be a refusal, not a passthrough.
        raise EvidenceRefused("That file type cannot be processed safely.")

    clean, manifest = scrubber(payload)

    return {
        "filename": _safe_name(filename),
        "mimetype": mimetype,
        "original_sha256": hashlib.sha256(payload).hexdigest(),
        "original_bytes": len(payload),
        "scrubbed_sha256": hashlib.sha256(clean).hexdigest(),
        "scrubbed_bytes": len(clean),
        "manifest": manifest,
        # Not part of the returned reference; handed to the caller to store.
        "_original": payload,
        "_scrubbed": clean,
    }


def _safe_name(filename):
    """A display name with no path and no surprises.

    The name is chosen by the submitter and shown to a reviewer, so it is
    treated as hostile input: no directory separators, no control characters,
    bounded length.
    """
    name = (filename or "attachment").replace("\\", "/").split("/")[-1]
    name = "".join(c for c in name if c.isprintable() and c not in '<>:"|?*')
    return (name or "attachment")[:120]


def reference(prepared):
    """The part of `prepare()` that belongs in the sealed payload.

    Deliberately excludes the bytes. The payload records what was attached and
    what was taken out of it; the files themselves are separate objects.
    """
    return {key: value for key, value in prepared.items()
            if not key.startswith("_")}


def manifest_json(prepared):
    return json.dumps(prepared["manifest"], sort_keys=True, default=str)
