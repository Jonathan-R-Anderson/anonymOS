"""The evidence upload path: storage, sealing, and who gets the original.

The scrubbing itself is tested in test_report_evidence.py. This is about what
happens to the three artefacts afterwards -- whether they are all encrypted,
whether one can be served in place of another, and whether a reviewer can reach
untouched bytes from an anonymous stranger by accident.
"""

import hashlib
import os
import sys
import types
import unittest
from unittest import mock
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
BACKEND = os.path.dirname(HERE)
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)


def _install_stubs():
    if "shared" not in sys.modules:
        shared = types.ModuleType("shared")
        db = MagicMock()
        db.Model = object
        shared.db = db
        shared.app = MagicMock()
        shared.app.config = {}
        sys.modules["shared"] = shared


_install_stubs()

REPORT_MASTER = "33" * 32
os.environ.setdefault("REPORT_CONTENT_MASTER_SECRET", REPORT_MASTER)

from services import report_crypto  # noqa: E402
from services import report_dht  # noqa: E402


class _FakeApp(object):
    def __init__(self):
        self.config = {}
        self.logger = MagicMock()


class _Body(object):
    def __init__(self, data):
        self._data = data

    def read(self):
        return self._data


class FakeGateway(object):
    def __init__(self):
        self.objects = {}
        self.buckets = set()
        self.swallow_writes = False

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise RuntimeError("no such bucket")

    def create_bucket(self, Bucket):
        self.buckets.add(Bucket)

    def put_object(self, Bucket, Key, Body, Metadata=None):
        if not self.swallow_writes:
            self.objects[(Bucket, Key)] = (Body, Metadata or {})

    def get_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise RuntimeError("no such key")
        return {"Body": _Body(self.objects[(Bucket, Key)][0])}

    def head_object(self, Bucket, Key):
        if (Bucket, Key) not in self.objects:
            raise RuntimeError("no such key")

    def delete_object(self, Bucket, Key):
        self.objects.pop((Bucket, Key), None)


# The civil-rights reporting feature was removed with the rest of the stripped
# blueprints, and four classes below read its files directly:
# blueprints/civil_rights.py, blueprints/report_review.py,
# templates/civil_rights/form.html and clamav/Dockerfile.
#
# SKIPPED CONDITIONALLY RATHER THAN DELETED. The assertions are still correct
# and still worth having -- that the original download is CSRF-protected and
# POST-only, that neither route may be cached by an intermediary, that the
# preview serves the scrubbed copy -- and deleting them would mean rewriting all
# of it from scratch if the feature returns. A skipUnless brings them back the
# moment the files exist again, which a deletion cannot do and an unconditional
# skip would not either.
_CIVIL_RIGHTS_PRESENT = all(
    os.path.exists(os.path.join(BACKEND, part)) for part in (
        "blueprints/civil_rights.py",
        "blueprints/report_review.py",
        "templates/civil_rights/form.html",
    )
)
_FEATURE_GONE = "the civil-rights reporting feature was removed; these read its files"

class EvidenceKeyTest(unittest.TestCase):

    def test_the_key_describes_nothing(self):
        """A DHT key is visible to every node that routes for it. An attachment
        called bodycam-2026-03-04.mp4 in a key describes the contents of an
        encrypted object to strangers."""
        key = report_dht.evidence_key_for("SR-AAAAAAAAAAAA", 0, "original")
        self.assertEqual(key, "civil-rights-reports/SR-AAAAAAAAAAAA/e0/original")
        for leak in (".pdf", ".mp4", "bodycam", "image/jpeg", "1048576"):
            self.assertNotIn(leak, key)

    def test_an_unknown_variant_is_refused(self):
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.evidence_key_for("SR-A", 0, "raw")

    def test_the_three_variants_have_distinct_keys(self):
        keys = {report_dht.evidence_key_for("SR-A", 0, v)
                for v in report_dht.VARIANTS}
        self.assertEqual(len(keys), 3)


class EvidenceStorageTest(unittest.TestCase):

    def setUp(self):
        self.gateway = FakeGateway()
        self._patch = mock.patch.object(report_dht, "app", _FakeApp())
        self._patch.start()
        report_dht.app.config["S3_ENDPOINT"] = "https://storage.invalid:9000"

    def tearDown(self):
        self._patch.stop()

    def test_a_stored_artefact_reads_back(self):
        blob = b"SCE1-pretend"
        digest = hashlib.sha256(blob).hexdigest()
        key = report_dht.store_evidence("SR-A", 0, "original", blob, digest,
                                        client=self.gateway)
        self.assertIn("e0/original", key)

    def test_a_write_that_cannot_be_read_back_raises(self):
        """The same gate as the payload. A source who believes a document was
        delivered will not send it again."""
        self.gateway.swallow_writes = True
        blob = b"SCE1-pretend"
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store_evidence("SR-A", 0, "original", blob,
                                      hashlib.sha256(blob).hexdigest(),
                                      client=self.gateway)

    def test_a_hash_mismatch_raises(self):
        with self.assertRaises(report_dht.ReportStorageError):
            report_dht.store_evidence("SR-A", 0, "original", b"one", "0" * 64,
                                      client=self.gateway)

    def test_delete_removes_every_variant_of_every_attachment(self):
        """Retention must not leave the most sensitive part of a submission on
        volunteer disks with nothing pointing at it."""
        for index in (0, 1):
            for variant in report_dht.VARIANTS:
                blob = ("v%d%s" % (index, variant)).encode()
                report_dht.store_evidence("SR-A", index, variant, blob,
                                          hashlib.sha256(blob).hexdigest(),
                                          client=self.gateway)
        removed = report_dht.delete_evidence("SR-A", client=self.gateway)
        self.assertEqual(len(removed), 6)
        self.assertIsNone(report_dht.fetch_evidence("SR-A", 0, "original",
                                                    client=self.gateway))


class EverythingIsEncryptedTest(unittest.TestCase):
    """Including the manifest, which is the most concentrated identifying
    material in a submission."""

    def test_the_manifest_is_sealed_not_stored_in_the_clear(self):
        manifest = b'{"removed": {"GPS": "34.53N 117.01W", "Make": "ACME"}}'
        blob, digest = report_crypto.seal_bytes("SR-A/e0/manifest", manifest)
        self.assertNotIn(b"34.53N", blob)
        self.assertNotIn(b"ACME", blob)
        self.assertEqual(
            report_crypto.unseal_bytes("SR-A/e0/manifest", blob,
                                       expected_hash=digest),
            manifest)

    def test_an_original_cannot_be_served_as_a_scrubbed_copy(self):
        """The AEAD binds the ciphertext to its object id, and the ids differ by
        variant -- so a node that swapped them is detected."""
        blob, _ = report_crypto.seal_bytes("SR-A/e0/original", b"untouched")
        with self.assertRaises(report_crypto.ReportCryptoError):
            report_crypto.unseal_bytes("SR-A/e0/scrubbed", blob)

    def test_one_attachment_cannot_be_served_as_another(self):
        blob, _ = report_crypto.seal_bytes("SR-A/e0/original", b"first")
        with self.assertRaises(report_crypto.ReportCryptoError):
            report_crypto.unseal_bytes("SR-A/e1/original", blob)

    def test_a_flipped_byte_fails_to_decrypt(self):
        blob, _ = report_crypto.seal_bytes("SR-A/e0/original", b"payload")
        tampered = bytearray(blob)
        tampered[-1] ^= 0x01
        with self.assertRaises(Exception):
            report_crypto.unseal_bytes("SR-A/e0/original", bytes(tampered))


@unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _FEATURE_GONE)
class WhoGetsTheOriginalTest(unittest.TestCase):
    """Reading a tip must not mean opening an untrusted file."""

    def _source(self):
        return open(os.path.join(BACKEND, "blueprints", "report_review.py"),
                    encoding="utf-8").read()

    def test_the_preview_serves_the_scrubbed_copy(self):
        body = self._source()
        preview = body[body.index("def evidence_preview"):
                       body.index("def evidence_original")]
        self.assertIn('"scrubbed"', preview)
        self.assertNotIn('"original"', preview)

    def test_the_original_needs_a_post_not_a_get(self):
        """A GET is something a browser can be made to do by a link, a preload
        or a crawler. Taking the raw bytes should be a decision."""
        body = self._source()
        route = body[body.index('/evidence/<int:index>/original'):]
        route = route[:route.index("def evidence_original")]
        self.assertIn('methods=["POST"]', route)

    def test_the_original_download_is_csrf_protected(self):
        body = self._source()
        route = body[body.index('/evidence/<int:index>/original'):]
        route = route[:route.index("def evidence_original")]
        self.assertIn("csrf_protect", route)

    def test_the_original_is_never_rendered_inline(self):
        body = self._source()
        original = body[body.index("def evidence_original"):
                        body.index("def _evidence_mimetype")]
        self.assertIn("attachment;", original)
        self.assertIn("octet-stream", original)

    def _route_bodies(self):
        """Each evidence route's own source, so a header mentioned in a comment
        elsewhere cannot satisfy an assertion about the route."""
        body = self._source()
        preview = body[body.index("def evidence_preview"):
                       body.index("def evidence_original")]
        original = body[body.index("def evidence_original"):
                        body.index("def _evidence_mimetype")]
        return {"preview": preview, "original": original}

    def test_both_routes_forbid_content_sniffing(self):
        """A scrubbed image a browser decided to read as HTML would be a stored
        cross-site script in the admin panel."""
        for name, route in self._route_bodies().items():
            self.assertIn("X-Content-Type-Options", route,
                          "%s route allows sniffing" % name)

    def test_neither_route_may_be_cached_by_an_intermediary(self):
        for name, route in self._route_bodies().items():
            self.assertIn("no-store", route, "%s route is cacheable" % name)

    def test_taking_the_original_is_audited_separately_from_reading(self):
        """'Read the safe copy' and 'took the raw file' must be separable."""
        body = self._source()
        self.assertIn("evidence_original_downloaded", body)


@unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _FEATURE_GONE)
class TheWrittenReportSurvivesTest(unittest.TestCase):
    """A refused attachment must never cost somebody their account of what
    happened."""

    def _source(self):
        return open(os.path.join(BACKEND, "blueprints", "civil_rights.py"),
                    encoding="utf-8").read()

    def test_attachments_are_prepared_before_the_report_is_created(self):
        body = self._source()
        self.assertLess(body.index("report_evidence.prepare("),
                        body.index("report = reports.submit("))

    def test_a_refused_file_re_renders_the_form_with_the_values(self):
        body = self._source()
        refused = body[body.index("except report_evidence.EvidenceRefused"):]
        refused = refused[:400]
        self.assertIn("values=request.form.to_dict()", refused)

    def test_a_storage_failure_still_confirms_the_report(self):
        """The report IS stored; only the file is not. Telling them the whole
        submission failed would make them retype it."""
        body = self._source()
        self.assertIn("_CONFIRM_FAILED_FILES_KEY", body)

    def test_the_picker_is_hidden_when_files_cannot_be_scanned(self):
        """A file picker that always refuses reads as the site being broken."""
        body = self._source()
        self.assertIn("report_evidence.scanning_available()", body)


@unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _FEATURE_GONE)
class WarnBeforeTheFilePickerTest(unittest.TestCase):

    def test_the_warning_appears_above_the_input(self):
        """Below it, it is a disclaimer. Above it, it is advice -- and the only
        intervention early enough to help somebody who should not send a file."""
        body = open(os.path.join(BACKEND, "templates", "civil_rights",
                                 "form.html"), encoding="utf-8").read()
        self.assertLess(body.index("Before you attach anything"),
                        body.index('type="file"'))

    def test_the_printer_dot_limitation_is_stated(self):
        """It lives in the pixels of a scan and nothing removes it."""
        body = open(os.path.join(BACKEND, "templates", "civil_rights",
                                 "form.html"), encoding="utf-8").read()
        self.assertIn("cannot remove", body)
        self.assertIn("printers add", body)

    def test_the_form_can_carry_files_at_all(self):
        body = open(os.path.join(BACKEND, "templates", "civil_rights",
                                 "form.html"), encoding="utf-8").read()
        self.assertIn('enctype="multipart/form-data"', body)


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(_CIVIL_RIGHTS_PRESENT, _FEATURE_GONE)
class ScannerLimitsAgreeTest(unittest.TestCase):
    """Four independent limits govern a scan. They have to agree.

    Civil-rights evidence fails CLOSED, so a file the scanner declines to
    examine is a file the site refuses. Three of the four used to sit below the
    512 MB file cap -- and the binding one, clamd's StreamMaxLength, was never
    set at all, leaving the default of 25 MB. A hundred-page colour scan is well
    over that, so the attachment path would have rejected exactly the documents
    it exists to carry.
    """

    ROOT = os.path.dirname(BACKEND)

    def _clamav_dockerfile(self):
        return open(os.path.join(self.ROOT, "clamav", "Dockerfile"),
                    encoding="utf-8").read()

    def _effective_config_block(self):
        """The directives APPENDED after the packaged config is copied.

        Asserting on the whole file would pass on the fallback block, which only
        runs when no packaged clamd.conf exists -- and on this base image one
        always does, so those lines are dead code. That is exactly how the
        running daemon ended up with StreamMaxLength 25M while the Dockerfile
        appeared to say 100M.
        """
        body = self._clamav_dockerfile()
        return body[body.index('echo "TCPAddr 0.0.0.0"'):]

    def test_clamd_streams_at_least_the_file_cap(self):
        """app.py scans with INSTREAM, so StreamMaxLength is the real ceiling."""
        self.assertIn('"StreamMaxLength 512M"', self._effective_config_block())

    def test_clamd_will_examine_a_file_that_large(self):
        block = self._effective_config_block()
        self.assertIn('"MaxFileSize 512M"', block)
        self.assertIn('"MaxScanSize 512M"', block)

    def test_the_limits_replace_rather_than_append(self):
        """clamd takes the FIRST occurrence of a directive and ignores later
        duplicates, so appending left the packaged 25M in force -- and the
        daemon closed the connection mid-stream, which reads to the caller as
        "clamd unavailable: Broken pipe" rather than as a size refusal."""
        block = self._effective_config_block()
        self.assertIn("sed -i", block)
        self.assertIn("grep -qE", block)

    def test_the_wrapper_cap_matches_the_file_cap(self):
        from services import report_evidence

        media = open(os.path.join(self.ROOT, "k8s", "media",
                                  "00-media-common.yaml"), encoding="utf-8").read()
        line = [l for l in media.splitlines()
                if l.strip().startswith("CLAMAV_SCAN_MAX_SIZE:")][0]
        configured = int(line.split(":", 1)[1].strip().strip('"'))
        self.assertGreaterEqual(configured, report_evidence.MAX_FILE_BYTES)

    def test_the_scan_timeout_is_raised_for_evidence(self):
        """8 seconds is the site default and cannot stream 512 MB. Failing
        closed, a timeout is a refusal."""
        body = open(os.path.join(BACKEND, "services", "report_evidence.py"),
                    encoding="utf-8").read()
        self.assertIn("EVIDENCE_CLAMAV_TIMEOUT", body)
        self.assertIn("CLAMAV_TIMEOUT", body)

    def test_the_raised_timeout_is_restored_afterwards(self):
        """One evidence scan must not raise the timeout for every board
        attachment that follows in the same worker."""
        body = open(os.path.join(BACKEND, "services", "report_evidence.py"),
                    encoding="utf-8").read()
        scan = body[body.index("def _scan_or_refuse"):body.index("def prepare")]
        self.assertIn("finally:", scan)
        self.assertIn("previous", scan)
