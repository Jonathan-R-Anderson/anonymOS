"""Evidence handling: does the metadata actually come out?

Built on real fixtures with real metadata rather than on mocks, because the
question these tests answer is not "was the scrubber called" but "is the GPS
tag gone" -- and only the file can answer that.
"""

import io
import os
import sys
import types
import unittest
import zipfile
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

from services import report_evidence as ev  # noqa: E402


def _jpeg_with_gps():
    """A real JPEG carrying GPS coordinates and a camera serial number."""
    from PIL import Image
    from PIL.TiffImagePlugin import IFDRational

    image = Image.new("RGB", (32, 32), (120, 30, 30))
    exif = image.getexif()
    exif[0x010F] = "ACME Camera Co"          # Make
    exif[0x0110] = "Model X"                 # Model
    exif[0x0132] = "2026:03:04 14:02:00"     # DateTime
    exif[0xA431] = "SERIAL-12345"            # BodySerialNumber
    gps = exif.get_ifd(0x8825)
    gps[1] = "N"
    gps[2] = (IFDRational(34, 1), IFDRational(53, 1), IFDRational(0, 1))
    gps[3] = "W"
    gps[4] = (IFDRational(117, 1), IFDRational(1, 1), IFDRational(0, 1))
    out = io.BytesIO()
    image.save(out, format="JPEG", exif=exif)
    return out.getvalue()


def _docx_with_author():
    """A minimal OOXML package with the metadata parts a real one carries."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml",
                   "<document>the actual text of the document</document>")
        z.writestr("docProps/core.xml",
                   '<coreProperties><dc:creator>J. Smith</dc:creator>'
                   '<cp:lastModifiedBy>J. Smith</cp:lastModifiedBy>'
                   '</coreProperties>')
        z.writestr("docProps/app.xml",
                   "<Properties><Company>Acme Holdings</Company></Properties>")
    return out.getvalue()


class ImageScrubbingTest(unittest.TestCase):

    def test_gps_is_gone_from_the_scrubbed_copy(self):
        """The tag most likely to place a source at a scene."""
        from PIL import Image

        original = _jpeg_with_gps()
        # Confirm the fixture is actually carrying what we claim.
        self.assertTrue(Image.open(io.BytesIO(original)).getexif().get_ifd(0x8825))

        clean, manifest = ev._scrub_image(original)
        self.assertFalse(Image.open(io.BytesIO(clean)).getexif())
        self.assertIn("GPS", manifest["removed"])

    def test_the_camera_serial_is_gone(self):
        clean, manifest = ev._scrub_image(_jpeg_with_gps())
        self.assertNotIn(b"SERIAL-12345", clean)

    def test_the_manifest_records_what_was_removed(self):
        """A reviewer should be able to SEE the metadata as data, even though
        it no longer travels inside the file."""
        _, manifest = ev._scrub_image(_jpeg_with_gps())
        self.assertEqual(manifest["kind"], "image")
        self.assertIn("Make", manifest["removed"])
        self.assertIn("ACME Camera Co", manifest["removed"]["Make"])

    def test_the_picture_survives(self):
        from PIL import Image
        clean, _ = ev._scrub_image(_jpeg_with_gps())
        self.assertEqual(Image.open(io.BytesIO(clean)).size, (32, 32))

    def test_an_unreadable_image_is_refused_not_stored(self):
        with self.assertRaises(ev.EvidenceRefused):
            ev._scrub_image(b"this is not an image")


class OfficeScrubbingTest(unittest.TestCase):

    def test_the_author_and_company_are_gone(self):
        clean, manifest = ev._scrub_office(_docx_with_author())
        self.assertNotIn(b"J. Smith", clean)
        self.assertNotIn(b"Acme Holdings", clean)
        self.assertIn("docProps/core.xml", manifest["removed"])

    def test_the_document_content_survives(self):
        clean, _ = ev._scrub_office(_docx_with_author())
        with zipfile.ZipFile(io.BytesIO(clean)) as z:
            self.assertIn(b"the actual text of the document",
                          z.read("word/document.xml"))

    def test_the_manifest_keeps_the_metadata_as_data(self):
        _, manifest = ev._scrub_office(_docx_with_author())
        self.assertIn("J. Smith", manifest["removed"]["docProps/core.xml"])

    def test_tracked_changes_are_flagged_as_not_removed(self):
        """They live in the document body. Claiming otherwise would be worse
        than saying nothing."""
        _, manifest = ev._scrub_office(_docx_with_author())
        self.assertIn("Tracked changes", manifest["note"])


class PdfTest(unittest.TestCase):

    def test_a_pdf_is_refused_when_no_library_is_available(self):
        """Refusing beats storing a PDF unscrubbed -- it carries the author,
        the producing application and often the local path."""
        with mock.patch.dict(sys.modules, {"pypdf": None}):
            with self.assertRaises(ev.EvidenceRefused) as caught:
                ev._scrub_pdf(b"%PDF-1.4 whatever")
            self.assertIn("not available", str(caught.exception))


class GateTest(unittest.TestCase):
    """Type checking and the scan requirement."""

    def setUp(self):
        self.jpeg = _jpeg_with_gps()
        self._scan = mock.patch.object(ev.upload_security,
                                       "scan_bytes_with_clamav")
        self._scan.start()
        self._available = mock.patch.object(ev, "scanning_available",
                                            return_value=True)
        self._available.start()

    def tearDown(self):
        self._available.stop()
        self._scan.stop()

    def test_a_clean_image_is_accepted_and_scrubbed(self):
        prepared = ev.prepare(self.jpeg, "photo.jpg", "image/jpeg")
        self.assertEqual(prepared["mimetype"], "image/jpeg")
        self.assertNotEqual(prepared["original_sha256"],
                            prepared["scrubbed_sha256"])

    def test_the_original_hash_is_of_the_untouched_bytes(self):
        """The evidentiary copy must be provably unmodified."""
        import hashlib
        prepared = ev.prepare(self.jpeg, "photo.jpg", "image/jpeg")
        self.assertEqual(prepared["original_sha256"],
                         hashlib.sha256(self.jpeg).hexdigest())
        self.assertEqual(prepared["_original"], self.jpeg)

    def test_an_unlisted_type_is_refused(self):
        with self.assertRaises(ev.EvidenceRefused):
            ev.prepare(b"MZ\x90\x00", "payload.exe", "application/x-msdownload")

    def test_a_file_lying_about_its_type_is_refused(self):
        """Magic bytes must match the declaration."""
        with self.assertRaises(ev.EvidenceRefused) as caught:
            ev.prepare(b"not a real png at all", "x.png", "image/png")
        self.assertIn("does not look like", str(caught.exception))

    def test_an_oversize_file_is_refused(self):
        with mock.patch.object(ev, "MAX_FILE_BYTES", 10):
            with self.assertRaises(ev.EvidenceRefused):
                ev.prepare(self.jpeg, "photo.jpg", "image/jpeg")

    def test_an_empty_file_is_refused(self):
        with self.assertRaises(ev.EvidenceRefused):
            ev.prepare(b"", "empty.jpg", "image/jpeg")

    def test_an_infected_file_is_refused(self):
        with mock.patch.object(ev.upload_security, "scan_bytes_with_clamav",
                               side_effect=ev.upload_security.UnsafeUploadError(
                                   "Eicar-Test-Signature")):
            with self.assertRaises(ev.EvidenceRefused) as caught:
                ev.prepare(self.jpeg, "photo.jpg", "image/jpeg")
            self.assertIn("Eicar", str(caught.exception))

    def test_a_scanner_error_refuses_rather_than_allowing(self):
        """Fail closed here regardless of the global policy."""
        with mock.patch.object(ev.upload_security, "scan_bytes_with_clamav",
                               side_effect=RuntimeError("scanner exploded")):
            with self.assertRaises(ev.EvidenceRefused):
                ev.prepare(self.jpeg, "photo.jpg", "image/jpeg")


class NoScannerTest(unittest.TestCase):

    def test_no_scanner_configured_refuses_attachments(self):
        """upload_security returns silently with no scanner; for evidence that
        silence is indistinguishable from 'clean'."""
        with mock.patch.object(ev, "scanning_available", return_value=False):
            with self.assertRaises(ev.EvidenceRefused) as caught:
                ev.prepare(_jpeg_with_gps(), "photo.jpg", "image/jpeg")
            self.assertIn("virus-check", str(caught.exception))

    def test_the_refusal_tells_them_the_report_can_still_be_sent(self):
        """Losing the written report because an attachment failed would be the
        worse outcome."""
        with mock.patch.object(ev, "scanning_available", return_value=False):
            with self.assertRaises(ev.EvidenceRefused) as caught:
                ev.prepare(_jpeg_with_gps(), "photo.jpg", "image/jpeg")
            self.assertIn("still be submitted", str(caught.exception))


class ReferenceTest(unittest.TestCase):

    def test_the_payload_reference_carries_no_file_bytes(self):
        with mock.patch.object(ev, "scanning_available", return_value=True), \
             mock.patch.object(ev.upload_security, "scan_bytes_with_clamav"):
            prepared = ev.prepare(_jpeg_with_gps(), "photo.jpg", "image/jpeg")
        ref = ev.reference(prepared)
        self.assertNotIn("_original", ref)
        self.assertNotIn("_scrubbed", ref)
        self.assertIn("original_sha256", ref)

    def test_a_hostile_filename_is_defanged(self):
        self.assertEqual(ev._safe_name("../../etc/passwd"), "passwd")
        self.assertEqual(ev._safe_name("C:\\Users\\me\\secret.jpg"), "secret.jpg")
        self.assertTrue(len(ev._safe_name("x" * 500)) <= 120)

    def test_every_allowed_type_has_a_scrubber(self):
        """A type in the allowlist with no scrubber would be stored untouched."""
        for mimetype in ev.ALLOWED_TYPES:
            self.assertIsNotNone(ev.scrubber_for(mimetype),
                                 "%s is allowed but has no scrubber" % mimetype)


if __name__ == "__main__":
    unittest.main()
