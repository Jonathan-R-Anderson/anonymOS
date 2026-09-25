# Copyright (C) 2026 Musa Jaradat
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""Test suite for orin.core.self_verify module - Self-verification & signed releases."""
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from orin.core.self_verify import (
    compute_file_sha256,
    compute_file_hash,
    generate_sbom,
    generate_release_manifest,
    verify_against_manifest,
    self_check,
    sign_manifest_with_gpg,
    verify_gpg_signature,
)


class TestComputeFileHash(unittest.TestCase):
    def test_compute_file_sha256(self):
        """Test SHA-256 computation on a known file."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"hello world")
            temp_path = Path(f.name)

        try:
            # SHA-256 of "hello world"
            expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
            result = compute_file_sha256(temp_path)
            self.assertEqual(result, expected)
        finally:
            temp_path.unlink()

    def test_compute_file_hash_md5(self):
        """Test MD5 computation."""
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(b"test data")
            temp_path = Path(f.name)

        try:
            expected = hashlib.md5(b"test data", usedforsecurity=False).hexdigest()
            result = compute_file_hash(temp_path, algorithm="md5")
            self.assertEqual(result, expected)
        finally:
            temp_path.unlink()


class TestSBOMGeneration(unittest.TestCase):
    def test_generate_sbom_structure(self):
        """Test that SBOM has correct structure."""
        sbom = generate_sbom(Path('.'))

        self.assertIn("sbom_version", sbom)
        self.assertIn("generated_at", sbom)
        self.assertIn("tool_info", sbom)
        self.assertIn("components", sbom)
        self.assertIn("dependencies", sbom)

        # Should have components
        self.assertGreater(len(sbom["components"]), 0)

        # Check component structure
        if sbom["components"]:
            comp = sbom["components"][0]
            self.assertIn("type", comp)
            self.assertIn("name", comp)
            self.assertIn("hashes", comp)
            self.assertIn("SHA-256", comp["hashes"])


class TestReleaseManifest(unittest.TestCase):
    def test_generate_release_manifest_structure(self):
        """Test that release manifest has correct structure."""
        manifest = generate_release_manifest(Path('.'))

        self.assertIn("manifest_version", manifest)
        self.assertIn("generated_at", manifest)
        self.assertIn("files", manifest)
        self.assertIn("summary", manifest)
        self.assertIn("manifest_hash", manifest)

        # Should have files
        self.assertGreater(len(manifest["files"]), 0)

        # Check summary
        self.assertIn("total_files", manifest["summary"])
        self.assertIn("total_size_bytes", manifest["summary"])
        self.assertEqual(manifest["summary"]["total_files"], len(manifest["files"]))

    def test_verify_against_generated_manifest(self):
        """Test verification against a freshly generated manifest."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Generate and save manifest
            manifest = generate_release_manifest(Path('.'), output_path=manifest_path)

            # Verify
            success, passed, failed = verify_against_manifest(manifest_path, Path('.'))

            self.assertTrue(success, f"Verification failed: {failed}")
            self.assertGreater(len(passed), 0)
            self.assertEqual(len(failed), 0)

    def test_verify_detects_tampering(self):
        """Test that verification detects file tampering."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Generate manifest
            manifest = generate_release_manifest(Path('.'), output_path=manifest_path)

            # Tamper with the manifest hash
            manifest["files"]["pyproject.toml"]["sha256"] = "0" * 64

            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            # Verify should fail
            success, passed, failed = verify_against_manifest(manifest_path, Path('.'))

            self.assertFalse(success)
            self.assertTrue(any("HASH MISMATCH" in f for f in failed))

    def test_verify_detects_missing_file(self):
        """Test that verification detects missing files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Create a minimal manifest
            manifest = {
                "manifest_version": "1.0.0",
                "generated_at": "2024-01-01T00:00:00Z",
                "files": {
                    "nonexistent_file.txt": {
                        "sha256": "abc123",
                        "size_bytes": 100,
                        "category": "docs"
                    }
                },
                "summary": {"total_files": 1}
            }

            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            # Verify should fail
            success, passed, failed = verify_against_manifest(manifest_path, Path('.'))

            self.assertFalse(success)
            self.assertTrue(any("FILE MISSING" in f for f in failed))

    def test_verify_detects_manifest_tampering(self):
        """Test that verification detects manifest self-hash tampering."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"

            # Generate manifest
            manifest = generate_release_manifest(Path('.'), output_path=manifest_path)

            # Tamper with manifest content but keep the old hash
            manifest["tool_version"] = "tampered"

            with open(manifest_path, 'w') as f:
                json.dump(manifest, f)

            # Verify should detect manifest self-hash invalid
            success, passed, failed = verify_against_manifest(manifest_path, Path('.'))

            self.assertFalse(success)
            self.assertTrue(any("MANIFEST SELF-HASH INVALID" in f for f in failed))


class TestSelfCheck(unittest.TestCase):
    def test_self_check_with_valid_root(self):
        """Test self-check passes when run from package root."""
        success, message = self_check(package_root=Path('.'))

        # Since we don't have embedded reference hashes, it should pass
        # by reporting current hashes
        self.assertTrue(success)
        self.assertIn("PASSED", message)

    def test_self_check_reports_missing_files(self):
        """Test self-check reports missing critical files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            success, message = self_check(package_root=Path(tmpdir))

            self.assertFalse(success)
            self.assertIn("FAILED", message)
            self.assertIn("FILE MISSING", message)


class TestGPGIntegration(unittest.TestCase):
    @unittest.skip("Requires GPG key setup")
    def test_gpg_sign_and_verify(self):
        """Test GPG signing and verification (requires key)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manifest_path = Path(tmpdir) / "manifest.json"
            generate_release_manifest(Path('.'), output_path=manifest_path)

            sig_path = sign_manifest_with_gpg(manifest_path)
            self.assertTrue(sig_path.exists())

            is_valid = verify_gpg_signature(manifest_path, sig_path)
            self.assertTrue(is_valid)


if __name__ == "__main__":
    unittest.main()


# ---------------------------------------------------------------------------
# Extended tests for uncovered functions
# ---------------------------------------------------------------------------
import os
from orin.core.self_verify import (
    export_sbom,
    print_sbom_summary,
    print_manifest_summary,
    _get_embedded_reference_hashes,
)


class TestExportSbom(unittest.TestCase):
    def test_export_sbom_json(self):
        sbom = generate_sbom(Path("."))
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            out_path = Path(f.name)
        try:
            export_sbom(Path("."), out_path, format="json")
            content = json.loads(out_path.read_text())
            self.assertIn("components", content)
        finally:
            os.unlink(out_path)

    def test_export_sbom_txt(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            out_path = Path(f.name)
        try:
            export_sbom(Path("."), out_path, format="txt")
            content = out_path.read_text()
            self.assertTrue(len(content) > 0)
        finally:
            os.unlink(out_path)

    def test_export_sbom_csv(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            out_path = Path(f.name)
        try:
            export_sbom(Path("."), out_path, format="csv")
            content = out_path.read_text()
            self.assertTrue(len(content) > 0)
        finally:
            os.unlink(out_path)


class TestPrintSummaries(unittest.TestCase):
    def test_print_sbom_summary(self):
        sbom = generate_sbom(Path("."))
        # Should not raise
        print_sbom_summary(sbom)

    def test_print_manifest_summary(self):
        manifest = generate_release_manifest(Path("."))
        # Should not raise
        print_manifest_summary(manifest)


class TestEmbeddedReferenceHashes(unittest.TestCase):
    def test_returns_dict(self):
        hashes = _get_embedded_reference_hashes()
        self.assertIsInstance(hashes, dict)