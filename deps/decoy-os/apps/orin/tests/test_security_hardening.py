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

import unittest
import os
import tempfile
import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

from orin.core.crypto import zero_memory, generate_signed_export, verify_signed_export
from orin.core.credentials import SecureCredential, CredentialManager
from orin.core.database import EncryptedStorage, derive_key
from orin.orchestrator import resolve_export_secret, cmd_export, cmd_verify, cmd_diff


class TestSecurityHardening(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.db_path = Path(self.temp_dir) / "test_vault.db"
        self.export_path = Path(self.temp_dir) / "test_export.json"

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def test_zero_memory_bytearray(self):
        ba = bytearray(b"super-secret-value")
        zero_memory(ba)
        self.assertEqual(ba, bytearray(len(ba)))

    def test_zero_memory_bytes(self):
        # Construct bytes dynamically at runtime to keep CPython reference count <= 4
        b = bytes(bytearray(b"another-secret-bytes-payload"))
        zero_memory(b)
        # Verify it has been filled with zeroes in-place
        self.assertEqual(b, b"\x00" * len(b))

    def test_zero_memory_str(self):
        # Construct str dynamically at runtime to keep CPython reference count <= 4
        s = str(bytearray(b"another-secret-string-payload").decode("utf-8"))
        zero_memory(s)
        # Verify it has been filled with zeroes in-place
        self.assertEqual(s, "\x00" * len(s))

    def test_secure_credential_zeroize(self):
        cred = SecureCredential("passphrase-value-here-1234")
        self.assertEqual(cred.get_value(), "passphrase-value-here-1234")
        cred.zeroize()
        self.assertIsNone(cred._value)

    def test_credential_manager_env_eviction(self):
        os.environ["TEST_VAULT_PASSPHRASE"] = "very-secret-passphrase-here"
        mgr = CredentialManager(vault_passphrase_env="TEST_VAULT_PASSPHRASE")
        cred = mgr.load_vault_passphrase()
        self.assertEqual(cred.get_value(), "very-secret-passphrase-here")
        self.assertNotIn("TEST_VAULT_PASSPHRASE", os.environ)

    def test_database_pbkdf2_upgrade_and_compat(self):
        old_val = os.environ.pop("ORIN_TEST_FAST", None)
        try:
            self._run_database_pbkdf2_upgrade_and_compat()
        finally:
            if old_val is not None:
                os.environ["ORIN_TEST_FAST"] = old_val

    def _run_database_pbkdf2_upgrade_and_compat(self):
        plain_path = Path(self.temp_dir) / "test_plain.db"
        # Simulate SQLite header structure
        dummy_sqlite = b"SQLite format 3\x00" + b"\x00" * 84
        plain_path.write_bytes(dummy_sqlite)

        # 1. New DB should create 20-byte meta file (16 bytes salt + 4 bytes iteration count)
        storage = EncryptedStorage("my-secret-passphrase-123")
        storage.encrypt_file(plain_path, self.db_path)

        meta_path = self.db_path.with_suffix(self.db_path.suffix + ".meta")
        self.assertTrue(meta_path.exists())
        meta_data = meta_path.read_bytes()
        self.assertEqual(len(meta_data), 20)

        # Iteration count should be 600,000 (0x0927c0)
        iterations = int.from_bytes(meta_data[16:20], "big")
        self.assertEqual(iterations, 600_000)

        # Decrypt it back
        dec_path = Path(self.temp_dir) / "test_dec.db"
        storage.decrypt_file(self.db_path, dec_path)
        self.assertTrue(dec_path.exists())
        self.assertEqual(dec_path.read_bytes(), dummy_sqlite)

        # 2. Backward compatibility: legacy 16-byte meta file using 100,000 iterations
        db_legacy_path = Path(self.temp_dir) / "test_legacy.db"
        legacy_salt = b"L" * 16
        legacy_meta_path = db_legacy_path.with_suffix(db_legacy_path.suffix + ".meta")
        legacy_meta_path.write_bytes(legacy_salt) # 16 bytes exactly

        # Encrypt manually using PBKDF2 iterations = 100,000
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        legacy_key = derive_key("my-secret-passphrase-123", legacy_salt, 100_000)
        aesgcm = AESGCM(legacy_key)
        nonce = b"N" * 12
        ciphertext = aesgcm.encrypt(nonce, dummy_sqlite, None)
        db_legacy_path.write_bytes(legacy_salt + nonce + ciphertext)

        # Decrypt it using EncryptedStorage (which reads 16-byte legacy meta file)
        legacy_storage = EncryptedStorage("my-secret-passphrase-123")
        dec_legacy_path = Path(self.temp_dir) / "test_dec_legacy.db"
        legacy_storage.decrypt_file(db_legacy_path, dec_legacy_path)
        self.assertTrue(dec_legacy_path.exists())
        self.assertEqual(dec_legacy_path.read_bytes(), dummy_sqlite)

    def test_resolve_export_secret_cli(self):
        args = MagicMock()
        args.secret = "my-secret-cli-argument"
        secret = resolve_export_secret(args)
        self.assertEqual(secret, "my-secret-cli-argument")

    def test_resolve_export_secret_file(self):
        secret_file = Path(self.temp_dir) / "sec.txt"
        secret_file.write_text("my-secret-file-content\n")
        # Ensure correct restricted permissions
        os.chmod(secret_file, 0o600)

        args = MagicMock()
        args.secret = None
        args.secret_file = str(secret_file)

        secret = resolve_export_secret(args)
        self.assertEqual(secret, "my-secret-file-content")

    @patch("getpass.getpass")
    def test_resolve_export_secret_prompt(self, mock_getpass):
        mock_getpass.return_value = "my-secret-prompt-content"
        args = MagicMock()
        args.secret = None
        args.secret_file = None
        args.secret_prompt = True

        secret = resolve_export_secret(args)
        self.assertEqual(secret, "my-secret-prompt-content")

    def test_resolve_export_secret_env(self):
        os.environ["ORIN_EXPORT_SECRET"] = "my-secret-env-content"
        args = MagicMock()
        args.secret = None
        args.secret_file = None
        args.secret_prompt = False
        args.secret_env_var = None

        secret = resolve_export_secret(args)
        self.assertEqual(secret, "my-secret-env-content")
        self.assertNotIn("ORIN_EXPORT_SECRET", os.environ)

    @patch("orin.orchestrator.resolve_export_secret")
    def test_cmd_export_verify_diff(self, mock_resolve):
        # Setup mocks
        mock_resolve.return_value = "SuperSecureSigningPassphrase"
        
        # Test diff command
        diff_args = MagicMock()
        diff_args.base_file = str(self.export_path)
        diff_args.target_file = str(self.export_path)
        diff_args.verbose = False

        with patch("orin.analysis.diff.load_snapshot_data") as mock_load, \
             patch("orin.analysis.diff.compare_snapshots") as mock_compare:
            mock_load.return_value = {"metadata": {"hostname": "h"}}
            mock_compare.return_value = {"total_changes": 0, "critical_changes": 0}
            res = cmd_diff(diff_args)
            self.assertEqual(res, 0)

        # Test export command
        export_args = MagicMock()
        export_args.database = str(self.db_path)
        export_args.snapshot = 1
        export_args.output = str(self.export_path)

        with patch("os.path.exists", return_value=True), \
             patch("orin.core.crypto.generate_signed_export") as mock_gen, \
             patch("orin.core.crypto.generate_coc_manifest") as mock_coc, \
             patch("builtins.open", unittest.mock.mock_open()):
            mock_gen.return_value = "signed-data"
            mock_coc.return_value = {"evidence_count": 0}
            res = cmd_export(export_args)
            self.assertEqual(res, 0)

        # Test verify command
        verify_args = MagicMock()
        verify_args.file = str(self.export_path)

        with patch("os.path.exists", return_value=True), \
             patch("orin.core.crypto.verify_signed_export") as mock_ver:
            mock_ver.return_value = {"snapshot_id": 1, "metadata": {"timestamp": "2026"}}
            res = cmd_verify(verify_args)
            self.assertEqual(res, 0)


if __name__ == "__main__":
    unittest.main()
