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
import json
from pathlib import Path
from orin.core.database import OrinStorage
from orin.core.crypto import generate_signed_export, verify_signed_export, generate_coc_manifest

class TestCrypto(unittest.TestCase):
    def setUp(self):
        self.db_path = Path("test_crypto_unit.db")
        self.storage = OrinStorage(self.db_path)
        self.storage.initialize_db()
        
        with self.storage.get_connection() as conn:
            conn.execute(
                "INSERT INTO system_snapshots (id, hostname, os_platform) VALUES (1, 'test-host', 'Linux');"
            )
            conn.execute(
                "INSERT INTO collected_processes (snapshot_id, pid, ppid, name) VALUES (1, 100, 1, 'init');"
            )
            conn.execute(
                "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (1, 22, 'TCP', 'sshd');"
            )
            conn.execute(
                "INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash) VALUES (1, '/etc/passwd', 'abc123hash');"
            )
            conn.commit()

        self.export_path = Path("test_export.json")
        self.secret = "SuperSecureMasterPassphrase"

    def tearDown(self):
        if self.db_path.exists():
            self.db_path.unlink()
        if self.export_path.exists():
            self.export_path.unlink()

    def test_generate_and_verify_signed_export(self):
        signed_bundle = generate_signed_export(self.db_path, 1, self.secret)
        self.export_path.write_text(signed_bundle)
        
        bundle = json.loads(signed_bundle)
        self.assertIn("signature", bundle)
        self.assertIn("data", bundle)
        
        verified_data = verify_signed_export(self.export_path, self.secret)
        self.assertEqual(verified_data["metadata"]["hostname"], "test-host")
        self.assertEqual(len(verified_data["processes"]), 1)
        self.assertEqual(len(verified_data["ports"]), 1)
        self.assertEqual(len(verified_data["file_hashes"]), 1)

    def test_short_passphrase_validation(self):
        with self.assertRaises(ValueError):
            generate_signed_export(self.db_path, 1, "short")

    def test_tamper_detection(self):
        signed_bundle = generate_signed_export(self.db_path, 1, self.secret)
        bundle = json.loads(signed_bundle)
        
        data = json.loads(bundle["data"])
        data["metadata"]["hostname"] = "tampered-host"
        bundle["data"] = json.dumps(data)
        
        self.export_path.write_text(json.dumps(bundle))
        
        with self.assertRaises(PermissionError):
            verify_signed_export(self.export_path, self.secret)

    def test_signed_export_snapshot_not_exist(self):
        with self.assertRaises(ValueError):
            generate_signed_export(self.db_path, 9999, self.secret)

    def test_generate_coc_manifest_success_and_errors(self):
        # 1. Success without saving to file
        manifest = generate_coc_manifest(self.db_path, 1)
        self.assertEqual(manifest["snapshot_id"], 1)
        self.assertEqual(manifest["system_info"]["hostname"], "test-host")
        self.assertGreater(len(manifest["evidence_hashes"]), 0)
        
        # 2. Success saving to file
        import tempfile
        import shutil
        out_dir = Path(tempfile.mkdtemp())
        try:
            generate_coc_manifest(self.db_path, 1, output_dir=out_dir)
            self.assertTrue((out_dir / "coc_manifest_1.json").exists())
        finally:
            shutil.rmtree(out_dir)
            
        # 3. Snapshot ID does not exist raises ValueError
        with self.assertRaises(ValueError):
            generate_coc_manifest(self.db_path, 9999)

if __name__ == "__main__":
    unittest.main()
