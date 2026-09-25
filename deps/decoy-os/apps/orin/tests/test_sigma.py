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
# tests/test_sigma.py
import unittest
import tempfile
import json
from pathlib import Path
from orin.analysis.sigma import parse_yaml_rule, evaluate_condition, evaluate_rule_against_log, load_rules
from orin.analysis.engine import run_analysis_cycle
from orin.core.database import OrinStorage

class TestSigma(unittest.TestCase):
    def test_parse_yaml_rule(self):
        yaml_content = """
title: SSH brute-force attempts
id: 5b6c1234-abcd-4ef0-9e8c-1234567890ab
description: Detects multiple failed SSH login attempts
detection:
  selection:
    - 'Failed password for'
    - 'authentication failure'
  condition: selection
level: medium
tags:
  - attack.t1110.001
"""
        rule = parse_yaml_rule(yaml_content)
        self.assertEqual(rule.get("title"), "SSH brute-force attempts")
        self.assertEqual(rule.get("id"), "5b6c1234-abcd-4ef0-9e8c-1234567890ab")
        self.assertEqual(rule.get("level"), "medium")
        self.assertEqual(rule.get("tags"), ["attack.t1110.001"])
        self.assertIn("detection", rule)
        self.assertEqual(rule["detection"].get("condition"), "selection")
        self.assertEqual(rule["detection"].get("selection"), ['Failed password for', 'authentication failure'])

    def test_evaluate_condition(self):
        selector_values = {"selection_a": True, "selection_b": False}
        self.assertTrue(evaluate_condition("selection_a", selector_values))
        self.assertFalse(evaluate_condition("selection_b", selector_values))
        self.assertTrue(evaluate_condition("selection_a or selection_b", selector_values))
        self.assertFalse(evaluate_condition("selection_a and selection_b", selector_values))
        self.assertTrue(evaluate_condition("not selection_b", selector_values))

        # Test wildcard prefix
        sel_vals = {"selection_1": True, "selection_2": False, "other": True}
        self.assertTrue(evaluate_condition("1 of selection*", sel_vals))
        self.assertFalse(evaluate_condition("all of selection*", sel_vals))
        
        sel_vals_all = {"selection_1": True, "selection_2": True}
        self.assertTrue(evaluate_condition("all of selection*", sel_vals_all))

    def test_evaluate_rule_against_log(self):
        rule = {
            "detection": {
                "selection_service": ["sudo:"],
                "selection_binaries": ["COMMAND=/usr/bin/find", "COMMAND=/usr/bin/vim"],
                "condition": "selection_service and selection_binaries"
            }
        }
        log_match = "Jun 04 12:00:00 host sudo: pam_unix(sudo:session): session opened; COMMAND=/usr/bin/find /"
        log_no_match = "Jun 04 12:00:00 host sudo: pam_unix(sudo:session): session opened; COMMAND=/usr/bin/ls"
        
        self.assertTrue(evaluate_rule_against_log(log_match, rule))
        self.assertFalse(evaluate_rule_against_log(log_no_match, rule))

    def test_engine_eval_with_db(self):
        # Create a temp database
        with tempfile.NamedTemporaryFile() as tmp_db:
            db_path = Path(tmp_db.name)
            storage = OrinStorage(db_path)
            storage.initialize_db()

            with storage.get_connection() as conn:
                snapshot_id = storage.create_snapshot(conn, hostname="test-host", os_platform="Linux")
                
                # Insert mock auth logs matching our Sigma rules
                logs = [
                    "Jun 04 22:00:00 test-host sudo: musa : TTY=pts/0 ; PWD=/home/musa ; USER=root ; COMMAND=/usr/bin/find / -name flag",
                    "Jun 04 22:01:00 test-host sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2"
                ]
                storage.store_auth_logs(conn, snapshot_id, logs)
                conn.commit()

            # Execute threat assessment cycle
            metrics = run_analysis_cycle(db_path)
            self.assertEqual(metrics["status"], "success")
            self.assertEqual(metrics["snapshot_id"], snapshot_id)

            # Query database for generated security events
            with storage.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT event_type, severity, description, attck_technique, attck_tactic FROM security_events;")
                events = cursor.fetchall()
                
                # Check that we generated events from the Sigma rules
                # The rule sudo_privesc_abuse.yml should match
                # The rule ssh_bruteforce.yml should match the failed password log line
                sigma_events = [e for e in events if e["event_type"] == "sigma_rule_match"]
                self.assertTrue(len(sigma_events) >= 1)
                
                # Check ATT&CK mapping was populated correctly via our new parsing logic
                has_privesc_match = False
                has_ssh_match = False
                for e in sigma_events:
                    if "Sudo privilege escalation execution" in e["description"]:
                        has_privesc_match = True
                        self.assertEqual(e["severity"], "high")
                        self.assertEqual(e["attck_technique"], "T1548.002")
                        self.assertEqual(e["attck_tactic"], "Privilege Escalation")
                    elif "SSH brute-force attempts" in e["description"]:
                        has_ssh_match = True
                        self.assertEqual(e["severity"], "medium")
                        self.assertEqual(e["attck_technique"], "T1110.001")
                        self.assertEqual(e["attck_tactic"], "Credential Access")

                self.assertTrue(has_privesc_match)
                self.assertTrue(has_ssh_match)

if __name__ == "__main__":
    unittest.main()
