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
from orin.analysis.attck import get_attck_enrichment, ATTCK_MAP, DEFAULT_ATTCK

class TestAttck(unittest.TestCase):
    def test_known_mappings(self):
        # Verify general event types mapping
        for event_type, (expected_tech, expected_tactic, expected_url) in ATTCK_MAP.items():
            tech, tactic, url = get_attck_enrichment(event_type)
            self.assertEqual(tech, expected_tech)
            self.assertEqual(tactic, expected_tactic)
            self.assertEqual(url, expected_url)

    def test_suspicious_process_ancestry_refinements(self):
        # Case A: Masquerade in description
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Masquerade Fraud: Non-system ancestry parent discovered")
        self.assertEqual(tech, "T1036.004")
        self.assertEqual(tactic, "Defense Evasion")

        # Case B: Volatile in description
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Process running from volatile system workspace directory")
        self.assertEqual(tech, "T1036")
        self.assertEqual(tactic, "Defense Evasion")

        # Case C: Other/shell execution
        tech, tactic, url = get_attck_enrichment("suspicious_process_ancestry", "Suspicious interactive command parameter flags matched")
        self.assertEqual(tech, "T1059.004")
        self.assertEqual(tactic, "Execution")

    def test_fallback_mapping(self):
        # Verify fallback for completely unknown event types
        tech, tactic, url = get_attck_enrichment("completely_unknown_event_type_here")
        self.assertEqual(tech, DEFAULT_ATTCK[0])
        self.assertEqual(tactic, DEFAULT_ATTCK[1])
        self.assertEqual(url, DEFAULT_ATTCK[2])

    def test_tactic_prefix_fallback(self):
        """Test technique ID extraction with tactic prefix fallback."""
        # Test Defense Evasion prefix
        tech, tactic, url = get_attck_enrichment("test", "T1036.005 Masquerading")
        self.assertEqual(tech, "T1036.005")
        self.assertEqual(tactic, "Defense Evasion")

        # Test Persistence prefix
        tech, tactic, url = get_attck_enrichment("test", "T1053.001 Scheduled Task")
        self.assertEqual(tech, "T1053.001")
        self.assertEqual(tactic, "Persistence")

        # Test Privilege Escalation prefix
        tech, tactic, url = get_attck_enrichment("test", "T1548.003 Sudo Caching")
        self.assertEqual(tech, "T1548.003")
        self.assertEqual(tactic, "Privilege Escalation")

        # Test Credential Access prefix
        tech, tactic, url = get_attck_enrichment("test", "T1110.003 Password Spraying")
        self.assertEqual(tech, "T1110.003")
        self.assertEqual(tactic, "Credential Access")

        # Test Command and Control prefix
        tech, tactic, url = get_attck_enrichment("test", "T1571.001 Uncommon Port")
        self.assertEqual(tech, "T1571.001")
        self.assertEqual(tactic, "Command and Control")

if __name__ == "__main__":
    unittest.main()