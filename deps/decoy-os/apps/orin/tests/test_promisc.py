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
import errno
from unittest.mock import patch, MagicMock
from pathlib import Path
from orin.collectors.promisc import gather_promisc_interfaces

class TestPromisc(unittest.TestCase):
    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.iterdir")
    def test_gather_promisc_interfaces_success(self, mock_iterdir, mock_is_dir, mock_exists):
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        # Mock network interface directories
        iface_eth0 = MagicMock(spec=Path)
        iface_eth0.is_dir.return_value = True
        iface_eth0.name = "eth0"
        mock_eth0_flags = MagicMock(spec=Path)
        mock_eth0_flags.exists.return_value = True
        mock_eth0_flags.read_text.return_value = "0x1103\n"
        iface_eth0.__truediv__.return_value = mock_eth0_flags
        
        iface_lo = MagicMock(spec=Path)
        iface_lo.is_dir.return_value = True
        iface_lo.name = "lo"
        mock_lo_flags = MagicMock(spec=Path)
        mock_lo_flags.exists.return_value = True
        mock_lo_flags.read_text.return_value = "0x1003\n"
        iface_lo.__truediv__.return_value = mock_lo_flags
        
        mock_iterdir.return_value = [iface_eth0, iface_lo]
        
        res = gather_promisc_interfaces()
        
        self.assertEqual(len(res), 2)
        eth0_res = next(r for r in res if r["interface"] == "eth0")
        lo_res = next(r for r in res if r["interface"] == "lo")
        
        self.assertEqual(eth0_res["is_promiscuous"], 1)
        self.assertEqual(lo_res["is_promiscuous"], 0)

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    def test_gather_promisc_interfaces_no_net(self, mock_is_dir, mock_exists):
        mock_exists.return_value = False
        mock_is_dir.return_value = False
        res = gather_promisc_interfaces()
        self.assertEqual(res, [])

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.iterdir")
    def test_gather_promisc_interfaces_edge_cases(self, mock_iterdir, mock_is_dir, mock_exists):
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        
        # User 1: Non-directory in /sys/class/net (skipped)
        iface1 = MagicMock(spec=Path)
        iface1.is_dir.return_value = False
        
        # User 2: Directory but flags file doesn't exist (skipped)
        iface2 = MagicMock(spec=Path)
        iface2.is_dir.return_value = True
        iface2.name = "eth1"
        mock_eth1_flags = MagicMock(spec=Path)
        mock_eth1_flags.exists.return_value = False
        iface2.__truediv__.return_value = mock_eth1_flags
        
        # User 3: ValueError when parsing flags (malformed hex)
        iface3 = MagicMock(spec=Path)
        iface3.is_dir.return_value = True
        iface3.name = "eth2"
        mock_eth2_flags = MagicMock(spec=Path)
        mock_eth2_flags.exists.return_value = True
        mock_eth2_flags.read_text.return_value = "invalid_hex\n"
        iface3.__truediv__.return_value = mock_eth2_flags
        
        # User 4: ENOENT on read_text (device detached)
        iface4 = MagicMock(spec=Path)
        iface4.is_dir.return_value = True
        iface4.name = "eth3"
        mock_eth3_flags = MagicMock(spec=Path)
        mock_eth3_flags.exists.return_value = True
        mock_eth3_flags.read_text.side_effect = OSError(errno.ENOENT, "No such file")
        iface4.__truediv__.return_value = mock_eth3_flags
        
        # User 5: Permission denied on read_text
        iface5 = MagicMock(spec=Path)
        iface5.is_dir.return_value = True
        iface5.name = "eth4"
        mock_eth4_flags = MagicMock(spec=Path)
        mock_eth4_flags.exists.return_value = True
        mock_eth4_flags.read_text.side_effect = OSError(errno.EACCES, "Permission denied")
        iface5.__truediv__.return_value = mock_eth4_flags
        
        mock_iterdir.return_value = [iface1, iface2, iface3, iface4, iface5]
        
        res = gather_promisc_interfaces()
        # Only eth2 and eth4 should be returned (as anomaly entries)
        self.assertEqual(len(res), 2)
        eth2_res = next(r for r in res if r["interface"] == "eth2")
        self.assertEqual(eth2_res["flags"], "ERROR_MALFORMED_HEX")
        
        eth4_res = next(r for r in res if r["interface"] == "eth4")
        self.assertEqual(eth4_res["flags"], "ERROR_ACCESS_DENIED")

    @patch("pathlib.Path.exists")
    @patch("pathlib.Path.is_dir")
    @patch("pathlib.Path.iterdir")
    def test_gather_promisc_interfaces_traversal_fault(self, mock_iterdir, mock_is_dir, mock_exists):
        mock_exists.return_value = True
        mock_is_dir.return_value = True
        mock_iterdir.side_effect = PermissionError("Permission denied traversing dir")
        
        res = gather_promisc_interfaces()
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["interface"], "ERROR_SYS_CLASS_NET_ROOT")
        self.assertEqual(res[0]["flags"], "ERROR_TRAVERSAL_FAULT")

if __name__ == "__main__":
    unittest.main()
