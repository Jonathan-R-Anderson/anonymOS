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
from unittest.mock import patch, MagicMock, mock_open
import sys
from pathlib import Path

# Add ebpf directory to sys.path to easily import consumer
EBPF_DIR = Path(__file__).parent.parent / "ebpf"
sys.path.append(str(EBPF_DIR))

# Mock BPF since we are running unit tests without requiring a real kernel compiler context
sys.modules['bcc'] = MagicMock()

import consumer

class TestEBPFSetupAndAutoGeneration(unittest.TestCase):
    def setUp(self):
        # Clean patches before each test
        pass

    @patch("consumer.EBPF_PROGRAM_PATH")
    @patch("consumer.init_db")
    @patch("consumer.BPF")
    @patch("consumer.argparse.ArgumentParser.parse_args")
    def test_consumer_vmlinux_exists_loads_directly(self, mock_parse_args, mock_bpf, mock_init_db, mock_ebpf_program_path):
        # Setup mock paths where vmlinux.h exists
        mock_ebpf_program_path.exists.return_value = True
        mock_ebpf_program_path.parent = MagicMock()
        mock_vmlinux = MagicMock()
        mock_vmlinux.exists.return_value = True
        mock_ebpf_program_path.parent.__truediv__.return_value = mock_vmlinux
        
        mock_parse_args.return_value = MagicMock(verbose=False)

        # Execute main (should load directly without generation)
        with patch("consumer.Path.exists", return_value=True), \
             patch("consumer.EBPF_ELF_PATH") as mock_elf_path:
            mock_elf_path.exists.return_value = True
            # This should load successfully and print successful loading message
            with patch("consumer.sys.exit") as mock_exit:
                # We mock open_ring_buffer to prevent loop
                mock_bpf_instance = MagicMock()
                mock_bpf.return_value = mock_bpf_instance
                
                mock_rb = MagicMock()
                mock_rb.poll.side_effect = KeyboardInterrupt
                mock_bpf_instance.__getitem__.return_value = mock_rb
                
                consumer.main()
                
                mock_exit.assert_not_called()
                mock_bpf.assert_called_once()

    @patch("consumer.EBPF_PROGRAM_PATH")
    @patch("consumer.init_db")
    @patch("consumer.BPF")
    @patch("consumer.argparse.ArgumentParser.parse_args")
    @patch("shutil.which")
    @patch("subprocess.run")
    @patch("builtins.open", new_callable=mock_open)
    def test_consumer_vmlinux_missing_auto_generates(self, mock_file_open, mock_subproc_run, mock_shutil_which, mock_parse_args, mock_bpf, mock_init_db, mock_ebpf_program_path):
        mock_ebpf_program_path.exists.return_value = True
        mock_ebpf_program_path.parent = MagicMock()
        
        # vmlinux.h starts missing but exists after subprocess runs
        mock_vmlinux = MagicMock()
        mock_vmlinux.exists.side_effect = [False, True, True] # Check 1 (missing), Check 2 (after generation - exists)
        mock_ebpf_program_path.parent.__truediv__.return_value = mock_vmlinux
        
        mock_parse_args.return_value = MagicMock(verbose=False)
        mock_shutil_which.return_value = "/usr/sbin/bpftool"
        
        mock_bpf_instance = MagicMock()
        mock_bpf.return_value = mock_bpf_instance
        
        mock_rb = MagicMock()
        mock_rb.poll.side_effect = KeyboardInterrupt
        mock_bpf_instance.__getitem__.return_value = mock_rb

        # Mock the BTF source structure existence and EBPF ELF checks
        with patch("consumer.Path.exists") as mock_path_exists:
            mock_path_exists.side_effect = [False, True, True]

            consumer.main()
            
            # Assert bpftool command was invoked
            mock_subproc_run.assert_any_call(
                ["/usr/sbin/bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"],
                stdout=mock_file_open.return_value,
                check=True
            )

    @patch("consumer.EBPF_PROGRAM_PATH")
    @patch("consumer.init_db")
    @patch("consumer.BPF")
    @patch("consumer.argparse.ArgumentParser.parse_args")
    @patch("shutil.which")
    @patch("subprocess.run")
    def test_consumer_vmlinux_missing_generation_fails_exits(self, mock_subproc_run, mock_shutil_which, mock_parse_args, mock_bpf, mock_init_db, mock_ebpf_program_path):
        mock_ebpf_program_path.exists.return_value = True
        mock_ebpf_program_path.parent = MagicMock()
        
        # vmlinux.h is always missing
        mock_vmlinux = MagicMock()
        mock_vmlinux.exists.return_value = False
        mock_ebpf_program_path.parent.__truediv__.return_value = mock_vmlinux
        
        mock_parse_args.return_value = MagicMock(verbose=False)
        
        # Even if bpftool is there, generation throws an exception or doesn't write
        mock_shutil_which.return_value = "/usr/sbin/bpftool"
        mock_subproc_run.side_effect = Exception("bpftool crash")

        # Mock BTF source as present so it attempts generation
        with patch("consumer.Path.exists") as mock_path_exists:
            mock_path_exists.side_effect = [False, True]

            with patch("consumer.sys.exit", side_effect=SystemExit) as mock_exit:
                with self.assertRaises(SystemExit):
                    consumer.main()
                mock_exit.assert_called_with(1)

if __name__ == "__main__":
    unittest.main()
