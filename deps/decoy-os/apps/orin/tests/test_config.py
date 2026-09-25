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
"""Unit tests for orin.core.config module."""
import unittest
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, mock_open

from orin.core.config import (
    load_config,
    load_config_with_source,
    DEFAULT_CONFIG,
    DEFAULT_CONFIG_LOCATIONS
)


class TestConfigDefaults(unittest.TestCase):
    """Test default configuration values."""

    def test_default_config_has_expected_ports(self):
        """Verify DEFAULT_CONFIG contains expected_ports key."""
        self.assertIn("expected_ports", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["expected_ports"], list)
        self.assertIn(22, DEFAULT_CONFIG["expected_ports"])

    def test_default_config_has_whitelisted_processes(self):
        """Verify DEFAULT_CONFIG contains whitelisted_processes key."""
        self.assertIn("whitelisted_processes", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["whitelisted_processes"], list)

    def test_default_config_has_critical_paths(self):
        """Verify DEFAULT_CONFIG contains critical_paths key."""
        self.assertIn("critical_paths", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["critical_paths"], list)
        self.assertIn("/etc/passwd", DEFAULT_CONFIG["critical_paths"])

    def test_default_config_has_critical_dirs(self):
        """Verify DEFAULT_CONFIG contains critical_dirs key."""
        self.assertIn("critical_dirs", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["critical_dirs"], list)

    def test_default_config_has_vault_encryption(self):
        """Verify DEFAULT_CONFIG contains vault_encryption settings."""
        self.assertIn("vault_encryption", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["vault_encryption"], dict)
        self.assertIn("enabled", DEFAULT_CONFIG["vault_encryption"])

    def test_default_config_has_logging_settings(self):
        """Verify DEFAULT_CONFIG contains logging settings."""
        self.assertIn("logging", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["logging"], dict)
        self.assertEqual(DEFAULT_CONFIG["logging"]["level"], "INFO")
        self.assertEqual(DEFAULT_CONFIG["logging"]["format"], "json")

    def test_default_config_has_collectors_settings(self):
        """Verify DEFAULT_CONFIG contains collectors settings."""
        self.assertIn("collectors", DEFAULT_CONFIG)
        self.assertIsInstance(DEFAULT_CONFIG["collectors"], dict)
        self.assertIn("parallel_enabled", DEFAULT_CONFIG["collectors"])
        self.assertIn("default_timeout", DEFAULT_CONFIG["collectors"])


class TestLoadConfigNoFile(unittest.TestCase):
    """Test load_config when no config file exists."""

    @patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS')
    def test_load_config_returns_defaults_when_no_file(self, mock_locations):
        """Verify load_config returns DEFAULT_CONFIG when no file exists."""
        mock_locations.__iter__ = lambda self: iter([])

        config = load_config()

        self.assertEqual(config, DEFAULT_CONFIG)
        self.assertIsNot(config, DEFAULT_CONFIG)  # Should be a copy

    @patch.object(Path, 'exists', return_value=False)
    def test_load_config_with_nonexistent_locations(self, mock_exists):
        """Verify load_config handles non-existent config locations."""
        config = load_config()

        self.assertEqual(config, DEFAULT_CONFIG)


class TestLoadConfigWithFile(unittest.TestCase):
    """Test load_config when config file exists."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "orin_config.json"

    def tearDown(self):
        """Clean up test fixtures."""
        if self.config_path.exists():
            self.config_path.unlink()
        Path(self.temp_dir).rmdir()

    def test_load_config_from_local_file(self):
        """Verify load_config loads from local orin_config.json."""
        custom_config = {
            "expected_ports": [8080, 9090],
            "custom_key": "custom_value"
        }

        with open(self.config_path, 'w') as f:
            json.dump(custom_config, f)

        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.config_path]):
            config = load_config()

            # Custom values should override defaults
            self.assertEqual(config["expected_ports"], [8080, 9090])
            self.assertEqual(config["custom_key"], "custom_value")
            # Default values should still be present
            self.assertIn("whitelisted_processes", config)

    def test_load_config_merges_with_defaults(self):
        """Verify load_config merges user config with defaults."""
        custom_config = {"custom_key": "value"}

        with open(self.config_path, 'w') as f:
            json.dump(custom_config, f)

        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.config_path]):
            config = load_config()

            # Custom key should be present
            self.assertEqual(config["custom_key"], "value")
            # Default keys should still be present
            self.assertIn("expected_ports", config)
            self.assertEqual(config["expected_ports"], DEFAULT_CONFIG["expected_ports"])

    def test_load_config_with_source_returns_path(self):
        """Verify load_config_with_source returns tuple with path."""
        custom_config = {"test": "value"}

        with open(self.config_path, 'w') as f:
            json.dump(custom_config, f)

        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.config_path]):
            config, source = load_config_with_source()

            self.assertEqual(config["test"], "value")
            self.assertEqual(source, self.config_path)


class TestLoadConfigInvalidFile(unittest.TestCase):
    """Test load_config with invalid config files."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.config_path = Path(self.temp_dir) / "orin_config.json"

    def tearDown(self):
        """Clean up test fixtures."""
        if self.config_path.exists():
            self.config_path.unlink()
        Path(self.temp_dir).rmdir()

    def test_load_config_with_invalid_json(self):
        """Verify load_config falls back to defaults with invalid JSON."""
        with open(self.config_path, 'w') as f:
            f.write("{ invalid json }")

        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.config_path]):
            config = load_config()

            # Should fall back to defaults
            self.assertEqual(config, DEFAULT_CONFIG)

    def test_load_config_with_empty_file(self):
        """Verify load_config handles empty config file."""
        with open(self.config_path, 'w') as f:
            f.write("")

        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.config_path]):
            config = load_config()

            # Should fall back to defaults
            self.assertEqual(config, DEFAULT_CONFIG)


class TestLoadConfigPriority(unittest.TestCase):
    """Test config file loading priority."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.local_config = Path(self.temp_dir) / "orin_config.json"
        self.system_config = Path(self.temp_dir) / "system_config.json"

    def tearDown(self):
        """Clean up test fixtures."""
        for config in [self.local_config, self.system_config]:
            if config.exists():
                config.unlink()
        Path(self.temp_dir).rmdir()

    def test_local_config_takes_priority(self):
        """Verify local config takes priority over system config."""
        local_data = {"source": "local"}
        system_data = {"source": "system"}

        with open(self.local_config, 'w') as f:
            json.dump(local_data, f)
        with open(self.system_config, 'w') as f:
            json.dump(system_data, f)

        locations = [self.local_config, self.system_config]
        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', locations):
            config = load_config()

            # Local config should win
            self.assertEqual(config["source"], "local")


class TestLoadConfigEnvOverride(unittest.TestCase):
    """Test configuration loading override via ORIN_CONFIG_PATH environment variable."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.env_config_path = Path(self.temp_dir) / "env_config.json"
        self.local_config_path = Path(self.temp_dir) / "orin_config.json"
        
        # Back up environment
        self.old_env = os.environ.get("ORIN_CONFIG_PATH")

    def tearDown(self):
        # Restore environment
        if self.old_env is not None:
            os.environ["ORIN_CONFIG_PATH"] = self.old_env
        else:
            os.environ.pop("ORIN_CONFIG_PATH", None)

        for path in [self.env_config_path, self.local_config_path]:
            if path.exists():
                path.unlink()
        Path(self.temp_dir).rmdir()

    def test_env_path_loaded(self):
        """Verify load_config loads from the path in ORIN_CONFIG_PATH."""
        custom_data = {"key": "env_override"}
        with open(self.env_config_path, "w") as f:
            json.dump(custom_data, f)

        os.environ["ORIN_CONFIG_PATH"] = str(self.env_config_path)
        config, source = load_config_with_source()
        
        self.assertEqual(config["key"], "env_override")
        self.assertEqual(source, self.env_config_path)

    def test_env_path_priority_over_default_locations(self):
        """Verify ORIN_CONFIG_PATH takes precedence over default locations."""
        env_data = {"key": "env"}
        local_data = {"key": "local"}
        
        with open(self.env_config_path, "w") as f:
            json.dump(env_data, f)
        with open(self.local_config_path, "w") as f:
            json.dump(local_data, f)

        os.environ["ORIN_CONFIG_PATH"] = str(self.env_config_path)
        # Patch default config locations to simulate local config existing
        with patch('orin.core.config.DEFAULT_CONFIG_LOCATIONS', [self.local_config_path]):
            config, source = load_config_with_source()
            
            # Env config should take precedence
            self.assertEqual(config["key"], "env")
            self.assertEqual(source, self.env_config_path)


if __name__ == '__main__':
    unittest.main()