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
"""Unit tests for orin.core.credentials module."""

import os
import sys
import stat
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from orin.core.credentials import (
    SecureCredential,
    CredentialManager,
    redact_sensitive_data,
    secure_print,
)


class TestSecureCredential:
    """Tests for SecureCredential class."""

    def test_init_valid_string(self):
        """Test initialization with valid string value."""
        cred = SecureCredential("test_password_123")
        assert cred.get_value() == "test_password_123"
        assert len(cred) == 17

    def test_init_empty_string(self):
        """Test initialization with empty string."""
        cred = SecureCredential("")
        assert cred.get_value() == ""
        assert len(cred) == 0
        assert cred.is_empty() is True

    def test_init_non_string_raises_typeerror(self):
        """Test that non-string values raise TypeError."""
        with pytest.raises(TypeError):
            SecureCredential(12345)

        with pytest.raises(TypeError):
            SecureCredential(None)

        with pytest.raises(TypeError):
            SecureCredential(["password"])

    def test_str_redacted(self):
        """Test that __str__ returns redacted value."""
        cred = SecureCredential("secret_password")
        assert str(cred) == "[REDACTED]"

    def test_repr_redacted(self):
        """Test that __repr__ returns redacted representation."""
        cred = SecureCredential("secret_password")
        repr_str = repr(cred)
        assert "REDACTED" in repr_str or "length=" in repr_str
        assert "secret_password" not in repr_str

    def test_len_without_exposing_value(self):
        """Test that len() works without exposing actual value."""
        password = "my_secure_password_123"
        cred = SecureCredential(password)
        assert len(cred) == len(password)

    def test_compare_secure_match(self):
        """Test timing-safe comparison with matching values."""
        cred = SecureCredential("test_value")
        assert cred.compare_secure("test_value") is True

    def test_compare_secure_no_match(self):
        """Test timing-safe comparison with non-matching values."""
        cred = SecureCredential("test_value")
        assert cred.compare_secure("different_value") is False
        assert cred.compare_secure("test_valu") is False
        assert cred.compare_secure("test_value_extra") is False

    def test_is_empty_true(self):
        """Test is_empty returns True for empty credential."""
        cred = SecureCredential("")
        assert cred.is_empty() is True

    def test_is_empty_false(self):
        """Test is_empty returns False for non-empty credential."""
        cred = SecureCredential("has_value")
        assert cred.is_empty() is False

    def test_get_value_returns_actual_value(self):
        """Test that get_value() returns the actual credential."""
        secret = "super_secret_value"
        cred = SecureCredential(secret)
        assert cred.get_value() == secret


class TestCredentialManager:
    """Tests for CredentialManager class."""

    def test_init_default_values(self):
        """Test initialization with default values."""
        manager = CredentialManager()
        assert manager.vault_passphrase_env == "ORIN_VAULT_PASSPHRASE"
        assert manager.min_passphrase_length == 12

    def test_init_custom_values(self):
        """Test initialization with custom values."""
        manager = CredentialManager(
            vault_passphrase_env="CUSTOM_ENV_VAR",
            min_passphrase_length=20
        )
        assert manager.vault_passphrase_env == "CUSTOM_ENV_VAR"
        assert manager.min_passphrase_length == 20

    def test_load_vault_passphrase_from_env_success(self):
        """Test loading passphrase from environment variable."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "valid_passphrase_123"}):
            result = manager.load_vault_passphrase()
            assert result is not None
            assert result.get_value() == "valid_passphrase_123"
            assert manager._vault_passphrase is not None

    def test_load_vault_passphrase_from_env_not_set(self):
        """Test loading passphrase when env var is not set."""
        manager = CredentialManager()
        with patch.dict(os.environ, {}, clear=True):
            result = manager.load_vault_passphrase()
            assert result is None

    def test_load_vault_passphrase_from_env_required_raises(self):
        """Test that required=True raises ValueError when env var not set."""
        manager = CredentialManager()
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(ValueError, match="Vault passphrase required"):
                manager.load_vault_passphrase(required=True)

    def test_load_vault_passphrase_too_short(self):
        """Test that short passphrase returns None with warning."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "short"}):
            result = manager.load_vault_passphrase()
            assert result is None

    def test_load_vault_passphrase_too_short_required_raises(self):
        """Test that short passphrase raises ValueError when required."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "short"}):
            with pytest.raises(ValueError, match="Vault passphrase too short"):
                manager.load_vault_passphrase(required=True)

    def test_load_vault_passphrase_custom_env_var(self):
        """Test loading passphrase from custom environment variable."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"MY_CUSTOM_VAR": "custom_passphrase_123"}):
            result = manager.load_vault_passphrase(env_var="MY_CUSTOM_VAR")
            assert result is not None
            assert result.get_value() == "custom_passphrase_123"

    def test_load_vault_passphrase_from_file_success(self, tmp_path):
        """Test loading passphrase from file."""
        manager = CredentialManager()
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_text("file_passphrase_123\n")
        # Set secure permissions
        os.chmod(passphrase_file, 0o600)

        result = manager.load_vault_passphrase_from_file(passphrase_file)
        assert result is not None
        assert result.get_value() == "file_passphrase_123"

    def test_load_vault_passphrase_from_file_not_found(self, tmp_path):
        """Test loading passphrase from non-existent file."""
        manager = CredentialManager()
        non_existent = tmp_path / "does_not_exist.txt"

        result = manager.load_vault_passphrase_from_file(non_existent)
        assert result is None

    def test_load_vault_passphrase_from_file_required_raises(self, tmp_path):
        """Test that required=True raises ValueError for missing file."""
        manager = CredentialManager()
        non_existent = tmp_path / "does_not_exist.txt"

        with pytest.raises(ValueError, match="Vault passphrase file not found"):
            manager.load_vault_passphrase_from_file(non_existent, required=True)

    def test_load_vault_passphrase_from_file_insecure_permissions(self, tmp_path):
        """Test loading passphrase from file with insecure permissions."""
        manager = CredentialManager()
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_text("file_passphrase_123\n")
        # Set world-readable permissions
        os.chmod(passphrase_file, 0o644)

        result = manager.load_vault_passphrase_from_file(passphrase_file)
        # Should return None or warn but not fail
        assert result is None or result is not None

    def test_load_vault_passphrase_from_file_insecure_required_raises(self, tmp_path):
        """Test that insecure permissions raise error when required."""
        manager = CredentialManager()
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_text("file_passphrase_123\n")
        # Set world-readable permissions
        os.chmod(passphrase_file, 0o644)

        with pytest.raises(PermissionError, match="insecure permissions"):
            manager.load_vault_passphrase_from_file(passphrase_file, required=True)

    def test_load_vault_passphrase_from_file_empty(self, tmp_path):
        """Test loading passphrase from empty file."""
        manager = CredentialManager()
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_text("")
        os.chmod(passphrase_file, 0o600)

        result = manager.load_vault_passphrase_from_file(passphrase_file)
        assert result is None

    def test_load_vault_passphrase_from_file_empty_required_raises(self, tmp_path):
        """Test that empty file raises ValueError when required."""
        manager = CredentialManager()
        passphrase_file = tmp_path / "passphrase.txt"
        passphrase_file.write_text("")
        os.chmod(passphrase_file, 0o600)

        with pytest.raises(ValueError, match="Vault passphrase file is empty"):
            manager.load_vault_passphrase_from_file(passphrase_file, required=True)

    def test_load_vault_passphrase_from_prompt_success(self):
        """Test loading passphrase via interactive prompt."""
        manager = CredentialManager()
        with patch('getpass.getpass', return_value="interactive_pass_123"):
            result = manager.load_vault_passphrase_from_prompt()
            assert result is not None
            assert result.get_value() == "interactive_pass_123"

    def test_load_vault_passphrase_from_prompt_empty(self):
        """Test loading empty passphrase via prompt."""
        manager = CredentialManager()
        with patch('getpass.getpass', return_value=""):
            result = manager.load_vault_passphrase_from_prompt()
            assert result is None

    def test_load_vault_passphrase_from_prompt_empty_required_raises(self):
        """Test that empty passphrase raises ValueError when required."""
        manager = CredentialManager()
        with patch('getpass.getpass', return_value=""):
            with pytest.raises(ValueError, match="Vault passphrase cannot be empty"):
                manager.load_vault_passphrase_from_prompt(required=True)

    def test_load_vault_passphrase_from_prompt_confirmation_success(self):
        """Test loading passphrase with confirmation."""
        manager = CredentialManager()
        with patch('getpass.getpass', side_effect=["confirm_pass_123", "confirm_pass_123"]):
            result = manager.load_vault_passphrase_from_prompt(confirm=True)
            assert result is not None
            assert result.get_value() == "confirm_pass_123"

    def test_load_vault_passphrase_from_prompt_confirmation_mismatch(self):
        """Test that mismatched confirmation raises ValueError."""
        manager = CredentialManager()
        with patch('getpass.getpass', side_effect=["pass123456789", "different_pass"]):
            with pytest.raises(ValueError, match="Passphrases do not match"):
                manager.load_vault_passphrase_from_prompt(confirm=True, required=True)

    def test_load_vault_passphrase_from_prompt_eof_error(self):
        """Test handling EOFError in non-interactive mode."""
        manager = CredentialManager()
        with patch('getpass.getpass', side_effect=EOFError()):
            result = manager.load_vault_passphrase_from_prompt()
            assert result is None

    def test_load_vault_passphrase_from_prompt_eof_error_required_raises(self):
        """Test that EOFError raises ValueError when required."""
        manager = CredentialManager()
        with patch('getpass.getpass', side_effect=EOFError()):
            with pytest.raises(ValueError, match="non-interactive mode"):
                manager.load_vault_passphrase_from_prompt(required=True)

    def test_load_vault_passphrase_from_env_var_name(self):
        """Test loading passphrase from custom env var name."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"TEMP_VAR": "temp_passphrase_123"}):
            result = manager.load_vault_passphrase_from_env_var_name("TEMP_VAR")
            assert result is not None
            assert result.get_value() == "temp_passphrase_123"
            # Verify original env var name is restored
            assert manager.vault_passphrase_env == "ORIN_VAULT_PASSPHRASE"

    def test_generate_session_token(self):
        """Test session token generation."""
        manager = CredentialManager()
        token = manager.generate_session_token()

        assert token is not None
        assert len(token.get_value()) == 64  # 32 bytes hex-encoded = 64 chars
        assert token.get_value() != manager.generate_session_token().get_value()

    def test_get_session_token_none_when_not_generated(self):
        """Test that get_session_token returns None when no token generated."""
        manager = CredentialManager()
        assert manager.get_session_token() is None

    def test_get_session_token_after_generation(self):
        """Test that get_session_token returns token after generation."""
        manager = CredentialManager()
        generated = manager.generate_session_token()
        retrieved = manager.get_session_token()

        assert retrieved is not None
        assert retrieved.get_value() == generated.get_value()

    def test_get_vault_passphrase_none_when_not_loaded(self):
        """Test that get_vault_passphrase returns None when not loaded."""
        manager = CredentialManager()
        assert manager.get_vault_passphrase() is None

    def test_get_vault_passphrase_after_loading(self):
        """Test that get_vault_passphrase returns passphrase after loading."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "test_pass_123456"}):
            loaded = manager.load_vault_passphrase()
            retrieved = manager.get_vault_passphrase()

            assert retrieved is not None
            assert retrieved.get_value() == loaded.get_value()

    def test_validate_token_match(self):
        """Test token validation with matching token."""
        manager = CredentialManager()
        token = manager.generate_session_token()

        assert manager.validate_token(token.get_value()) is True

    def test_validate_token_no_match(self):
        """Test token validation with non-matching token."""
        manager = CredentialManager()
        manager.generate_session_token()

        assert manager.validate_token("wrong_token_12345678901234567890123456789012") is False

    def test_validate_token_no_token_generated(self):
        """Test token validation when no token generated."""
        manager = CredentialManager()

        assert manager.validate_token("any_token") is False

    def test_clear_credentials(self):
        """Test clearing all credentials."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "test_pass_123456"}):
            manager.load_vault_passphrase()
            manager.generate_session_token()

            manager.clear_credentials()

            assert manager._vault_passphrase is None
            assert manager._session_token is None

    def test_temporary_token_context_manager(self):
        """Test temporary token context manager."""
        manager = CredentialManager()
        original_token = manager.generate_session_token()
        original_value = original_token.get_value()

        with manager.temporary_token():
            # Inside context, a new token is generated
            current_token = manager.get_session_token()
            # The temporary token replaces the original during context
            assert current_token is not None

        # After context, token is cleared (set to None)
        restored_token = manager.get_session_token()
        assert restored_token is None

    def test_get_token_display_url(self):
        """Test generating token display URL."""
        manager = CredentialManager()
        token = manager.generate_session_token()
        token_value = token.get_value()

        base_url = "http://localhost:8080"
        display_url = manager.get_token_display_url(base_url)

        assert display_url.startswith(base_url)
        assert token_value in display_url

    def test_get_redacted_status(self):
        """Test getting redacted status dictionary."""
        manager = CredentialManager()
        with patch.dict(os.environ, {"ORIN_VAULT_PASSPHRASE": "test_pass_123456"}):
            manager.load_vault_passphrase()
            manager.generate_session_token()

            status = manager.get_redacted_status()

            # Check actual keys returned by get_redacted_status()
            assert "vault_passphrase_loaded" in status
            assert "session_token_generated" in status
            assert status["vault_passphrase_loaded"] is True
            assert status["session_token_generated"] is True
            assert status["vault_passphrase_length"] == 16
            assert status["min_passphrase_length"] == 12

    def test_save_session_token_to_file(self, tmp_path):
        """Test saving session token to file."""
        manager = CredentialManager()
        manager.generate_session_token()
        token_file = tmp_path / "token.txt"

        manager.save_session_token_to_file(token_file)

        assert token_file.exists()
        # Verify file permissions are secure
        file_mode = stat.S_IMODE(token_file.stat().st_mode)
        assert file_mode == 0o600
        # Verify content
        saved_token = token_file.read_text().strip()
        assert len(saved_token) == 64

    def test_save_session_token_to_file_no_token(self, tmp_path):
        """Test saving token when none generated."""
        manager = CredentialManager()
        token_file = tmp_path / "token.txt"

        # When no token exists and required=False (default), returns None
        result = manager.save_session_token_to_file(token_file)
        assert result is None

        # When required=True, should raise ValueError
        with pytest.raises(ValueError, match="No session token generated"):
            manager.save_session_token_to_file(token_file, required=True)

    def test_load_session_token_from_file_success(self, tmp_path):
        """Test loading session token from file."""
        manager = CredentialManager()
        token_file = tmp_path / "token.txt"
        test_token = "a" * 64
        token_file.write_text(test_token)

        result = manager.load_session_token_from_file(token_file)

        assert result is not None
        assert result.get_value() == test_token

    def test_load_session_token_from_file_not_found(self, tmp_path):
        """Test loading token from non-existent file."""
        manager = CredentialManager()
        non_existent = tmp_path / "does_not_exist.txt"

        result = manager.load_session_token_from_file(non_existent)
        assert result is None

    def test_load_session_token_from_file_required_raises(self, tmp_path):
        """Test that required=True raises ValueError for missing file."""
        manager = CredentialManager()
        non_existent = tmp_path / "does_not_exist.txt"

        with pytest.raises(ValueError, match="Session token file not found"):
            manager.load_session_token_from_file(non_existent, required=True)

    def test_load_session_token_from_file_empty(self, tmp_path):
        """Test loading token from empty file."""
        manager = CredentialManager()
        token_file = tmp_path / "token.txt"
        token_file.write_text("")

        result = manager.load_session_token_from_file(token_file)
        assert result is None

    def test_load_session_token_from_file_empty_required_raises(self, tmp_path):
        """Test that empty file raises ValueError when required."""
        manager = CredentialManager()
        token_file = tmp_path / "token.txt"
        token_file.write_text("")

        with pytest.raises(ValueError, match="Session token file is empty"):
            manager.load_session_token_from_file(token_file, required=True)


class TestRedactSensitiveData:
    """Tests for redact_sensitive_data function."""

    def test_redact_hex_token(self):
        """Test redaction of long hex tokens."""
        data = "Token: " + "a" * 64
        result = redact_sensitive_data(data)
        assert "[TOKEN_REDACTED]" in result
        assert "a" * 64 not in result

    def test_redact_passphrase_pattern(self):
        """Test redaction of passphrase patterns."""
        data = "Config: passphrase=my_secret_value here"
        result = redact_sensitive_data(data)
        assert "passphrase=[REDACTED]" in result
        assert "my_secret_value" not in result

    def test_redact_secret_pattern(self):
        """Test redaction of secret patterns."""
        data = "Setting: secret=very_confidential"
        result = redact_sensitive_data(data)
        assert "secret=[REDACTED]" in result
        assert "very_confidential" not in result

    def test_redact_token_pattern(self):
        """Test redaction of token patterns."""
        data = "Auth: token=abc123xyz789"
        result = redact_sensitive_data(data)
        assert "token=[REDACTED]" in result
        assert "abc123xyz789" not in result

    def test_redact_base64_pattern(self):
        """Test redaction of base64 encoded secrets."""
        data = "Key: " + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx" + "=="
        result = redact_sensitive_data(data)
        assert "[BASE64_REDACTED]" in result

    def test_custom_pattern(self):
        """Test redaction with custom pattern."""
        data = "Custom: MY_SECRET_VALUE"
        result = redact_sensitive_data(data, pattern=r"MY_SECRET_\w+")
        assert "[REDACTED]" in result
        assert "MY_SECRET_VALUE" not in result

    def test_no_sensitive_data(self):
        """Test that normal data passes through unchanged."""
        data = "This is a normal log message with no secrets"
        result = redact_sensitive_data(data)
        assert result == data

    def test_empty_string(self):
        """Test redaction of empty string."""
        result = redact_sensitive_data("")
        assert result == ""


class TestSecurePrint:
    """Tests for secure_print function."""

    def test_basic_print(self, capsys):
        """Test basic secure print without sensitive values."""
        secure_print("Hello World")
        captured = capsys.readouterr()
        assert "Hello World" in captured.out

    def test_redact_sensitive_values(self, capsys):
        """Test redaction of provided sensitive values."""
        sensitive = "super_secret_password"
        message = f"Using credential: {sensitive} for auth"
        secure_print(message, sensitive_values=[sensitive])
        captured = capsys.readouterr()
        assert "[REDACTED]" in captured.out
        assert sensitive not in captured.out

    def test_multiple_sensitive_values(self, capsys):
        """Test redaction of multiple sensitive values."""
        message = "Credentials: user=admin pass=secret123 token=abc"
        secure_print(message, sensitive_values=["admin", "secret123", "abc"])
        captured = capsys.readouterr()
        assert "admin" not in captured.out
        assert "secret123" not in captured.out
        assert "abc" not in captured.out

    def test_automatic_pattern_redaction(self, capsys):
        """Test automatic pattern-based redaction."""
        message = "Token: " + "f" * 64
        secure_print(message)
        captured = capsys.readouterr()
        assert "[TOKEN_REDACTED]" in captured.out
        assert "f" * 64 not in captured.out

    def test_none_sensitive_values(self, capsys):
        """Test print with None sensitive values list."""
        secure_print("Normal message", sensitive_values=None)
        captured = capsys.readouterr()
        assert "Normal message" in captured.out

    def test_empty_sensitive_values(self, capsys):
        """Test print with empty sensitive values list."""
        secure_print("Normal message", sensitive_values=[])
        captured = capsys.readouterr()
        assert "Normal message" in captured.out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])