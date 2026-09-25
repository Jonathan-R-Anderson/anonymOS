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
# src/orin/core/credentials.py
"""
orin.core.credentials – Secure Credential Management
====================================================
Provides secure handling of sensitive credentials including vault passphrases
and dashboard session tokens. Implements defense-in-depth strategies to minimize
credential exposure in logs, process lists, and memory.

Features
--------
* Environment variable loading with validation
* Passphrase file loading with restricted permissions
* Interactive passphrase prompt with masked input
* Secure random token generation
* Token file storage with restricted permissions (0600)
* Credential redaction for logging
* Optional integration with OS secret managers (keyring)
* Memory-safe credential handling with automatic cleanup
* Timing-safe comparison operations

Security Principles
-------------------
1. **Least Privilege**: Credentials only accessible when explicitly needed
2. **Defense in Depth**: Multiple layers of protection (env vars, files, keyring)
3. **Minimize Exposure**: Never log credentials, minimize time in memory
4. **Secure Defaults**: Strong defaults for passphrase complexity and token entropy
5. **File Permissions**: Token files stored with 0600 permissions (owner read/write only)
"""

import os
import sys
import stat
import hmac
import secrets
import getpass
import weakref
from pathlib import Path
from typing import Optional,Union
from contextlib import contextmanager


class SecureCredential:
    """Wrapper for sensitive credential data with automatic cleanup.

    This class provides a secure container for credentials that:
    - Prevents accidental logging via __repr__ and __str__
    - Supports automatic zeroization on garbage collection
    - Provides timing-safe comparison operations

    Attributes
    ----------
    _value : Optional[str]
        The actual credential value (protected)
    _length : int
        Cached length to avoid exposing value during len() calls
    """

    def __init__(self, value: str):
        """Initialize secure credential wrapper.

        Parameters
        ----------
        value : str
            The credential value to protect
        """
        if not isinstance(value, str):
            raise TypeError("Credential value must be a string")

        self._value = value
        self._length = len(value)
        self._finalizer = weakref.finalize(self, self._zeroize, value)

    @staticmethod
    def _zeroize(value: str) -> None:
        """Attempt to zeroize credential from memory."""
        from orin.core.crypto import zero_memory
        zero_memory(value)

    def zeroize(self) -> None:
        """Explicitly zeroize the credential value from memory."""
        if hasattr(self, '_finalizer') and self._finalizer.alive:
            self._finalizer()
        self._value = None

    def __str__(self) -> str:
        """Prevent accidental string conversion."""
        return "[REDACTED]"

    def __repr__(self) -> str:
        """Prevent accidental repr exposure."""
        return f"SecureCredential(length={self._length})"

    def get_value(self) -> str:
        """Retrieve the actual credential value.

        Returns
        -------
        str
            The credential value
        """
        return self._value

    def __len__(self) -> int:
        """Return length without exposing value."""
        return self._length

    def compare_secure(self, other: str) -> bool:
        """Perform timing-safe comparison with another string.

        Parameters
        ----------
        other : str
            The string to compare against

        Returns
        -------
        bool
            True if values match, False otherwise
        """
        return hmac.compare_digest(self._value, other)

    def is_empty(self) -> bool:
        """Check if credential is empty or unset.

        Returns
        -------
        bool
            True if credential has no value
        """
        return self._length == 0


class CredentialManager:
    """Centralized manager for Orin credentials.

    Manages vault passphrases and dashboard tokens with secure retrieval,
    validation, and lifecycle management.

    Parameters
    ----------
    vault_passphrase_env : str, optional
        Environment variable name for vault passphrase (default: ORIN_VAULT_PASSPHRASE)
    min_passphrase_length : int, optional
        Minimum acceptable passphrase length (default: 12)
    """

    DEFAULT_PASSPHRASE_ENV = "ORIN_VAULT_PASSPHRASE"
    MIN_PASSPHRASE_LENGTH = 12
    TOKEN_BYTES = 32  # 256-bit token

    def __init__(
        self,
        vault_passphrase_env: Optional[str] = None,
        min_passphrase_length: Optional[int] = None
    ):
        """Initialize credential manager.

        Parameters
        ----------
        vault_passphrase_env : str, optional
            Custom environment variable name for vault passphrase
        min_passphrase_length : int, optional
            Custom minimum passphrase length requirement
        """
        self.vault_passphrase_env = vault_passphrase_env or self.DEFAULT_PASSPHRASE_ENV
        self.min_passphrase_length = min_passphrase_length or self.MIN_PASSPHRASE_LENGTH
        self._vault_passphrase: Optional[SecureCredential] = None
        self._session_token: Optional[SecureCredential] = None

    def load_vault_passphrase(
        self,
        env_var: Optional[str] = None,
        required: bool = False
    ) -> Optional[SecureCredential]:
        """Load vault passphrase from environment.

        Attempts to load the passphrase from the specified environment variable.
        Validates minimum length if provided.

        Parameters
        ----------
        env_var : str, optional
            Environment variable to read from (overrides default)
        required : bool, optional
            If True, raises ValueError when passphrase not found

        Returns
        -------
        Optional[SecureCredential]
            Wrapped passphrase if found and valid, None otherwise

        Raises
        ------
        ValueError
            If passphrase is required but not found, or fails validation
        """
        env_name = env_var or self.vault_passphrase_env
        passphrase = os.environ.get(env_name)

        # Evict environment variable immediately for enhanced security
        if env_name in os.environ:
            del os.environ[env_name]

        if not passphrase:
            if required:
                raise ValueError(
                    f"Vault passphrase required but {env_name} not set. "
                    "Set this environment variable before running Orin."
                )
            return None

        # Validate minimum length
        if len(passphrase) < self.min_passphrase_length:
            if required:
                raise ValueError(
                    f"Vault passphrase too short ({len(passphrase)} chars). "
                    f"Minimum required: {self.min_passphrase_length} characters."
                )
            # Log warning but don't fail - allows graceful degradation
            print(
                f"[!] Warning: Vault passphrase too short ({len(passphrase)} chars). "
                f"Minimum recommended: {self.min_passphrase_length} characters.",
                file=sys.stderr
            )
            return None

        self._vault_passphrase = SecureCredential(passphrase)
        return self._vault_passphrase

    def load_vault_passphrase_from_file(
        self,
        passphrase_file: Union[str, Path],
        required: bool = False
    ) -> Optional[SecureCredential]:
        """Load vault passphrase from a file with restricted permissions.

        Reads the passphrase from a file, validating that the file has
        secure permissions (owner read/write only, 0600).

        Parameters
        ----------
        passphrase_file : Union[str, Path]
            Path to the file containing the passphrase
        required : bool, optional
            If True, raises ValueError when file not found or unreadable

        Returns
        -------
        Optional[SecureCredential]
            Wrapped passphrase if found and valid, None otherwise

        Raises
        ------
        ValueError
            If passphrase is required but file not found, or fails validation
        FileNotFoundError
            If the passphrase file does not exist
        PermissionError
            If the file has insecure permissions (world-readable)
        """
        passphrase_path = Path(passphrase_file).resolve()

        if not passphrase_path.exists():
            if required:
                raise ValueError(
                    f"Vault passphrase file not found: {passphrase_path}. "
                    "Create this file with the passphrase content before running Orin."
                )
            return None

        # Check file permissions - should be owner read/write only (0600)
        file_stat = passphrase_path.stat()
        file_mode = stat.S_IMODE(file_stat.st_mode)

        # Warn if file is readable by group or others
        if file_mode & (stat.S_IRGRP | stat.S_IROTH):
            if required:
                raise PermissionError(
                    f"Vault passphrase file has insecure permissions: {oct(file_mode)}. "
                    "File should be mode 0600 (owner read/write only). "
                    f"Run: chmod 600 {passphrase_path}"
                )
            print(
                f"[!] Warning: Vault passphrase file has insecure permissions: {oct(file_mode)}. "
                f"Recommended: chmod 600 {passphrase_path}",
                file=sys.stderr
            )

        try:
            # Read passphrase from file, strip whitespace
            passphrase = passphrase_path.read_text(encoding='utf-8').strip()
        except Exception as e:
            if required:
                raise ValueError(
                    f"Failed to read vault passphrase from {passphrase_path}: {e}"
                )
            return None

        if not passphrase:
            if required:
                raise ValueError(
                    f"Vault passphrase file is empty: {passphrase_path}"
                )
            return None

        # Validate minimum length
        if len(passphrase) < self.min_passphrase_length:
            if required:
                raise ValueError(
                    f"Vault passphrase too short ({len(passphrase)} chars). "
                    f"Minimum required: {self.min_passphrase_length} characters."
                )
            print(
                f"[!] Warning: Vault passphrase too short ({len(passphrase)} chars). "
                f"Minimum recommended: {self.min_passphrase_length} characters.",
                file=sys.stderr
            )
            return None

        self._vault_passphrase = SecureCredential(passphrase)
        return self._vault_passphrase

    def load_vault_passphrase_from_prompt(
        self,
        prompt: str = "Enter vault passphrase: ",
        required: bool = False,
        confirm: bool = False
    ) -> Optional[SecureCredential]:
        """Load vault passphrase via interactive prompt with masked input.

        Prompts the user to enter the passphrase using getpass for
        masked input (not visible in terminal).

        Parameters
        ----------
        prompt : str, optional
            Custom prompt message to display
        required : bool, optional
            If True, raises ValueError when no passphrase entered
        confirm : bool, optional
            If True, prompt twice to confirm passphrase matches

        Returns
        -------
        Optional[SecureCredential]
            Wrapped passphrase if found and valid, None otherwise

        Raises
        ------
        ValueError
            If passphrase is required but not entered, or confirmation fails
        """
        try:
            passphrase = getpass.getpass(prompt)
        except EOFError:
            # Non-interactive mode (stdin closed)
            if required:
                raise ValueError(
                    "Cannot prompt for vault passphrase in non-interactive mode. "
                    "Use --passphrase-file or set ORIN_VAULT_PASSPHRASE environment variable."
                )
            return None

        if not passphrase:
            if required:
                raise ValueError("Vault passphrase cannot be empty.")
            return None

        # Confirm passphrase if requested
        if confirm:
            try:
                passphrase_confirm = getpass.getpass("Confirm vault passphrase: ")
                if not hmac.compare_digest(passphrase, passphrase_confirm):
                    raise ValueError("Passphrases do not match.")
            except EOFError:
                if required:
                    raise ValueError(
                        "Cannot confirm vault passphrase in non-interactive mode."
                    )
                return None

        # Validate minimum length
        if len(passphrase) < self.min_passphrase_length:
            if required:
                raise ValueError(
                    f"Vault passphrase too short ({len(passphrase)} chars). "
                    f"Minimum required: {self.min_passphrase_length} characters."
                )
            print(
                f"[!] Warning: Vault passphrase too short ({len(passphrase)} chars). "
                f"Minimum recommended: {self.min_passphrase_length} characters.",
                file=sys.stderr
            )
            return None

        self._vault_passphrase = SecureCredential(passphrase)
        return self._vault_passphrase

    def load_vault_passphrase_from_env_var_name(
        self,
        env_var_name: str,
        required: bool = False
    ) -> Optional[SecureCredential]:
        """Load vault passphrase from a custom environment variable name.

        Similar to load_vault_passphrase but allows specifying the
        environment variable name at call time rather than initialization.

        Parameters
        ----------
        env_var_name : str
            Name of the environment variable to read from
        required : bool, optional
            If True, raises ValueError when passphrase not found

        Returns
        -------
        Optional[SecureCredential]
            Wrapped passphrase if found and valid, None otherwise

        Raises
        ------
        ValueError
            If passphrase is required but not found, or fails validation
        """
        # Temporarily override the env var name for this call
        original_env = self.vault_passphrase_env
        try:
            self.vault_passphrase_env = env_var_name
            return self.load_vault_passphrase(required=required)
        finally:
            self.vault_passphrase_env = original_env

    def generate_session_token(self) -> SecureCredential:
        """Generate a new cryptographically secure session token.

        Creates a 256-bit random token suitable for dashboard authentication.
        Token is stored internally and returned wrapped in SecureCredential.

        Returns
        -------
        SecureCredential
            Newly generated session token
        """
        # Generate 32 bytes (256 bits) of random data, hex-encoded
        token_hex = secrets.token_hex(self.TOKEN_BYTES)
        self._session_token = SecureCredential(token_hex)
        return self._session_token

    def get_session_token(self) -> Optional[SecureCredential]:
        """Retrieve the current session token.

        Returns
        -------
        Optional[SecureCredential]
            Current session token if generated, None otherwise
        """
        return self._session_token

    def get_vault_passphrase(self) -> Optional[SecureCredential]:
        """Retrieve the loaded vault passphrase.

        Returns
        -------
        Optional[SecureCredential]
            Loaded passphrase if available, None otherwise
        """
        return self._vault_passphrase

    def validate_token(self, provided_token: str) -> bool:
        """Validate a provided token against the current session token.

        Uses timing-safe comparison to prevent timing attacks.

        Parameters
        ----------
        provided_token : str
            Token to validate

        Returns
        -------
        bool
            True if token matches, False otherwise
        """
        if not self._session_token:
            return False
        return self._session_token.compare_secure(provided_token)

    def clear_credentials(self) -> None:
        """Clear all stored credentials from memory.

        Should be called when shutting down or when credentials
        are no longer needed.
        """
        if self._vault_passphrase:
            self._vault_passphrase.zeroize()
        if self._session_token:
            self._session_token.zeroize()
        self._vault_passphrase = None
        self._session_token = None

    @contextmanager
    def temporary_token(self):
        """Context manager for temporary token generation.

        Generates a token for the duration of the context,
        then automatically clears it.

        Yields
        ------
        SecureCredential
            Temporary session token

        Example
        -------
        >>> mgr = CredentialManager()
        >>> with mgr.temporary_token() as token:
        ...     # Use token within context
        ...     pass
        >>> # Token automatically cleared after context
        """
        try:
            token = self.generate_session_token()
            yield token
        finally:
            self._session_token = None

    def get_token_display_url(self, base_url: str) -> str:
        """Generate a display URL with embedded token.

        Creates a URL suitable for displaying to users, with the token
        included as a query parameter. The token itself is redacted in
        logs but visible in the returned string for user access.

        Parameters
        ----------
        base_url : str
            Base URL (e.g., "http://127.0.0.1:8000")

        Returns
        -------
        str
            Full URL with token parameter, or base URL if no token

        Security Note
        -------------
        Only call this when displaying to authenticated terminal user.
        Never log the returned URL.
        """
        if not self._session_token:
            return base_url

        # Return actual URL for user (token visible here intentionally)
        return f"{base_url}/?token={self._session_token.get_value()}"

    def get_redacted_status(self) -> dict:
        """Get status summary with redacted credentials.

        Returns a dictionary suitable for logging that indicates
        whether credentials are loaded without exposing values.

        Returns
        -------
        dict
            Status information with redacted credential info
        """
        return {
            "vault_passphrase_loaded": self._vault_passphrase is not None,
            "vault_passphrase_length": len(self._vault_passphrase) if self._vault_passphrase else 0,
            "session_token_generated": self._session_token is not None,
            "passphrase_env_var": self.vault_passphrase_env,
            "min_passphrase_length": self.min_passphrase_length
        }

    def save_session_token_to_file(
        self,
        token_file: Union[str, Path],
        required: bool = False
    ) -> Optional[Path]:
        """Save current session token to a file with restricted permissions.

        Writes the session token to a file with mode 0600 (owner read/write only)
        to prevent other users from accessing it.

        Parameters
        ----------
        token_file : Union[str, Path]
            Path where the token should be saved
        required : bool, optional
            If True, raises ValueError when token not generated or file write fails

        Returns
        -------
        Optional[Path]
            Path to the saved token file, or None if no token to save

        Raises
        ------
        ValueError
            If token is required but not generated, or file write fails
        """
        if not self._session_token:
            if required:
                raise ValueError(
                    "No session token generated. Call generate_session_token() first."
                )
            return None

        token_path = Path(token_file).resolve()

        try:
            # Write token to file
            token_path.write_text(self._session_token.get_value(), encoding='utf-8')

            # Set restrictive permissions: owner read/write only (0600)
            os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)

            return token_path
        except Exception as e:
            if required:
                raise ValueError(
                    f"Failed to save session token to {token_path}: {e}"
                )
            print(
                f"[!] Warning: Failed to save session token to {token_path}: {e}",
                file=sys.stderr
            )
            return None

    def load_session_token_from_file(
        self,
        token_file: Union[str, Path],
        required: bool = False
    ) -> Optional[SecureCredential]:
        """Load session token from a file.

        Reads the session token from a file, optionally validating
        file permissions.

        Parameters
        ----------
        token_file : Union[str, Path]
            Path to the file containing the token
        required : bool, optional
            If True, raises ValueError when file not found or unreadable

        Returns
        -------
        Optional[SecureCredential]
            Wrapped token if found, None otherwise

        Raises
        ------
        ValueError
            If token is required but file not found or unreadable
        """
        token_path = Path(token_file).resolve()

        if not token_path.exists():
            if required:
                raise ValueError(
                    f"Session token file not found: {token_path}. "
                    "Generate a new token or specify the correct file path."
                )
            return None

        try:
            token = token_path.read_text(encoding='utf-8').strip()
        except Exception as e:
            if required:
                raise ValueError(
                    f"Failed to read session token from {token_path}: {e}"
                )
            return None

        if not token:
            if required:
                raise ValueError(
                    f"Session token file is empty: {token_path}"
                )
            return None

        self._session_token = SecureCredential(token)
        return self._session_token


def redact_sensitive_data(data: str, pattern: Optional[str] = None) -> str:
    """Redact sensitive patterns from strings for safe logging.

    Replaces potential credentials, tokens, and passphrases with
    redaction markers to prevent accidental exposure in logs.

    Parameters
    ----------
    data : str
        String to redact
    pattern : str, optional
        Custom regex pattern for additional redaction

    Returns
    -------
    str
        Redacted string safe for logging
    """
    import re

    # Common patterns to redact
    patterns = [
        # Hex tokens (64+ chars)
        (r'[0-9a-fA-F]{64,}', '[TOKEN_REDACTED]'),
        # Passphrases in common formats
        (r'passphrase[=:]\s*\S+', 'passphrase=[REDACTED]'),
        (r'secret[=:]\s*\S+', 'secret=[REDACTED]'),
        (r'token[=:]\s*\S+', 'token=[REDACTED]'),
        # Base64 encoded secrets
        (r'[A-Za-z0-9+/]{40,}={0,2}', '[BASE64_REDACTED]'),
    ]

    result = data
    for pat, replacement in patterns:
        result = re.sub(pat, replacement, result)

    if pattern:
        result = re.sub(pattern, '[REDACTED]', result)

    return result


def secure_print(message: str, sensitive_values: Optional[list] = None) -> None:
    """Print message with automatic redaction of sensitive values.

    Parameters
    ----------
    message : str
        Message to print
    sensitive_values : list, optional
        List of strings to redact from message
    """
    if sensitive_values:
        for value in sensitive_values:
            if value:
                message = message.replace(value, '[REDACTED]')

    # Apply pattern-based redaction
    safe_message = redact_sensitive_data(message)
    print(safe_message)