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
# src/orin/core/database.py
"""
orin.core.database – Relational Local Forensic Vault
===================================================
Manages the lifecycle of the Orin offline SQLite storage layer, handles table
schema deployments, maps data-streaming insertions, and enforces row factories.

Security Features
-----------------
- AES-256-GCM encrypted database files at rest
- Key derivation via PBKDF2-HMAC-SHA256
- Tamper detection via GCM authentication tag
- Input validation for all critical parameters
"""

import sqlite3
import json
import platform
import threading
import queue
import logging
from pathlib import Path
from datetime import datetime, timezone
from contextlib import contextmanager
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import secrets
from orin.core.validators import (
    validate_snapshot_id,
    validate_host,
    SQLInjectionValidator
)

logger = logging.getLogger(__name__)


def derive_key(passphrase: str, salt: bytes, iterations: int = 600_000) -> bytes:
    """Derive a 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.

    Parameters
    ----------
    passphrase : str
        User-provided passphrase for encryption.
    salt : bytes
        Random salt (16 bytes recommended).
    iterations : int
        PBKDF2 iteration count (default: 600,000).

    Returns
    -------
    bytes
        32-byte AES-256 key.
    """
    from orin.core.crypto import zero_memory
    passphrase_bytes = bytearray(passphrase.encode('utf-8'))
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        return kdf.derive(bytes(passphrase_bytes))
    finally:
        zero_memory(passphrase_bytes)


class EncryptedStorage:
    """Handles AES-256-GCM encryption/decryption of database files.

    Uses AES-256 in GCM mode for authenticated encryption, providing both
    confidentiality and integrity protection.
    """

    SALT_SIZE = 16
    NONCE_SIZE = 12
    TAG_SIZE = 16

    def __init__(self, passphrase: str):
        """Initialize encrypted storage with a passphrase.

        Parameters
        ----------
        passphrase : str
            Master passphrase for encryption/decryption.
        """
        if len(passphrase) < 12:
            raise ValueError("Passphrase must be at least 12 characters")
        self.passphrase = passphrase
        self._cached_key = None
        self._cached_salt = None

    def _get_or_create_key(self, db_path: Path) -> tuple[bytes, bytes, int]:
        """Get existing key or create new one for a database file.

        Parameters
        ----------
        db_path : Path
            Path to the encrypted database file.

        Returns
        -------
        tuple[bytes, bytes, int]
            Tuple of (derived_key, salt, iterations).
        """
        meta_path = db_path.with_suffix(db_path.suffix + '.meta')

        if meta_path.exists():
            # Load existing salt and iterations
            with open(meta_path, 'rb') as f:
                meta_data = f.read()
            if len(meta_data) == self.SALT_SIZE:
                salt = meta_data
                iterations = 100_000 # Legacy fallback
            elif len(meta_data) >= 20:
                salt = meta_data[:self.SALT_SIZE]
                iterations = int.from_bytes(meta_data[self.SALT_SIZE:self.SALT_SIZE+4], 'big')
            else:
                salt = meta_data
                iterations = 100_000

            key = derive_key(self.passphrase, salt, iterations)
            return key, salt, iterations
        else:
            # Generate new salt and derive key
            import os
            salt = secrets.token_bytes(self.SALT_SIZE)
            iterations = 600_000
            if "ORIN_TEST_FAST" in os.environ:
                iterations = 1000
            key = derive_key(self.passphrase, salt, iterations)

            # Save salt and iterations to metadata file
            meta_path.parent.mkdir(parents=True, exist_ok=True)
            with open(meta_path, 'wb') as f:
                f.write(salt + iterations.to_bytes(4, 'big'))

            return key, salt, iterations

    def encrypt_file(self, plaintext_path: Path, ciphertext_path: Path) -> None:
        """Encrypt a database file in-place.

        Parameters
        ----------
        plaintext_path : Path
            Path to the unencrypted database.
        ciphertext_path : Path
            Path where encrypted database will be written.

        Raises
        ------
        FileNotFoundError
            If the plaintext file does not exist.
        PermissionError
            If encryption fails due to access rights or cryptographic errors.
        ValueError
            If the plaintext file is empty or corrupted.
        IOError
            If file read/write operations fail.
        """
        # Validate input file exists
        if not plaintext_path.exists():
            raise FileNotFoundError(f"Plaintext file not found: {plaintext_path}")

        # Validate input file is readable and non-empty
        try:
            plaintext_size = plaintext_path.stat().st_size
            if plaintext_size == 0:
                raise ValueError(f"Plaintext file is empty: {plaintext_path}")
        except OSError as e:
            raise PermissionError(
                f"Cannot access plaintext file {plaintext_path}: {e}"
            )

        key, salt, iterations = self._get_or_create_key(ciphertext_path)
        try:
            aesgcm = AESGCM(key)
            try:
                # Read plaintext with error handling
                try:
                    with open(plaintext_path, 'rb') as f:
                        plaintext = f.read()
                except IOError as e:
                    raise IOError(f"Failed to read plaintext file {plaintext_path}: {e}")

                # Validate plaintext was read successfully
                if len(plaintext) != plaintext_size:
                    raise ValueError(
                        f"Plaintext file size mismatch during read: "
                        f"expected {plaintext_size}, got {len(plaintext)}"
                    )

                # Generate nonce and encrypt
                nonce = secrets.token_bytes(self.NONCE_SIZE)
                try:
                    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
                except Exception as e:
                    raise PermissionError(
                        f"Encryption failed for {plaintext_path}: {e}"
                    )

                # Write encrypted file with atomic operation
                try:
                    # Write to temp file first for atomicity
                    temp_ciphertext_path = ciphertext_path.with_suffix(
                        ciphertext_path.suffix + '.tmp'
                    )
                    with open(temp_ciphertext_path, 'wb') as f:
                        f.write(salt + nonce + ciphertext)

                    # Atomic rename
                    temp_ciphertext_path.rename(ciphertext_path)
                except IOError as e:
                    # Clean up temp file if it exists
                    if temp_ciphertext_path.exists():
                        temp_ciphertext_path.unlink()
                    raise IOError(f"Failed to write encrypted file {ciphertext_path}: {e}")

                # Remove plaintext only after successful encryption
                try:
                    plaintext_path.unlink()
                    logger.info(f"Successfully encrypted {plaintext_path} -> {ciphertext_path}")
                except OSError as e:
                    # Log warning but don't fail - plaintext should be securely deleted
                    logger.warning(
                        f"Failed to remove plaintext file {plaintext_path} after encryption: {e}. "
                        f"Manual deletion recommended for security."
                    )

            except Exception as e:
                # Ensure plaintext is not left exposed on failure
                logger.error(f"Encryption failed for {plaintext_path}: {e}")
                # Re-raise with context
                if not isinstance(e, (FileNotFoundError, PermissionError, ValueError, IOError)):
                    raise IOError(f"Unexpected encryption error for {plaintext_path}: {e}")
                raise
        finally:
            from orin.core.crypto import zero_memory
            zero_memory(key)

    def decrypt_file(self, ciphertext_path: Path, plaintext_path: Path) -> None:
        """Decrypt a database file.

        Parameters
        ----------
        ciphertext_path : Path
            Path to the encrypted database.
        plaintext_path : Path
            Path where decrypted database will be written.

        Raises
        ------
        FileNotFoundError
            If the ciphertext or metadata file does not exist.
        PermissionError
            If decryption fails due to wrong passphrase or tampering.
        ValueError
            If salt mismatch or corrupted data detected.
        IOError
            If file read/write operations fail.
        """
        # Validate ciphertext file exists
        if not ciphertext_path.exists():
            raise FileNotFoundError(f"Ciphertext file not found: {ciphertext_path}")

        # Read salt from metadata file
        meta_path = ciphertext_path.with_suffix(ciphertext_path.suffix + '.meta')
        if not meta_path.exists():
            raise FileNotFoundError(f"Metadata file not found: {meta_path}")

        try:
            with open(meta_path, 'rb') as f:
                meta_data = f.read()

            if len(meta_data) == self.SALT_SIZE:
                salt = meta_data
                iterations = 100_000
            elif len(meta_data) >= 20:
                salt = meta_data[:self.SALT_SIZE]
                iterations = int.from_bytes(meta_data[self.SALT_SIZE:self.SALT_SIZE+4], 'big')
            else:
                salt = meta_data
                iterations = 100_000

            if len(salt) != self.SALT_SIZE:
                raise ValueError(
                    f"Invalid salt size in metadata: expected {self.SALT_SIZE}, "
                    f"got {len(salt)}"
                )
        except IOError as e:
            raise IOError(f"Failed to read metadata file {meta_path}: {e}")

        key = derive_key(self.passphrase, salt, iterations)
        try:
            aesgcm = AESGCM(key)
            try:
                # Read encrypted file: salt (16) + nonce (12) + ciphertext
                try:
                    with open(ciphertext_path, 'rb') as f:
                        stored_salt = f.read(self.SALT_SIZE)
                        nonce = f.read(self.NONCE_SIZE)
                        ciphertext = f.read()
                except IOError as e:
                    raise IOError(f"Failed to read ciphertext file {ciphertext_path}: {e}")

                # Validate salt size
                if len(stored_salt) != self.SALT_SIZE:
                    raise ValueError(
                        f"Invalid salt size in ciphertext: expected {self.SALT_SIZE}, "
                        f"got {len(stored_salt)}"
                    )

                if len(nonce) != self.NONCE_SIZE:
                    raise ValueError(
                        f"Invalid nonce size: expected {self.NONCE_SIZE}, "
                        f"got {len(nonce)}"
                    )

                if len(ciphertext) == 0:
                    raise ValueError("Ciphertext is empty")

                if stored_salt != salt:
                    raise ValueError("Salt mismatch - possible tampering")

                # Decrypt with proper error handling
                try:
                    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
                except Exception as e:
                    raise PermissionError(
                        f"Decryption failed - possible tampering or wrong passphrase: {e}"
                    )

                # Write plaintext atomically
                try:
                    plaintext_path.parent.mkdir(parents=True, exist_ok=True)
                    temp_plaintext_path = plaintext_path.with_suffix(
                        plaintext_path.suffix + '.tmp'
                    )
                    with open(temp_plaintext_path, 'wb') as f:
                        f.write(plaintext)

                    # Atomic rename
                    temp_plaintext_path.rename(plaintext_path)
                    logger.info(f"Successfully decrypted {ciphertext_path} -> {plaintext_path}")
                except IOError as e:
                    # Clean up temp file if it exists
                    if temp_plaintext_path.exists():
                        temp_plaintext_path.unlink()
                    raise IOError(f"Failed to write decrypted file {plaintext_path}: {e}")

            except Exception as e:
                logger.error(f"Decryption failed for {ciphertext_path}: {e}")
                # Re-raise with context
                if not isinstance(e, (FileNotFoundError, PermissionError, ValueError, IOError)):
                    raise IOError(f"Unexpected decryption error for {ciphertext_path}: {e}")
                raise
        finally:
            from orin.core.crypto import zero_memory
            zero_memory(key)

    def cleanup(self, db_path: Path) -> None:
        """Remove encrypted database and metadata files.

        Parameters
        ----------
        db_path : Path
            Path to the encrypted database file.
        """
        meta_path = db_path.with_suffix(db_path.suffix + '.meta')
        if db_path.exists():
            db_path.unlink()
        if meta_path.exists():
            meta_path.unlink()


class ConnectionPool:
    """Thread-safe connection pool for SQLite with performance optimizations.

    Implements a bounded pool of reusable database connections with automatic
    health checking and WAL mode enforcement.
    """

    def __init__(self, db_path: Path, max_connections: int = 10,
                 timeout: float = 30.0, encryption_passphrase: str = None):
        """Initialize the connection pool.

        Parameters
        ----------
        db_path : Path
            Path to the SQLite database file.
        max_connections : int
            Maximum number of connections in the pool (default: 10).
        timeout : float
            Timeout in seconds for acquiring a connection (default: 30.0).
        encryption_passphrase : str, optional
            Passphrase for encrypted databases.
        """
        self.db_path = Path(db_path)
        self.max_connections = max_connections
        self.timeout = timeout
        self.encryption_passphrase = encryption_passphrase
        self._pool: queue.Queue = queue.Queue(maxsize=max_connections)
        self._lock = threading.Lock()
        self._created = 0
        self._closed = False

        # Auto-fix permissions on init before warming up connections
        self._ensure_db_writable()

        # Pre-create some connections for immediate use
        self._warmup_connections(min(3, max_connections))

    def _ensure_db_writable(self) -> None:
        """Auto-fix database file permissions if owned by current user but not writable."""
        import os
        import stat

        if not self.db_path.exists():
            return

        try:
            st = self.db_path.stat()
            uid = os.getuid()

            # If file is owned by current user, ensure it's writable
            if st.st_uid == uid:
                current_mode = st.st_mode
                if not (current_mode & stat.S_IWUSR):
                    self.db_path.chmod(current_mode | stat.S_IWUSR)
                    logger.info(f"Fixed write permissions on {self.db_path}")
        except Exception as e:
            logger.debug(f"Could not check/fix database permissions: {e}")

    def _warmup_connections(self, count: int) -> None:
        """Pre-warm the pool with initial connections."""
        for _ in range(count):
            try:
                conn = self._create_connection()
                self._pool.put_nowait(conn)
            except Exception as e:
                logger.warning(f"Failed to warm up connection: {e}")

    def _create_connection(self) -> sqlite3.Connection:
        """Create a new optimized SQLite connection."""
        conn = sqlite3.connect(str(self.db_path), timeout=self.timeout,
                               check_same_thread=False)

        # Performance optimizations
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.execute("PRAGMA journal_mode=WAL;")
        mode = cursor.fetchone()[0]
        if mode.lower() != "wal":
            logger.warning(f"Failed to enable WAL mode. Current journal mode is: {mode}")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-64000;")  # 64MB cache
        conn.execute("PRAGMA temp_store=MEMORY;")
        conn.execute("PRAGMA mmap_size=268435456;")  # 256MB memory-mapped I/O
        conn.execute("PRAGMA busy_timeout=30000;")  # 30 second busy timeout

        # Row factory for named access
        conn.row_factory = sqlite3.Row

        return conn

    def _is_connection_valid(self, conn: sqlite3.Connection) -> bool:
        """Check if a connection is still valid."""
        try:
            conn.execute("SELECT 1;")
            return True
        except sqlite3.Error:
            return False

    def acquire(self, timeout: float = None) -> sqlite3.Connection:
        """Acquire a connection from the pool.

        Parameters
        ----------
        timeout : float, optional
            Override default timeout for this acquisition.

        Returns
        -------
        sqlite3.Connection
            A valid database connection.

        Raises
        ------
        TimeoutError
            If no connection can be acquired within the timeout period.
        RuntimeError
            If the pool has been closed.
        """
        if self._closed:
            raise RuntimeError("Connection pool has been closed")

        timeout = timeout if timeout is not None else self.timeout
        deadline = datetime.now().timestamp() + timeout

        while True:
            conn = None
            try:
                # Try to get an existing connection with proper timeout handling
                remaining_time = max(0, deadline - datetime.now().timestamp())
                if remaining_time <= 0:
                    raise TimeoutError(
                        f"Could not acquire database connection within {timeout}s"
                    )

                queue_timeout = min(remaining_time, 0.1)
                conn = self._pool.get(timeout=queue_timeout)

                if self._is_connection_valid(conn):
                    return conn
                else:
                    # Connection is stale, close it and create a new one
                    try:
                        conn.close()
                    except Exception as e:
                        logger.warning(f"Error closing stale connection: {e}")
                    conn = None  # Mark as closed so we don't double-close

                    # Atomically check and increment creation counter
                    with self._lock:
                        if self._created < self.max_connections:
                            self._created += 1
                            should_create = True
                        else:
                            should_create = False

                    if should_create:
                        try:
                            new_conn = self._create_connection()
                            return new_conn
                        except Exception as e:
                            # Creation failed, decrement counter
                            with self._lock:
                                self._created = max(0, self._created - 1)
                            logger.error(f"Failed to create new connection: {e}")
                            raise
                    else:
                        # Pool is full, mark task done and retry
                        try:
                            self._pool.task_done()
                        except ValueError:
                            # task_done called too many times, ignore
                            pass
                        continue

            except queue.Empty:
                # No connection available, try to create one atomically
                with self._lock:
                    if self._created < self.max_connections:
                        self._created += 1
                        should_create = True
                    else:
                        should_create = False

                if should_create:
                    try:
                        conn = self._create_connection()
                        return conn
                    except Exception as e:
                        # Creation failed, decrement counter
                        with self._lock:
                            self._created = max(0, self._created - 1)
                        logger.error(f"Failed to create connection: {e}")
                        raise

                # Pool is at capacity, wait and retry
                if datetime.now().timestamp() > deadline:
                    raise TimeoutError(
                        f"Could not acquire database connection within {timeout}s"
                    )
            except Exception as e:
                # Ensure we don't leak connections on unexpected errors
                if conn is not None:
                    try:
                        conn.close()
                    except Exception as close_error:
                        logger.warning(f"Error closing connection during exception: {close_error}")
                    conn = None
                logger.error(f"Unexpected error acquiring connection: {e}")
                raise

    def release(self, conn: sqlite3.Connection) -> None:
        """Return a connection to the pool.

        Parameters
        ----------
        conn : sqlite3.Connection
            The connection to return.

        Raises
        ------
        ValueError
            If the connection does not belong to this pool.
        """
        if conn is None:
            return

        # Check if pool is closed or connection is invalid
        should_close = False
        with self._lock:
            if self._closed:
                should_close = True
            elif not self._is_connection_valid(conn):
                should_close = True

        if should_close:
            try:
                conn.close()
            except Exception as e:
                logger.warning(f"Error closing connection during release: {e}")
            with self._lock:
                self._created = max(0, self._created - 1)
        else:
            try:
                self._pool.put_nowait(conn)
            except queue.Full:
                # Pool is full, close the connection atomically
                try:
                    conn.close()
                except Exception as e:
                    logger.warning(f"Error closing connection when pool full: {e}")
                with self._lock:
                    self._created = max(0, self._created - 1)

    @contextmanager
    def get_connection(self, timeout: float = None):
        """Context manager for acquiring and releasing connections.

        Parameters
        ----------
        timeout : float, optional
            Override default timeout for this acquisition.

        Yields
        ------
        sqlite3.Connection
            A valid database connection.
        """
        conn = self.acquire(timeout)
        try:
            yield conn
        finally:
            self.release(conn)

    def close(self) -> None:
        """Close all connections in the pool.

        This method is thread-safe and can be called multiple times safely.
        All pending acquires will raise RuntimeError after this is called.
        """
        # Atomically set closed flag to prevent new acquisitions
        with self._lock:
            if self._closed:
                return  # Already closed
            self._closed = True

        # Close all pooled connections with proper exception handling
        while True:
            try:
                conn = self._pool.get_nowait()
                try:
                    conn.close()
                except Exception as e:
                    logger.warning(f"Error closing connection during pool shutdown: {e}")
                finally:
                    try:
                        self._pool.task_done()
                    except ValueError:
                        # task_done called too many times, ignore
                        pass
            except queue.Empty:
                break

        # Reset counter atomically
        with self._lock:
            self._created = 0

        logger.info("Connection pool closed successfully")

    def stats(self) -> dict:
        """Get pool statistics.

        Returns
        -------
        dict
            Statistics including pool size, created connections, etc.
        """
        return {
            'max_connections': self.max_connections,
            'current_size': self._pool.qsize(),
            'created_connections': self._created,
            'closed': self._closed
        }


class OrinStorage:
    """Encapsulates connections and schema workflows for the local SQLite vault.

    Supports both plain and AES-256-GCM encrypted database files.
    Features connection pooling, WAL mode, and batch insert optimizations.
    """

    def __init__(self, db_path: Path, encryption_passphrase: str = None,
                 pool_size: int = 10, pool_timeout: float = 30.0):
        """Initialize storage engine bounds.

        Parameters
        ----------
        db_path : Path
            Filesystem location where the SQLite database will be written.
        encryption_passphrase : str, optional
            If provided, database will be encrypted at rest using AES-256-GCM.
        pool_size : int
            Maximum number of connections in the pool (default: 10).
        pool_timeout : float
            Timeout in seconds for acquiring a connection (default: 30.0).
        """
        self.db_path = Path(db_path)
        self.encryption_passphrase = encryption_passphrase
        self.pool_size = pool_size
        self.pool_timeout = pool_timeout
        self.encrypted_storage = None
        self._temp_db_path = None
        self._connection_pool: Optional[ConnectionPool] = None

        if encryption_passphrase:
            self.encrypted_storage = EncryptedStorage(encryption_passphrase)
            self._encrypted_db_path = self.db_path.with_suffix(
                self.db_path.suffix + '.enc'
            )
            self._temp_db_path = self.db_path.with_suffix(
                self.db_path.suffix + '.tmp'
            )

    def __del__(self) -> None:
        """Ensure connection pool is closed on garbage collection."""
        try:
            self.close_pool()
        except Exception:
            pass

    def _ensure_pool_initialized(self) -> None:
        """Ensure the connection pool is initialized."""
        if self._connection_pool is None:
            # For encrypted databases, we need to handle decryption differently
            # Pool works best with unencrypted DBs, so we decrypt once on init
            if self.encrypted_storage:
                if self._encrypted_db_path.exists():
                    self.encrypted_storage.decrypt_file(
                        self._encrypted_db_path,
                        self.db_path
                    )
                elif self.db_path.exists():
                    # Encrypt it first, then decrypt to have consistent state
                    self.encrypted_storage.encrypt_file(
                        self.db_path,
                        self._encrypted_db_path
                    )
                    self.encrypted_storage.decrypt_file(
                        self._encrypted_db_path,
                        self.db_path
                    )

            self._connection_pool = ConnectionPool(
                self.db_path,
                max_connections=self.pool_size,
                timeout=self.pool_timeout,
                encryption_passphrase=None  # Already decrypted
            )

    def initialize_pool(self) -> None:
        """Initialize the connection pool with performance optimizations.

        This should be called once during application startup to pre-warm
        the connection pool and apply SQLite performance settings.
        """
        self._ensure_pool_initialized()
        logger.info(f"Database connection pool initialized with {self.pool_size} connections")

    def close_pool(self) -> None:
        """Close the connection pool and re-encrypt if needed."""
        if self._connection_pool:
            self._connection_pool.close()
            self._connection_pool = None

            # Re-encrypt the database if encryption is enabled
            if self.encrypted_storage and self.db_path.exists():
                self.encrypted_storage.encrypt_file(
                    self.db_path,
                    self._encrypted_db_path
                )
                if self._temp_db_path and self._temp_db_path.exists():
                    self._temp_db_path.unlink()

                logger.info("Database re-encrypted and pool closed")

    def cleanup_db(self) -> None:
        """Close connection pool and remove all database files including WAL/SHM."""
        self.close_pool()
        for suffix in ["", "-wal", "-shm"]:
            p = self.db_path.with_name(self.db_path.name + suffix)
            if p.exists():
                try:
                    p.unlink()
                except Exception as e:
                    logger.warning(f"Failed to remove SQLite database component {p}: {e}")

    @contextmanager
    def get_connection(self, use_pool: bool = True):
        """Yield an open transaction-ready database connection handle.

        Foreign-key enforcement is enabled for every connection. Rows are
        returned as sqlite3.Row objects so columns can be accessed by name.

        If encryption is enabled, the database is temporarily decrypted,
        used, then re-encrypted on close.

        Parameters
        ----------
        use_pool : bool
            If True, use the connection pool (default). If False, create
            a new connection directly (for initialization tasks).

        Yields
        ------
        sqlite3.Connection
            A valid database connection with WAL mode enabled.
        """
        # Use connection pool if available and requested
        if use_pool and self._connection_pool is not None:
            with self._connection_pool.get_connection() as conn:
                yield conn
            return

        # Legacy path for initialization or when pool is disabled
        if self.encrypted_storage and self._encrypted_db_path.exists():
            # Decrypt to temp location
            self.encrypted_storage.decrypt_file(
                self._encrypted_db_path,
                self._temp_db_path
            )
            db_to_use = self._temp_db_path
        elif self.encrypted_storage and self.db_path.exists():
            # Plain DB exists but encryption is enabled - encrypt it first
            self.encrypted_storage.encrypt_file(self.db_path, self._encrypted_db_path)
            self.encrypted_storage.decrypt_file(
                self._encrypted_db_path,
                self._temp_db_path
            )
            db_to_use = self._temp_db_path
        else:
            db_to_use = self.db_path

        conn = sqlite3.connect(str(db_to_use), timeout=self.pool_timeout)
        conn.execute("PRAGMA foreign_keys = ON;")
        cursor = conn.execute("PRAGMA journal_mode=WAL;")
        mode = cursor.fetchone()[0]
        if mode.lower() != "wal":
            logger.warning(f"Failed to enable WAL mode (legacy). Current journal mode is: {mode}")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA cache_size=-64000;")  # 64MB cache
        conn.execute(f"PRAGMA busy_timeout={int(self.pool_timeout * 1000)};")
        conn.row_factory = sqlite3.Row

        try:
            yield conn
        finally:
            conn.close()

            # Re-encrypt if needed
            if self.encrypted_storage and self._temp_db_path.exists():
                self.encrypted_storage.encrypt_file(
                    self._temp_db_path,
                    self._encrypted_db_path
                )
                if self._temp_db_path.exists():
                    self._temp_db_path.unlink()

    def initialize_db(self):
        """Deploy table layouts and operational indices."""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # 1. Core Tracking Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS system_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    hostname TEXT NOT NULL,
                    os_platform TEXT NOT NULL
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    raw_details TEXT,
                    notes TEXT DEFAULT '',
                    suppressed INTEGER DEFAULT 0,
                    reviewed_at TEXT,
                    resolved INTEGER DEFAULT 0,
                    attck_technique TEXT,
                    attck_tactic TEXT,
                    attck_url TEXT,
                    hostname TEXT
                );
            """)

            # 2. Approved System Baseline Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_kernel_modules (
                    hostname TEXT NOT NULL,
                    module_name TEXT NOT NULL,
                    memory_size INTEGER NOT NULL,
                    PRIMARY KEY (hostname, module_name)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_users (
                    hostname TEXT NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    home_dir TEXT,
                    login_shell TEXT,
                    PRIMARY KEY (hostname, username)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS baseline_suid_binaries (
                    hostname TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    grp TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    PRIMARY KEY (hostname, file_path)
                );
            """)

            # 3. Collected Telemetry Tables
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_processes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    ppid INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    exe TEXT,
                    cmdline TEXT,
                    ancestry_path TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    process_name TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_outbound_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT,
                    remote_port INTEGER,
                    state TEXT,
                    process_name TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_kernel_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    memory_size INTEGER NOT NULL,
                    instances_loaded INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_kernel_symbols (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    address TEXT NOT NULL,
                    symbol_type TEXT NOT NULL,
                    symbol_name TEXT NOT NULL,
                    module_name TEXT,
                    is_critical INTEGER DEFAULT 0,
                    suspicious INTEGER DEFAULT 0,
                    anomaly_detected INTEGER DEFAULT 0,
                    anomaly_reason TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kernel_analysis_summary (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL UNIQUE,
                    total_symbols INTEGER DEFAULT 0,
                    critical_symbols INTEGER DEFAULT 0,
                    suspicious_symbols INTEGER DEFAULT 0,
                    risk_level TEXT DEFAULT 'UNKNOWN',
                    hidden_module_count INTEGER DEFAULT 0,
                    analysis_timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kernel_rootkit_indicators (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    symbol_name TEXT NOT NULL,
                    address TEXT,
                    module_name TEXT,
                    reason TEXT,
                    severity TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS kernel_hidden_modules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    module_name TEXT NOT NULL,
                    symbol_count INTEGER DEFAULT 0,
                    detection_method TEXT,
                    severity TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    gid INTEGER NOT NULL,
                    home_dir TEXT,
                    login_shell TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ssh_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    user_account TEXT NOT NULL,
                    key_type TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    raw_key_comment TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_file_hashes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    sha256_hash TEXT NOT NULL,
                    mtime REAL,
                    ctime REAL,
                    size INTEGER,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_deleted_binaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    exe TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    md5 TEXT NOT NULL,
                    vault_path TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_promisc_interfaces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    interface TEXT NOT NULL,
                    flags TEXT NOT NULL,
                    is_promiscuous INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_wtmp_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    user TEXT NOT NULL,
                    line TEXT NOT NULL,
                    host TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    login_time TEXT,
                    logout_time TEXT,
                    anomaly_detected INTEGER DEFAULT 0,
                    anomaly_reason TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_lastlog_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    username TEXT NOT NULL,
                    uid INTEGER NOT NULL,
                    line TEXT,
                    host TEXT,
                    login_time TEXT,
                    anomaly_detected INTEGER DEFAULT 0,
                    anomaly_reason TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_privilege_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    syscall TEXT,
                    user TEXT,
                    target_user TEXT,
                    pid INTEGER,
                    audit_uid INTEGER,
                    command TEXT,
                    executable TEXT,
                    source_ip TEXT,
                    auth_method TEXT,
                    file_path TEXT,
                    severity TEXT DEFAULT 'medium',
                    details TEXT,
                    raw_record TEXT,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_pkg_integrity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    package TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    expected_md5 TEXT NOT NULL,
                    actual_md5 TEXT,
                    actual_sha256 TEXT,
                    status TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_crontabs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    source TEXT NOT NULL,
                    user TEXT NOT NULL,
                    schedule TEXT NOT NULL,
                    command TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_suid_binaries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    file_path TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    grp TEXT NOT NULL,
                    permissions TEXT NOT NULL,
                    sha256 TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_auth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    log_line TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ebpf_programs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    bpf_id INTEGER,
                    name TEXT NOT NULL,
                    type TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    gpl_compatible INTEGER NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ebpf_pinned (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    path TEXT NOT NULL,
                    type TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_ld_preload (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    line TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_special_fds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    pid INTEGER NOT NULL,
                    fd_num INTEGER NOT NULL,
                    fd_type TEXT NOT NULL,
                    resolved_path TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_persistence_configs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    source_path TEXT NOT NULL,
                    persistence_type TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    user_owner TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_dns_queries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    local_ip TEXT,
                    local_port INTEGER,
                    remote_ip TEXT NOT NULL,
                    remote_port INTEGER NOT NULL,
                    process_name TEXT,
                    dns_server_type TEXT,
                    domain TEXT,
                    query_type TEXT,
                    entropy REAL,
                    is_dga INTEGER DEFAULT 0,
                    is_tunneling INTEGER DEFAULT 0,
                    anomaly_flags TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    enabled TEXT NOT NULL,
                    user TEXT NOT NULL,
                    description TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collector_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    collector_name TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    duration REAL NOT NULL,
                    error_message TEXT,
                    items_collected INTEGER,
                    privilege_level TEXT NOT NULL,
                    runtime_impact TEXT NOT NULL,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_yara_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER NOT NULL,
                    scan_timestamp TEXT NOT NULL,
                    rules_loaded INTEGER,
                    files_scanned INTEGER,
                    total_matches INTEGER,
                    scan_errors TEXT,
                    FOREIGN KEY(snapshot_id) REFERENCES system_snapshots(id)
                );
            """)

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS collected_yara_matches (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    rule_name TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    file_path TEXT,
                    process_pid INTEGER,
                    severity TEXT,
                    matched_strings TEXT,
                    attck_techniques TEXT,
                    FOREIGN KEY(scan_id) REFERENCES collected_yara_scans(id)
                );
            """)

            # 4. Performance Look-up Optimizations (Indices)
            tables_to_index = [
                "collected_processes", "collected_ports", "collected_outbound_connections",
                "collected_kernel_modules", "collected_users", "collected_ssh_keys",
                "collected_file_hashes", "collected_deleted_binaries", "collected_promisc_interfaces",
                "collected_wtmp_sessions", "collected_lastlog_records", "collected_privilege_events",
                "collected_pkg_integrity", "collected_crontabs", "collected_suid_binaries",
                "collected_auth_logs", "collected_ebpf_programs", "collected_ebpf_pinned",
                "collected_ld_preload", "collected_special_fds", "collected_persistence_configs",
                "collected_dns_queries", "collected_services", "collector_runs",
                "collected_yara_scans", "collected_yara_matches"
            ]
            for t in tables_to_index:
                if t == "collected_yara_matches":
                    cursor.execute("CREATE INDEX IF NOT EXISTS idx_collected_yara_matches_scan ON collected_yara_matches(scan_id);")
                else:
                    cursor.execute(f"CREATE INDEX IF NOT EXISTS idx_{t}_snap ON {t}(snapshot_id);")

            # Schema Migration: ensure security_events has the new columns
            cursor.execute("PRAGMA table_info(security_events);")
            columns = {row["name"] for row in cursor.fetchall()}
            if "notes" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN notes TEXT DEFAULT '';")
            if "suppressed" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN suppressed INTEGER DEFAULT 0;")
            if "reviewed_at" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN reviewed_at TEXT;")
            if "attck_technique" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_technique TEXT;")
            if "attck_tactic" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_tactic TEXT;")
            if "attck_url" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN attck_url TEXT;")
            if "hostname" not in columns:
                cursor.execute("ALTER TABLE security_events ADD COLUMN hostname TEXT;")
                current_host = platform.node() or "unknown_host"
                cursor.execute("UPDATE security_events SET hostname = ? WHERE hostname IS NULL;", (current_host,))

            # Backfill existing security events that are missing ATT&CK tagging
            cursor.execute("SELECT id, event_type, description FROM security_events WHERE attck_technique IS NULL;")
            unmapped_rows = cursor.fetchall()
            if unmapped_rows:
                from orin.analysis.attck import get_attck_enrichment
                for row in unmapped_rows:
                    tech, tactic, url = get_attck_enrichment(row["event_type"], row["description"])
                    cursor.execute(
                        "UPDATE security_events SET attck_technique = ?, attck_tactic = ?, attck_url = ? WHERE id = ?;",
                        (tech, tactic, url, row["id"])
                    )

            # Migrate baseline_kernel_modules
            cursor.execute("PRAGMA table_info(baseline_kernel_modules);")
            k_cols = {row["name"] for row in cursor.fetchall()}
            if "hostname" not in k_cols:
                current_host = platform.node() or "unknown_host"
                cursor.execute("""
                    CREATE TABLE baseline_kernel_modules_new (
                        hostname TEXT NOT NULL,
                        module_name TEXT NOT NULL,
                        memory_size INTEGER NOT NULL,
                        PRIMARY KEY (hostname, module_name)
                    );
                """)
                cursor.execute(
                    "INSERT INTO baseline_kernel_modules_new (hostname, module_name, memory_size) SELECT ?, module_name, memory_size FROM baseline_kernel_modules;",
                    (current_host,)
                )
                cursor.execute("DROP TABLE baseline_kernel_modules;")
                cursor.execute("ALTER TABLE baseline_kernel_modules_new RENAME TO baseline_kernel_modules;")

            # Migrate baseline_users
            cursor.execute("PRAGMA table_info(baseline_users);")
            u_cols = {row["name"] for row in cursor.fetchall()}
            if "hostname" not in u_cols:
                current_host = platform.node() or "unknown_host"
                cursor.execute("""
                    CREATE TABLE baseline_users_new (
                        hostname TEXT NOT NULL,
                        username TEXT NOT NULL,
                        uid INTEGER NOT NULL,
                        gid INTEGER NOT NULL,
                        home_dir TEXT,
                        login_shell TEXT,
                        PRIMARY KEY (hostname, username)
                    );
                """)
                cursor.execute(
                    "INSERT INTO baseline_users_new (hostname, username, uid, gid, home_dir, login_shell) SELECT ?, username, uid, gid, home_dir, login_shell FROM baseline_users;",
                    (current_host,)
                )
                cursor.execute("DROP TABLE baseline_users;")
                cursor.execute("ALTER TABLE baseline_users_new RENAME TO baseline_users;")

            # Migrate collected_processes: ensure ancestry_path column exists
            cursor.execute("PRAGMA table_info(collected_processes);")
            p_cols = {row["name"] for row in cursor.fetchall()}
            if "ancestry_path" not in p_cols:
                cursor.execute("ALTER TABLE collected_processes ADD COLUMN ancestry_path TEXT DEFAULT '';")

            conn.commit()

    def create_snapshot(self, conn: sqlite3.Connection, hostname: str = None, os_platform: str = None) -> int:
        """Register snapshot details and return its autoincremented key identifier.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        hostname : str, optional
            Target hostname. Uses system hostname if None.
        os_platform : str, optional
            Operating system platform. Uses system platform if None.

        Returns
        -------
        int
            Auto-incremented snapshot ID.

        Raises
        ------
        ValidationError
            If hostname validation fails.
        """
        cursor = conn.cursor()
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
        if hostname is None:
            hostname = platform.node() or "unknown_host"
        else:
            # Validate hostname to prevent SQL injection and command injection
            try:
                hostname = validate_host(hostname, allow_localhost=True)
            except Exception as e:
                logger.error(f"Invalid hostname '{hostname}': {e}")
                raise

        if os_platform is None:
            os_platform = platform.platform() or "Linux"
        else:
            # Validate OS platform string for SQL injection
            try:
                os_platform = SQLInjectionValidator.validate(os_platform, "os_platform")
            except Exception as e:
                logger.error(f"Invalid os_platform '{os_platform}': {e}")
                raise

        cursor.execute(
            "INSERT INTO system_snapshots (timestamp, hostname, os_platform) VALUES (?, ?, ?);",
            (now_str, hostname, os_platform)
        )
        return cursor.lastrowid

    # Transaction-Safe Bulk Telemetry Storage APIs

    def _validate_snapshot_id(self, snapshot_id: int) -> int:
        """Validate snapshot ID before database operations.

        Parameters
        ----------
        snapshot_id : int
            The snapshot ID to validate.

        Returns
        -------
        int
            The validated snapshot ID.

        Raises
        ------
        ValidationError
            If the snapshot ID is invalid.
        """
        return validate_snapshot_id(snapshot_id)

    def store_collector_runs(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        """Store collector run metadata.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list[dict]
            List of collector run metadata records to store.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collector_runs (snapshot_id, collector_name, success, duration, error_message, items_collected, privilege_level, runtime_impact) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
            [(
                snapshot_id,
                r["collector_name"],
                1 if r["success"] else 0,
                r["duration"],
                r.get("error_message"),
                r.get("items_collected"),
                r["privilege_level"],
                r["runtime_impact"]
            ) for r in records]
        )

    def store_processes(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        """Store process telemetry data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list[dict]
            List of process records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline, ancestry_path) VALUES (?, ?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["pid"], r["ppid"], r["name"], r["exe"], r["cmdline"], r.get("ancestry_path", "")) for r in records]
        )

    def store_ports(self, conn: sqlite3.Connection, snapshot_id: int, records: list[dict]):
        """Store port telemetry data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list[dict]
            List of port records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_ports (snapshot_id, port, protocol, process_name) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["port"], r["protocol"], r["process_name"]) for r in records]
        )

    def store_outbound_connections(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store outbound connections data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_outbound_connections
            (snapshot_id, local_ip, local_port, remote_ip, remote_port, state, process_name)
            VALUES (?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["local_ip"], r["local_port"], r["remote_ip"], r["remote_port"], r["state"], r["process_name"]) for r in records]
        )

    def store_kernel_modules(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store kernel modules data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_kernel_modules (snapshot_id, module_name, memory_size, instances_loaded) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["module_name"], r["memory_size"], r["instances_loaded"]) for r in records]
        )

    def store_kernel_symbols(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store kernel symbols data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """INSERT INTO collected_kernel_symbols
               (snapshot_id, address, symbol_type, symbol_name, module_name, is_critical, suspicious, anomaly_detected, anomaly_reason)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            [(snapshot_id, r["address"], r["symbol_type"], r["symbol_name"], r.get("module_name"),
              1 if r.get("is_critical", False) else 0, 1 if r.get("suspicious", False) else 0,
              1 if r.get("anomaly_detected", False) else 0, r.get("anomaly_reason")) for r in records]
        )

    def store_kernel_analysis(self, conn: sqlite3.Connection, snapshot_id: int, analysis: dict):
        """Store kernel analysis summary data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        analysis : dict
            Kernel analysis results dictionary.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.execute(
            """INSERT INTO kernel_analysis_summary
               (snapshot_id, total_symbols, critical_symbols, suspicious_symbols, risk_level, hidden_module_count, analysis_timestamp)
               VALUES (?, ?, ?, ?, ?, ?, datetime('now'));""",
            (snapshot_id, analysis.get("total_symbols", 0), analysis.get("critical_symbols", 0),
             analysis.get("suspicious_symbols", 0), analysis.get("risk_level", "UNKNOWN"),
             analysis.get("hidden_module_count", 0))
        )

        # Store potential rootkit indicators
        indicators = analysis.get("potential_rootkit_indicators", [])
        for ind in indicators:
            conn.execute(
                """INSERT INTO kernel_rootkit_indicators
                   (snapshot_id, symbol_name, address, module_name, reason, severity)
                   VALUES (?, ?, ?, ?, ?, ?);""",
                (snapshot_id, ind.get("symbol_name"), ind.get("address"),
                 ind.get("module_name"), ind.get("reason"), ind.get("severity"))
            )

        # Store hidden modules
        hidden = analysis.get("hidden_modules", [])
        for mod in hidden:
            conn.execute(
                """INSERT INTO kernel_hidden_modules
                   (snapshot_id, module_name, symbol_count, detection_method, severity)
                   VALUES (?, ?, ?, ?, ?);""",
                (snapshot_id, mod.get("module_name"), mod.get("symbol_count"),
                 mod.get("detection_method"), mod.get("severity"))
            )

    def store_users(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store users data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_users (snapshot_id, username, uid, gid, home_dir, login_shell) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["username"], r["uid"], r["gid"], r["home_dir"], r["login_shell"]) for r in records]
        )

    def store_ssh_keys(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store ssh keys data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_ssh_keys (snapshot_id, user_account, key_type, fingerprint, raw_key_comment) VALUES (?, ?, ?, ?, ?);",
            [(snapshot_id, r["user_account"], r["key_type"], r["fingerprint"], r["raw_key_comment"]) for r in records]
        )

    def store_file_hashes(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store file hashes data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_file_hashes (snapshot_id, file_path, sha256_hash, mtime, ctime, size) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["file_path"], r["sha256_hash"], r["mtime"], r["ctime"], r["size"]) for r in records]
        )

    def store_deleted_binaries(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store deleted binaries data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_deleted_binaries (snapshot_id, pid, exe, sha256, md5, vault_path) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["pid"], r["exe"], r["sha256"], r["md5"], r["vault_path"]) for r in records]
        )

    def store_promisc_interfaces(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store promisc interfaces data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_promisc_interfaces (snapshot_id, interface, flags, is_promiscuous) VALUES (?, ?, ?, ?);",
            [(snapshot_id, r["interface"], r["flags"], r["is_promiscuous"]) for r in records]
        )

    def store_wtmp_sessions(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store wtmp sessions data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_wtmp_sessions
            (snapshot_id, user, line, host, pid, login_time, logout_time, anomaly_detected, anomaly_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["user"], r["line"], r["host"], r["pid"], r["login_time"], r["logout_time"], r["anomaly_detected"], r["anomaly_reason"]) for r in records]
        )

    def store_lastlog_records(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store lastlog records data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_lastlog_records
            (snapshot_id, username, uid, line, host, login_time, anomaly_detected, anomaly_reason)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["username"], r["uid"], r["line"], r["host"], r["login_time"], r["anomaly_detected"], r["anomaly_reason"]) for r in records]
        )

    def store_pkg_integrity(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store pkg integrity data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_pkg_integrity (snapshot_id, package, file_path, expected_md5, actual_md5, actual_sha256, status) VALUES (?, ?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["package"], r["file_path"], r["expected_md5"], r["actual_md5"], r["actual_sha256"], r["status"]) for r in records]
        )

    def store_crontabs(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store crontabs data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_crontabs (snapshot_id, source, user, schedule, command) VALUES (?, ?, ?, ?, ?);",
            [(snapshot_id, r["source"], r["user"], r["schedule"], r["command"]) for r in records]
        )

    def store_suid_binaries(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store suid binaries data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_suid_binaries (snapshot_id, file_path, owner, grp, permissions, sha256) VALUES (?, ?, ?, ?, ?, ?);",
            [(snapshot_id, r["file_path"], r["owner"], r["grp"], r["permissions"], r["sha256"]) for r in records]
        )

    def store_privilege_events(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store privilege events data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        """Store privilege escalation and authentication events."""
        conn.executemany(
            """INSERT INTO collected_privilege_events
               (snapshot_id, event_type, syscall, user, target_user, pid, audit_uid,
                command, executable, source_ip, auth_method, file_path, severity, details, raw_record, timestamp)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""",
            [(snapshot_id,
              r.get("event_type"),
              r.get("syscall"),
              r.get("user"),
              r.get("target_user"),
              r.get("pid"),
              r.get("audit_uid"),
              r.get("command"),
              r.get("executable"),
              r.get("source_ip"),
              r.get("auth_method"),
              r.get("file_path"),
              r.get("severity", "medium"),
              r.get("details"),
              r.get("raw_record"),
              r.get("timestamp")) for r in records]
        )

    def store_auth_logs(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store auth logs data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_auth_logs (snapshot_id, log_line) VALUES (?, ?);",
            [(snapshot_id, line) for line in records]
        )

    def store_ebpf_programs(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store ebpf programs data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_ebpf_programs (snapshot_id, bpf_id, name, type, tag, gpl_compatible)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r.get("bpf_id"), r["name"], r["type"], r["tag"], r["gpl_compatible"]) for r in records]
        )

    def store_ebpf_pinned(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store ebpf pinned data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_ebpf_pinned (snapshot_id, path, type) VALUES (?, ?, ?);",
            [(snapshot_id, r["path"], r["type"]) for r in records]
        )

    def store_ld_preload(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store ld preload data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            "INSERT INTO collected_ld_preload (snapshot_id, line) VALUES (?, ?);",
            [(snapshot_id, line) for line in records]
        )

    def store_special_fds(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store special fds data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_special_fds (snapshot_id, pid, fd_num, fd_type, resolved_path)
            VALUES (?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["pid"], r["fd_num"], r["fd_type"], r["resolved_path"]) for r in records]
        )

    def store_persistence_configs(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store persistence configs data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_persistence_configs (snapshot_id, source_path, persistence_type, content_hash, user_owner)
            VALUES (?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["source_path"], r["persistence_type"], r["content_hash"], r["user_owner"]) for r in records]
        )

    def store_dns_queries(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store dns queries data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_dns_queries (snapshot_id, local_ip, local_port, remote_ip, remote_port, process_name, dns_server_type, domain, query_type, entropy, is_dga, is_tunneling, anomaly_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r.get("local_ip"), r.get("local_port"), r.get("remote_ip"), r.get("remote_port"), r.get("process_name"), r.get("dns_server_type"), r.get("domain"), r.get("query_type"), r.get("entropy"), r.get("is_dga", 0), r.get("is_tunneling", 0), r.get("anomaly_flags")) for r in records]
        )

    def store_services(self, conn: sqlite3.Connection, snapshot_id: int, records):
        """Store system services data.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        records : list
            List of records to store.

        Raises
        ------
        ValidationError
            If snapshot_id validation fails.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        conn.executemany(
            """
            INSERT INTO collected_services (snapshot_id, name, status, enabled, user, description)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            [(snapshot_id, r["name"], r["status"], r["enabled"], r["user"], r.get("description", "")) for r in records]
        )

    def store_yara_scan_results(self, conn: sqlite3.Connection, snapshot_id: int, scan_summary: dict):
        """Store YARA scan summary and individual matches.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection object.
        snapshot_id : int
            Snapshot identifier to associate with the data.
        scan_summary : dict
            The scan summary dictionary.
        """
        snapshot_id = self._validate_snapshot_id(snapshot_id)
        cursor = conn.cursor()

        # Insert summary
        cursor.execute(
            """
            INSERT INTO collected_yara_scans (snapshot_id, scan_timestamp, rules_loaded, files_scanned, total_matches, scan_errors)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                snapshot_id,
                scan_summary.get("scan_timestamp"),
                scan_summary.get("rules_loaded"),
                scan_summary.get("files_scanned"),
                scan_summary.get("total_matches"),
                json.dumps(scan_summary.get("scan_errors", []))
            )
        )
        scan_id = cursor.lastrowid

        # Insert matches
        matches = scan_summary.get("matches", [])
        if matches:
            conn.executemany(
                """
                INSERT INTO collected_yara_matches (scan_id, rule_name, namespace, file_path, process_pid, severity, matched_strings, attck_techniques)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """,
                [
                    (
                        scan_id,
                        m["rule_name"],
                        m["namespace"],
                        m.get("file_path"),
                        m.get("process_pid"),
                        m.get("severity"),
                        json.dumps(m.get("matched_strings", [])),
                        json.dumps(m.get("attck_techniques", []))
                    )
                    for m in matches
                ]
            )

    # Vault Lifecycle Management
    def vault_stats(self, conn: sqlite3.Connection) -> dict:
        """Return statistics about the vault: size, snapshot count, oldest/newest record."""
        cursor = conn.cursor()

        # Snapshot count
        cursor.execute("SELECT COUNT(*) as total FROM system_snapshots;")
        snapshot_count = cursor.fetchone()["total"]

        # Oldest and newest snapshots
        cursor.execute("SELECT MIN(timestamp) as oldest, MAX(timestamp) as newest FROM system_snapshots;")
        time_range = cursor.fetchone()
        oldest_snapshot = time_range["oldest"]
        newest_snapshot = time_range["newest"]

        # Table sizes
        cursor.execute("""
            SELECT name,
                   (SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=name) as exists_flag
            FROM sqlite_master
            WHERE type='table' AND name LIKE 'collected_%';
        """)
        table_stats = {}
        for row in cursor.fetchall():
            table_name = row["name"]
            cursor.execute(f"SELECT COUNT(*) as cnt FROM {table_name};")
            table_stats[table_name] = cursor.fetchone()["cnt"]

        # Database file size (if on disk)
        db_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0

        return {
            "snapshot_count": snapshot_count,
            "oldest_snapshot": oldest_snapshot,
            "newest_snapshot": newest_snapshot,
            "table_counts": table_stats,
            "database_size_bytes": db_size_bytes,
            "database_size_mb": round(db_size_bytes / (1024 * 1024), 2)
        }

    def get_critical_alert_snapshot_ids(self, conn: sqlite3.Connection) -> set[int]:
        """Find snapshot IDs that are associated with unresolved critical security events."""
        from datetime import datetime
        cursor = conn.cursor()
        
        # Check if table exists (to avoid test failures on uninitialized/minimal databases in mocks)
        try:
            cursor.execute("SELECT 1 FROM security_events LIMIT 1;")
        except sqlite3.OperationalError:
            return set()

        cursor.execute("""
            SELECT timestamp, hostname FROM security_events
            WHERE severity = 'critical' AND resolved = 0;
        """)
        alerts = cursor.fetchall()
        if not alerts:
            return set()
            
        cursor.execute("SELECT id, hostname, timestamp FROM system_snapshots;")
        snapshots = cursor.fetchall()
        if not snapshots:
            return set()
            
        preserved_ids = set()
        
        # Helper to parse timestamps securely
        def parse_ts(ts_str):
            if not ts_str:
                return datetime.min
            # Standardize ISO formats: remove Z, replace T
            cleaned = ts_str.replace('Z', '').replace('T', ' ')
            # Try parsing with microsecond first, then without
            for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S'):
                try:
                    return datetime.strptime(cleaned[:19] if fmt == '%Y-%m-%d %H:%M:%S' else cleaned, fmt)
                except ValueError:
                    continue
            return datetime.min

        for alert in alerts:
            a_ts_str = alert["timestamp"]
            a_host = alert["hostname"]
            a_ts = parse_ts(a_ts_str)
            
            # Find snapshots on the same hostname (or all snapshots if a_host is None)
            host_snaps = [s for s in snapshots if a_host is None or s["hostname"] == a_host]
            if not host_snaps:
                continue
                
            # Mode 1: Find latest snapshot <= alert timestamp
            matching_snaps = [s for s in host_snaps if parse_ts(s["timestamp"]) <= a_ts]
            if matching_snaps:
                # Sort by timestamp descending
                matching_snaps.sort(key=lambda s: parse_ts(s["timestamp"]), reverse=True)
                preserved_ids.add(matching_snaps[0]["id"])
            else:
                # Fallback: find closest snapshot in absolute time difference
                host_snaps.sort(key=lambda s: abs((parse_ts(s["timestamp"]) - a_ts).total_seconds()))
                preserved_ids.add(host_snaps[0]["id"])
                
        return preserved_ids

    def vault_prune(self, conn: sqlite3.Connection, older_than_days: int = None,
                    dry_run: bool = False, retention_policies: dict = None,
                    keep_last: int = None, preserve_critical: bool = True) -> dict:
        """Delete snapshots, related collected data, and resolved alerts based on retention policies.

        Supports legacy single-threshold pruning, count-based pruning, and granular per-type retention policies.

        Parameters
        ----------
        conn : sqlite3.Connection
            Database connection handle.
        older_than_days : int, optional
            Legacy mode: Delete all snapshots older than this many days.
            Ignored if retention_policies or keep_last is provided.
        dry_run : bool
            If True, only report what would be deleted without actually deleting.
        retention_policies : dict, optional
            Granular retention configuration per table/event type.
            Example: {
                "collected_processes": 7,
                "collected_ports": 7,
                "default": 30
            }
        keep_last : int, optional
            Count-based mode: Keep only the latest N snapshots per host and delete older ones.
        preserve_critical : bool
            If True, snapshots associated with unresolved critical alerts will not be deleted.

        Returns
        -------
        dict
            Summary of deleted (or to-be-deleted) records by table.
        """
        from datetime import datetime, timedelta, timezone

        cursor = conn.cursor()

        # Retrieve preserved snapshot IDs
        preserved_ids = self.get_critical_alert_snapshot_ids(conn) if preserve_critical else set()

        # Determine retention mode
        if keep_last is not None:
            mode = "count"
            default_retention = None
        elif retention_policies:
            # Granular per-type retention mode
            default_retention = retention_policies.get("default", older_than_days or 30)
            mode = "granular"
        else:
            # Legacy single-threshold mode
            if older_than_days is None:
                older_than_days = 30  # Default to 30 days if nothing specified
            default_retention = older_than_days
            mode = "legacy"
            retention_policies = {"default": older_than_days}

        deletion_summary = {
            "mode": mode,
            "deleted_by_table": {},
            "dry_run": dry_run,
            "retention_policies_applied": retention_policies if mode == "granular" else None,
            "preserved_snapshots_count": len(preserved_ids)
        }

        if mode in ("legacy", "count"):
            if mode == "count":
                cursor.execute("SELECT DISTINCT hostname FROM system_snapshots;")
                hostnames = [row["hostname"] for row in cursor.fetchall()]
                
                snapshot_ids_to_delete = []
                for h in hostnames:
                    cursor.execute("""
                        SELECT id FROM system_snapshots
                        WHERE hostname = ?
                        ORDER BY timestamp DESC;
                    """, (h,))
                    snapshots = [row["id"] for row in cursor.fetchall()]
                    if len(snapshots) > keep_last:
                        snapshot_ids_to_delete.extend(snapshots[keep_last:])
                deletion_summary["keep_last"] = keep_last
            else:
                cutoff_date = (datetime.now(timezone.utc) - timedelta(days=default_retention)).strftime('%Y-%m-%dT%H:%M:%SZ')
                cursor.execute("SELECT id FROM system_snapshots WHERE timestamp < ?;", (cutoff_date,))
                snapshot_ids_to_delete = [row["id"] for row in cursor.fetchall()]
                deletion_summary["cutoff_date"] = cutoff_date

            # Exclude preserved snapshot IDs from deletion list
            actual_ids_to_delete = [sid for sid in snapshot_ids_to_delete if sid not in preserved_ids]
            preserved_count = len(snapshot_ids_to_delete) - len(actual_ids_to_delete)
            if preserved_count > 0:
                deletion_summary["preserved_by_alerts_count"] = preserved_count

            if not actual_ids_to_delete:
                deletion_summary["deleted_snapshots"] = 0
                if mode == "count":
                    deletion_summary["message"] = f"No snapshots exceed the keep limit of {keep_last} per host."
                else:
                    deletion_summary["message"] = f"No snapshots older than {older_than_days} days found (or all matched were preserved)."
                return deletion_summary

            deletion_summary["deleted_snapshots"] = len(actual_ids_to_delete)

            # Tables with foreign key references to snapshot_id
            tables_with_snapshot_ref = [
                "collected_processes",
                "collected_ports",
                "collected_outbound_connections",
                "collected_kernel_modules",
                "collected_kernel_symbols",
                "collected_users",
                "collected_ssh_keys",
                "collected_file_hashes",
                "collected_deleted_binaries",
                "collected_promisc_interfaces",
                "collected_crontabs",
                "collected_wtmp_sessions",
                "collected_lastlog_records",
                "collected_pkg_integrity",
                "collected_suid_binaries",
                "collected_privilege_events",
                "collected_auth_logs",
                "collected_ebpf_programs",
                "collected_ebpf_pinned",
                "collected_ld_preload",
                "collected_special_fds",
                "collected_persistence_configs",
                "collected_dns_queries",
            ]

            # Delete related telemetry data for these snapshots
            for snapshot_id in actual_ids_to_delete:
                for table in tables_with_snapshot_ref:
                    try:
                        cursor.execute(f"SELECT COUNT(*) as cnt FROM {table} WHERE snapshot_id = ?;", (snapshot_id,))
                        count = cursor.fetchone()["cnt"]
                        if count > 0:
                            deletion_summary["deleted_by_table"][table] = deletion_summary["deleted_by_table"].get(table, 0) + count
                            if not dry_run:
                                cursor.execute(f"DELETE FROM {table} WHERE snapshot_id = ?;", (snapshot_id,))
                    except sqlite3.Error:
                        pass

                # Delete resolved security events for this snapshot's hostname
                cursor.execute("SELECT hostname FROM system_snapshots WHERE id = ?;", (snapshot_id,))
                row = cursor.fetchone()
                if row:
                    hostname = row["hostname"]
                    cursor.execute(
                        "SELECT COUNT(*) as cnt FROM security_events WHERE hostname = ? AND resolved = 1;",
                        (hostname,)
                    )
                    count = cursor.fetchone()["cnt"]
                    if count > 0:
                        deletion_summary["deleted_by_table"]["security_events_resolved"] = \
                            deletion_summary["deleted_by_table"].get("security_events_resolved", 0) + count
                        if not dry_run:
                            cursor.execute(
                                "DELETE FROM security_events WHERE hostname = ? AND resolved = 1;",
                                (hostname,)
                            )

            # Delete the snapshots themselves
            if not dry_run:
                placeholders = ','.join('?' * len(actual_ids_to_delete))
                cursor.execute(f"DELETE FROM system_snapshots WHERE id IN ({placeholders});", actual_ids_to_delete)

                # Vacuum to reclaim space safely
                try:
                    conn.commit()
                    old_isolation = conn.isolation_level
                    conn.isolation_level = None
                    cursor.execute("VACUUM;")
                    conn.isolation_level = old_isolation
                except sqlite3.Error:
                    pass

            return deletion_summary

        else:
            # Granular per-type retention mode
            deletion_summary["cutoff_dates"] = {}

            # Define all managed tables
            telemetry_tables = [
                "collected_processes",
                "collected_ports",
                "collected_outbound_connections",
                "collected_kernel_modules",
                "collected_kernel_symbols",
                "collected_users",
                "collected_ssh_keys",
                "collected_file_hashes",
                "collected_deleted_binaries",
                "collected_promisc_interfaces",
                "collected_crontabs",
                "collected_wtmp_sessions",
                "collected_lastlog_records",
                "collected_pkg_integrity",
                "collected_suid_binaries",
                "collected_privilege_events",
                "collected_auth_logs",
                "collected_ebpf_programs",
                "collected_ebpf_pinned",
                "collected_ld_preload",
                "collected_special_fds",
                "collected_persistence_configs",
                "collected_dns_queries",
            ]

            event_tables = ["security_events"]

            # Process telemetry tables with per-table retention
            for table in telemetry_tables:
                table_retention = retention_policies.get(table, default_retention)
                table_cutoff = (datetime.now(timezone.utc) - timedelta(days=table_retention)).strftime('%Y-%m-%dT%H:%M:%SZ')
                deletion_summary["cutoff_dates"][table] = table_cutoff

                try:
                    # Find snapshot IDs that match the cutoff date
                    cursor.execute("SELECT id FROM system_snapshots WHERE timestamp < ?;", (table_cutoff,))
                    snap_ids = [row["id"] for row in cursor.fetchall()]
                    
                    # Exclude preserved snapshot IDs
                    actual_snap_ids = [sid for sid in snap_ids if sid not in preserved_ids]

                    if actual_snap_ids:
                        placeholders = ','.join('?' * len(actual_snap_ids))
                        cursor.execute(f"""
                            SELECT COUNT(*) as cnt
                            FROM {table}
                            WHERE snapshot_id IN ({placeholders});
                        """, actual_snap_ids)
                        count = cursor.fetchone()["cnt"]

                        if count > 0:
                            deletion_summary["deleted_by_table"][table] = count

                            if not dry_run:
                                cursor.execute(f"""
                                    DELETE FROM {table}
                                    WHERE snapshot_id IN ({placeholders});
                                """, actual_snap_ids)
                except sqlite3.Error:
                    pass

            # Process security events with special handling for resolved status
            for table in event_tables:
                table_retention = retention_policies.get(table, default_retention)
                table_cutoff = (datetime.now(timezone.utc) - timedelta(days=table_retention)).strftime('%Y-%m-%dT%H:%M:%SZ')
                deletion_summary["cutoff_dates"][table] = table_cutoff

                try:
                    cursor.execute(f"""
                        SELECT COUNT(*) as cnt
                        FROM {table}
                        WHERE resolved = 1 AND timestamp < ?;
                    """, (table_cutoff,))
                    count = cursor.fetchone()["cnt"]

                    if count > 0:
                        deletion_summary["deleted_by_table"][f"{table}_resolved"] = count

                        if not dry_run:
                            cursor.execute(f"""
                                DELETE FROM {table}
                                WHERE resolved = 1 AND timestamp < ?;
                            """, (table_cutoff,))
                except sqlite3.Error:
                    pass

            # Clean up orphaned snapshots (except those that are explicitly preserved)
            try:
                cursor.execute("""
                    SELECT id FROM system_snapshots
                    WHERE id NOT IN (
                        SELECT DISTINCT snapshot_id FROM collected_processes
                        UNION
                        SELECT DISTINCT snapshot_id FROM collected_ports
                        UNION
                        SELECT DISTINCT snapshot_id FROM collected_outbound_connections
                        UNION
                        SELECT DISTINCT snapshot_id FROM collected_kernel_modules
                        UNION
                        SELECT DISTINCT snapshot_id FROM collected_users
                    );
                """)
                orphaned_snapshots = [row["id"] for row in cursor.fetchall()]
                actual_orphaned = [sid for sid in orphaned_snapshots if sid not in preserved_ids]

                if actual_orphaned:
                    deletion_summary["deleted_orphaned_snapshots"] = len(actual_orphaned)

                    if not dry_run:
                        placeholders = ','.join('?' * len(actual_orphaned))
                        cursor.execute(f"DELETE FROM system_snapshots WHERE id IN ({placeholders});", actual_orphaned)
            except sqlite3.Error:
                pass

            # Vacuum to reclaim space safely
            if not dry_run:
                try:
                    conn.commit()
                    old_isolation = conn.isolation_level
                    conn.isolation_level = None
                    cursor.execute("VACUUM;")
                    conn.isolation_level = old_isolation
                except sqlite3.Error:
                    pass

            return deletion_summary

    # High-Performance Batch Insert Methods with Chunking
    def batch_store_processes(self, snapshot_id: int, records: list[dict],
                               chunk_size: int = 500) -> int:
        """Store process records in optimized batches.

        Parameters
        ----------
        snapshot_id : int
            The snapshot ID to associate with these records.
        records : list[dict]
            List of process record dictionaries.
        chunk_size : int
            Number of records to insert per transaction (default: 500).

        Returns
        -------
        int
            Total number of records inserted.
        """
        total_inserted = 0
        with self.get_connection() as conn:
            for i in range(0, len(records), chunk_size):
                chunk = records[i:i + chunk_size]
                conn.executemany(
                    "INSERT INTO collected_processes (snapshot_id, pid, ppid, name, exe, cmdline, ancestry_path) VALUES (?, ?, ?, ?, ?, ?, ?);",
                    [(snapshot_id, r["pid"], r["ppid"], r["name"], r["exe"], r["cmdline"], r.get("ancestry_path", "")) for r in chunk]
                )
                total_inserted += len(chunk)
            conn.commit()
        return total_inserted

    def batch_store_kernel_symbols(self, snapshot_id: int, records: list[dict],
                                    chunk_size: int = 1000) -> int:
        """Store kernel symbol records in optimized batches.

        Parameters
        ----------
        snapshot_id : int
            The snapshot ID to associate with these records.
        records : list[dict]
            List of kernel symbol record dictionaries.
        chunk_size : int
            Number of records to insert per transaction (default: 1000).

        Returns
        -------
        int
            Total number of records inserted.
        """
        total_inserted = 0
        with self.get_connection() as conn:
            for i in range(0, len(records), chunk_size):
                chunk = records[i:i + chunk_size]
                conn.executemany(
                    """INSERT INTO collected_kernel_symbols
                       (snapshot_id, address, symbol_type, symbol_name, module_name, is_critical, suspicious, anomaly_detected, anomaly_reason)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);""",
                    [(snapshot_id, r["address"], r["symbol_type"], r["symbol_name"], r.get("module_name"),
                      1 if r.get("is_critical", False) else 0, 1 if r.get("suspicious", False) else 0,
                      1 if r.get("anomaly_detected", False) else 0, r.get("anomaly_reason")) for r in chunk]
                )
                total_inserted += len(chunk)
            conn.commit()
        return total_inserted

    def batch_store_generic(self, table_name: str, columns: list[str],
                            records: list[tuple], chunk_size: int = 500) -> int:
        """Generic batch insert method for any table.

        Parameters
        ----------
        table_name : str
            Name of the target table.
        columns : list[str]
            List of column names to insert into.
        records : list[tuple]
            List of tuples containing values to insert.
        chunk_size : int
            Number of records to insert per transaction (default: 500).

        Returns
        -------
        int
            Total number of records inserted.

        Raises
        ------
        ValueError
            If columns list is empty or records contain invalid data.
        """
        if not columns:
            raise ValueError("Columns list cannot be empty")

        placeholders = ', '.join(['?' for _ in columns])
        column_names = ', '.join(columns)
        sql = f"INSERT INTO {table_name} ({column_names}) VALUES ({placeholders});"

        total_inserted = 0
        with self.get_connection() as conn:
            for i in range(0, len(records), chunk_size):
                chunk = records[i:i + chunk_size]
                conn.executemany(sql, chunk)
                total_inserted += len(chunk)
            conn.commit()
        return total_inserted

    def optimize_database(self) -> dict:
        """Apply comprehensive SQLite performance optimizations.

        This method applies various PRAGMA settings and runs ANALYZE
        to optimize query performance. Should be called periodically
        or after large data imports.

        Returns
        -------
        dict
            Statistics about the optimization performed.
        """
        stats = {
            'optimizations_applied': [],
            'tables_analyzed': 0,
            'indices_created': 0
        }

        with self.get_connection() as conn:
            # Apply performance PRAGMAs
            optimizations = [
                ("journal_mode", "WAL"),
                ("synchronous", "NORMAL"),
                ("cache_size", "-64000"),  # 64MB
                ("temp_store", "MEMORY"),
                ("mmap_size", "268435456"),  # 256MB
                ("busy_timeout", "30000"),  # 30 seconds
                ("foreign_keys", "ON")
            ]

            for pragma, value in optimizations:
                try:
                    cursor = conn.execute(f"PRAGMA {pragma}={value};")
                    if pragma == "journal_mode":
                        mode = cursor.fetchone()[0]
                        if mode.lower() != "wal":
                            logger.warning(f"Failed to set journal_mode to WAL during optimization. Mode: {mode}")
                    stats['optimizations_applied'].append(f"{pragma}={value}")
                except sqlite3.Error as e:
                    logger.warning(f"Failed to set PRAGMA {pragma}: {e}")

            # Analyze all tables for query optimization
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            for table in tables:
                try:
                    cursor.execute(f"ANALYZE {table};")
                    stats['tables_analyzed'] += 1
                except sqlite3.Error:
                    pass

            conn.commit()

        logger.info(f"Database optimization complete: {stats['tables_analyzed']} tables analyzed")
        return stats

    def get_pool_stats(self) -> dict:
        """Get connection pool statistics.

        Returns
        -------
        dict
            Pool statistics if pool is initialized, otherwise None.
        """
        if self._connection_pool:
            return self._connection_pool.stats()
        return {'status': 'pool_not_initialized'}