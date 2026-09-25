# Database Internals

Technical reference for `src/orin/core/database.py` — the connection pool, performance tuning, and encrypted-storage exception handling. Intended for contributors working on the storage layer.

---

## Connection Pool

`ConnectionPool` provides thread-safe, reusable SQLite connections.

**Key properties:**
- Configurable pool size (default: 10) and acquisition timeout (default: 30 s)
- Automatic health checking — stale connections are detected and replaced
- Connection warmup — 3 connections are pre-created on pool initialization
- Pool statistics via `stats()`

### Atomic Counter Management

The pool uses a pattern that prevents over-counting and ensures rollback on creation failure:

```python
with self._lock:
    if self._created < self.max_connections:
        self._created += 1
        should_create = True
    else:
        should_create = False

if should_create:
    try:
        return self._create_connection()
    except Exception:
        with self._lock:
            self._created = max(0, self._created - 1)
        raise
```

The counter is incremented inside the lock *before* attempting creation, with a decrement on failure. This prevents the earlier non-atomic check-then-increment race condition that allowed multiple threads to exceed `max_connections` and leaked counter increments on creation failures.

### `acquire()`

- The connection variable is initialized to `None` at the top of each loop iteration.
- On unexpected error, any partially-acquired connection is closed before the exception propagates — no leaked handles.

### `release()`

- Null-safe: `release(None)` is a no-op.
- Atomically checks `_closed` state and connection validity under the lock. Invalid or post-close connections are closed and the counter decremented, not returned to the pool.

### `close()`

Idempotent — repeated calls are safe. Sets `_closed` under the lock, drains and closes all pooled connections (logging any close errors as warnings), resets the counter to 0, and logs completion.

### Stale Connection Recovery

When a stale connection is detected: the connection is closed immediately, the reference is cleared to prevent double-close, and the pool then atomically decides whether a replacement can be created (decrementing the counter on failure) or whether to return to the wait loop at capacity.

### Test Coverage

`tests/test_connection_pool_race_conditions.py` — 12 tests covering: concurrent acquire/release under load, leak prevention on failure, atomic counter bounds, close-vs-acquire races, stale connection handling, pool-full behaviour, exception cleanup, double-close idempotency, null safety, and a 20-thread × 50-iteration stress test.

All tests pass consistently under high concurrency with no measurable performance regression. Locks are held only briefly for counter bookkeeping; connection creation happens outside the lock where possible.

---

## SQLite Performance Tuning

### `OrinStorage` Constructor

```python
OrinStorage(
    db_path: Path,
    encryption_passphrase: str = None,
    pool_size: int = 10,
    pool_timeout: float = 30.0,
)
```

### Pool Lifecycle

```python
storage = OrinStorage(Path("forensics.db"), pool_size=10)
storage.initialize_pool()    # Initialize and warm up the pool
storage.initialize_db()

with storage.get_connection() as conn:    # Pooled by default
    snapshot_id = storage.create_snapshot(conn)
    storage.store_processes(conn, snapshot_id, processes)
    conn.commit()

print(storage.get_pool_stats())    # {max_connections, current_size, created_connections, closed}
storage.close_pool()               # Re-encrypts if encryption is active
```

Use `get_connection(use_pool=False)` for legacy non-pooled behaviour.

### Applied PRAGMAs

| PRAGMA | Value | Effect |
|---|---|---|
| `journal_mode` | `WAL` | Readers do not block writers; better crash recovery |
| `synchronous` | `NORMAL` | Balanced durability / performance |
| `cache_size` | `-64000` | 64 MB page cache |
| `temp_store` | `MEMORY` | Temporary tables in RAM |
| `mmap_size` | `268435456` | 256 MB memory-mapped I/O |
| `busy_timeout` | `30000` | 30 s wait on lock contention |
| `foreign_keys` | `ON` | Referential integrity enforced |

### Batch Inserts

```python
storage.batch_store_processes(snapshot_id, records, chunk_size=500)
storage.batch_store_kernel_symbols(snapshot_id, records, chunk_size=1000)
storage.batch_store_generic(table_name, columns, records, chunk_size=500)
```

Chunking reduces transaction overhead by roughly 90% on large imports. For example, 500 records in 25-record chunks results in 20 transactions instead of 500.

### Database Optimization

```python
stats = storage.optimize_database()
```

Applies all performance PRAGMAs plus `ANALYZE` on all tables. Run after large imports.

### Concurrent Access

Each thread acquires its own pooled connection; the pool handles thread-safety internally:

```python
def collector_thread(data):
    with storage.get_connection() as conn:
        snapshot_id = storage.create_snapshot(conn)
        storage.store_processes(conn, snapshot_id, data)
        conn.commit()
```

### Test Coverage

`tests/test_database_performance.py` — 12 tests: pool initialization, acquire/release, concurrent access, timeouts, WAL verification, PRAGMA application, batch inserts (generic and type-specific), database optimization, and batch-vs-regular performance comparison.

---

## Encrypted Storage Exception Handling

`EncryptedStorage.encrypt_file()` and `decrypt_file()` implement comprehensive validation, atomic writes, and structured audit logging.

### `encrypt_file()`

- Validates that the plaintext file exists, is non-empty, and is accessible before starting.
- Writes ciphertext to a temporary file, then performs an atomic rename — no partial output files on failure.
- Temporary files are removed on any failure path.
- The plaintext file is deleted **only after** encryption succeeds. A warning is logged if plaintext cleanup itself fails.
- Raises `FileNotFoundError`, `PermissionError`, `ValueError`, or `IOError` as appropriate.

### `decrypt_file()`

- Validates that the ciphertext and metadata files exist, the salt is exactly 16 bytes, the nonce is exactly 12 bytes, and the ciphertext is non-empty.
- Validates that the salt in the metadata matches the salt embedded with the ciphertext as a tamper check, before attempting decryption.
- GCM authentication failures (wrong passphrase or tampered ciphertext) are surfaced as `PermissionError` or `ValueError`.
- Uses the same atomic temp-file + rename + cleanup-on-failure pattern as encryption.

### Security Properties

- No plaintext is ever left on disk after a failed encryption operation.
- GCM authentication tags provide tamper detection at decryption time.
- All operations are logged for audit trail purposes, including detected tampering attempts (logged at `ERROR` level).

### Test Coverage

`tests/test_encryption_exceptions.py` — 16 tests (1 skipped when running as root): missing/empty files, successful roundtrip with plaintext cleanup, atomic-write failure handling, missing ciphertext/metadata, wrong passphrase, tampered ciphertext, invalid salt/nonce sizes, empty ciphertext, and logging on both success and failure paths.

### Recommendations for Future Work

- Secure memory zeroization of sensitive data after use
- Rate limiting on encryption/decryption operations to mitigate brute-force attacks
- Centralized audit log integration
- Automatic key rotation with versioned key identifiers
- Pre-encryption backup strategy to prevent data loss on partial failure