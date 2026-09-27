import os
import time

from shared import app, db


STARTUP_RETRIES = int(os.getenv("MANIWANI_STARTUP_RETRIES", "30"))
STARTUP_DELAY_SECONDS = float(os.getenv("MANIWANI_STARTUP_DELAY", "2"))


def wait_for_port(host: str, port: int, timeout: float = 300) -> bool:
    import socket
    start_time = time.time()
    app.logger.info("CRITICAL: Waiting for object storage to become reachable at %s:%d...", host, port)
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                app.logger.info("SUCCESS: Object storage is reachable at %s:%d", host, port)
                return True
        except (socket.timeout, ConnectionRefusedError, OSError) as e:
            if int(time.time() - start_time) % 10 == 0:
                app.logger.warning(
                    "STILL WAITING: the storage gateway (%s:%d) is not yet accepting "
                    "connections: %s", host, port, e)
            time.sleep(2)
    return False


def can_continue_after_storage_error(exc: Exception) -> bool:
    message = " ".join(
        str(part) for part in (exc, getattr(exc, "__cause__", None), getattr(exc, "__context__", None)) if part
    )
    return "XMinioStorageFull" in message or "minimum free drive threshold" in message or "ConnectTimeoutError" in message


def has_table(table_name: str) -> bool:
    from sqlalchemy import inspect

    with app.app_context():
        return inspect(db.engine).has_table(table_name)


def initialize_runtime() -> None:
    from update import update_db, update_storage

    # Simple file lock for uWSGI workers
    lock_file = "/tmp/maniwani_init.lock"
    if os.path.exists(lock_file):
        app.logger.info("Initialization already completed by another worker. Skipping.")
        return

    try:
        with open(lock_file, "w") as f:
            f.write(str(os.getpid()))

        # Wait for S3 endpoint to be reachable before proceeding
        s3_endpoint = app.config.get("S3_ENDPOINT", "")
        if s3_endpoint:
            from urllib.parse import urlparse
            parsed = urlparse(s3_endpoint)
            if parsed.hostname and parsed.port:
                wait_for_port(parsed.hostname, parsed.port)

        if has_table("board"):
            app.logger.info("Existing database detected; applying migrations")
            try:
                update_storage()
            except Exception as exc:
                if not can_continue_after_storage_error(exc):
                    app.logger.warning("Storage update encountered a non-fatal error: %s", exc)
                else:
                    app.logger.warning("Storage update failed because the object store is full: %s", exc)

            update_db()
            # The folder->S3 media migration used to run HERE, synchronously,
            # before uwsgi was ever started. It os.walk()s all of /maniwani
            # (including anime-captcha/node_modules) and then /data looking for
            # loose image files, which takes ~6m15s on this box and then prints
            # "NO MEDIA FOUND" -- because the migration completed long ago and
            # there has been nothing to move for months.
            #
            # That was six minutes of hard downtime on EVERY restart: nginx
            # serves its "Just a moment..." page the whole time, because the
            # backend is replicas:1 and cannot answer /health until uwsgi runs.
            #
            # It now runs as a background thread inside the app instead (see
            # services/media_s3_migration.py, started from app.py). A thread
            # started here would not survive: ensure_runtime.py is a separate
            # process that exits before uwsgi starts.
        else:
            app.logger.info("No board table detected; bootstrapping a fresh installation")
            from bootstrap import main as bootstrap_main
            bootstrap_main()
    except BaseException:
        # A failed attempt must not leave the lock behind, or every retry (and
        # every other worker) silently skips initialization and the app serves
        # with an unmigrated database.
        try:
            os.remove(lock_file)
        except OSError:
            pass
        raise
    # On success the lock file stays to stop other workers from re-running
    # initialization during the same container session.

def main() -> None:
    last_error = None
    for attempt in range(1, STARTUP_RETRIES + 1):
        try:
            initialize_runtime()
            return
        except Exception as exc:
            last_error = exc
            try:
                if attempt < STARTUP_RETRIES:
                    app.logger.warning(
                        "Runtime initialization attempt %d/%d failed: %s (retrying in %ds...)",
                        attempt,
                        STARTUP_RETRIES,
                        str(exc),
                        STARTUP_DELAY_SECONDS,
                    )
                else:
                    app.logger.exception(
                        "Runtime initialization failed after %d attempts",
                        STARTUP_RETRIES,
                    )
            except Exception:
                # If logging fails (e.g. Due to Unicode error), don't crash the loop
                pass

            if attempt == STARTUP_RETRIES:
                raise
            time.sleep(STARTUP_DELAY_SECONDS)
    if last_error is not None:
        raise last_error


if __name__ == "__main__":
    main()
