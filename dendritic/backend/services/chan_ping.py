"""Reachability ping for each aggregated chan.

Answers "is this chan up, and what does it answer?" for the admin chan list, so
an operator can read down ~300 sites and see 200 / 403 / 404 / timeout at a
glance instead of clicking each one.

NEVER RUN FROM A REQUEST HANDLER. 300 sites x a network timeout would hang the
page — inline network work in a route already took the front page down once. A
background sweep fills the cached columns on ChanBoardScan and the admin list
renders those.

Design notes:
  * HEAD first, GET fallback. Many imageboards reject or mishandle HEAD (405/501),
    which would otherwise be reported as a failure for a perfectly live site.
  * Redirects are NOT followed: the status code of the URL as listed is what the
    operator wants to see, and following them hides a site that has moved.
  * A small thread pool, because these waits are almost entirely idle. Bounded so
    a sweep cannot become a burst of hundreds of outbound connections.
  * .onion / .i2p hosts are recorded as unreachable with a clear reason rather
    than being retried forever — they need a proxy this process does not have.
"""
import concurrent.futures
import os
import threading
import time

import requests

from model.ChanBoard import hosts_due_for_ping, record_ping
from model.SiteSetting import get_setting
from shared import app, db

SETTING_KEY = "chan_ping_enabled"
TIMEOUT_SECONDS = float(os.getenv("CHAN_PING_TIMEOUT", "10"))
BATCH_SIZE = int(os.getenv("CHAN_PING_BATCH", "25"))
MAX_WORKERS = int(os.getenv("CHAN_PING_WORKERS", "8"))
# How stale a result may be before the sweep refreshes it.
MAX_AGE_MINUTES = int(os.getenv("CHAN_PING_MAX_AGE_MINUTES", "60"))
_SWEEP_INTERVAL_SECONDS = int(os.getenv("CHAN_PING_LOOP_SECONDS", "300"))

_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome Safari"
)

_thread = None
_lock = threading.Lock()
_stop = threading.Event()


def ping_enabled():
    raw = (get_setting(SETTING_KEY, "") or "").strip().lower()
    return raw not in ("0", "false", "no", "off")


def _classify_error(exc):
    """Short, comparable reason string instead of a giant traceback repr."""
    name = type(exc).__name__
    text = str(exc).lower()
    if isinstance(exc, requests.exceptions.ConnectTimeout) or "connect timeout" in text:
        return "connect timeout"
    if isinstance(exc, requests.exceptions.ReadTimeout) or "read timed out" in text:
        return "read timeout"
    if isinstance(exc, requests.exceptions.Timeout) or "timed out" in text:
        return "timeout"
    if isinstance(exc, requests.exceptions.SSLError) or "certificate" in text or "ssl" in text:
        return "tls error"
    if "name or service not known" in text or "nodename nor servname" in text \
            or "failed to resolve" in text or "getaddrinfo" in text:
        return "dns failure"
    if "connection refused" in text:
        return "connection refused"
    if "too many redirects" in text:
        return "redirect loop"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection failed"
    return name[:40]


def ping_site(site_url):
    """Ping one URL. Returns (status_code|None, elapsed_ms, error|None)."""
    url = (site_url or "").strip()
    if not url:
        return None, None, "no url"
    if "://" not in url:
        url = "https://" + url
    host = url.split("://", 1)[1].split("/", 1)[0].lower()
    if host.endswith(".onion") or host.endswith(".i2p"):
        # Needs Tor/I2P routing this process does not have; reporting it is more
        # useful than timing out against it every hour.
        return None, None, "needs tor/i2p proxy"

    headers = {"User-Agent": _USER_AGENT, "Accept": "*/*"}
    started = time.perf_counter()
    try:
        # allow_redirects=False: show the status of the URL AS LISTED, so a moved
        # or redirect-to-login site is visible rather than masked as 200.
        response = requests.head(
            url, timeout=TIMEOUT_SECONDS, allow_redirects=False, headers=headers
        )
        # Plenty of imageboards do not implement HEAD properly.
        if response.status_code in (400, 401, 403, 405, 500, 501, 502, 503):
            response = requests.get(
                url, timeout=TIMEOUT_SECONDS, allow_redirects=False,
                headers=headers, stream=True,
            )
            response.close()
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return response.status_code, elapsed_ms, None
    except Exception as exc:
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        return None, elapsed_ms, _classify_error(exc)


def ping_hosts(pairs):
    """Ping [(host, site_url)] concurrently and store the results.

    Requests run in a pool, but every DB write happens on THIS thread — the
    SQLAlchemy session is not shared across threads.
    """
    if not pairs:
        return 0
    results = []
    workers = max(1, min(MAX_WORKERS, len(pairs)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(ping_site, site_url): (host, site_url) for host, site_url in pairs
        }
        for future in concurrent.futures.as_completed(futures):
            host, site_url = futures[future]
            try:
                status, elapsed_ms, error = future.result()
            except Exception as exc:
                status, elapsed_ms, error = None, None, _classify_error(exc)
            results.append((host, site_url, status, elapsed_ms, error))

    stored = 0
    for host, site_url, status, elapsed_ms, error in results:
        try:
            record_ping(host, site_url, status_code=status, elapsed_ms=elapsed_ms, error=error)
            stored += 1
        except Exception:
            db.session.rollback()
            app.logger.exception("chan ping: could not record result for %s", host)
    return stored


def run_chan_ping(limit=None, max_age_minutes=None, only_host=None, force=False):
    """Ping the chans that are due (or one specific host). Returns the count.

    `force=True` bypasses the leader gate for operator-initiated runs.
    """
    if not ping_enabled() and only_host is None:
        return 0
    if only_host is None and not force:
        # Leader-gated for the PERIODIC SWEEP only. Without a gate this ran in all
        # four workers, so ~300 remote sites were pinged four times per cycle at
        # 25 hosts x a 10s timeout each.
        #
        # `force` is essential, not decorative: the admin "ping all" button posts
        # no host, so gating on `only_host is None` alone would make that button
        # silently do nothing in the three non-leader workers.
        from services.singleton_worker import is_maintenance_leader

        if not is_maintenance_leader():
            return 0
    from services.chan_board_discovery import known_chan_sites

    sites = known_chan_sites()
    if only_host:
        wanted = (only_host or "").strip().lower()
        pairs = [(h, u) for h, u in sites if h == wanted]
    else:
        pairs = hosts_due_for_ping(
            sites,
            limit=limit or BATCH_SIZE,
            max_age_minutes=MAX_AGE_MINUTES if max_age_minutes is None else max_age_minutes,
        )
    return ping_hosts(pairs)


def _loop(flask_app):
    with flask_app.app_context():
        while not _stop.is_set():
            try:
                run_chan_ping()
            except Exception:
                flask_app.logger.exception("chan ping sweep failed")
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass
            _stop.wait(timeout=max(60, _SWEEP_INTERVAL_SECONDS))


def start_chan_ping(flask_app):
    """Start the periodic ping sweep once per process."""
    global _thread
    with _lock:
        if _thread is not None and _thread.is_alive():
            return False
        _thread = threading.Thread(
            target=_loop, args=(flask_app,), name="chan-ping", daemon=True
        )
        _thread.start()
        return True


__all__ = [
    "BATCH_SIZE", "SETTING_KEY", "ping_enabled", "ping_hosts", "ping_site",
    "run_chan_ping", "start_chan_ping",
]
