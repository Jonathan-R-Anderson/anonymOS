"""Discover which boards each aggregated chan hosts, and keep it fresh.

Split of responsibilities:
  * the generic scraper does the HTTP (GET /sites/boards) -- it already owns the
    machinery for fetching hostile imageboards: Tor, backoff, PoW/challenge
    handling, and BeautifulSoup. The backend has none of that and no HTML parser.
  * this module schedules the scans and caches results in Postgres
    (model/ChanBoard.py), which the admin board picker reads.

Scheduling: chans never scanned are done first, then any whose last scan is older
than REFRESH_INTERVAL_DAYS (7). Only a handful are scanned per pass, spread over
the background loop, because a scan is one request for the board list plus one
per board to read its <title> -- doing ~300 sites at once would be a stampede.

EVERYTHING HERE RUNS IN A BACKGROUND THREAD. Never call scan_due_chans() from a
request handler: an inline scan blocked the front page once before (see the
front-page render-blocking incident) and this one makes far more network calls.
"""
import datetime as _datetime
import os
import threading

import requests

from model.ChanBoard import (
    REFRESH_INTERVAL_DAYS,
    apply_scan_result,
    hosts_due_for_scan,
    record_scan_failure,
)
from shared import app, db

# Chans scanned per pass. Small on purpose: each is many HTTP requests.
DEFAULT_BATCH_SIZE = 5
# One scan can be slow (board list + a title fetch per board), so allow for it.
SCAN_TIMEOUT_SECONDS = float(os.getenv("CHAN_BOARD_SCAN_TIMEOUT", "180"))
# How often the loop wakes. The per-chan interval is what actually paces rescans.
LOOP_INTERVAL_SECONDS = int(os.getenv("CHAN_BOARD_SCAN_LOOP_SECONDS", "3600"))

_loop_thread = None
_loop_lock = threading.Lock()


def _generic_scraper_url():
    return (os.getenv("GENERIC_AGGREGATOR_URL") or "").strip().rstrip("/") or None


def _host_of(site_url):
    """Host for a chan URL. Must match the scraper's runtime.site_host_slug()."""
    raw = (site_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    from urllib.parse import urlparse
    host = (urlparse(raw).netloc or "").lower().split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return "".join(ch for ch in host if ch.isalnum() or ch in ".-")


def known_chan_sites():
    """[(host, site_url)] from the aggregated-chan list."""
    from model.Federation import AggregatedChan

    sites = []
    seen = set()
    for (url,) in db.session.query(AggregatedChan.url).all():
        host = _host_of(url)
        if not host or host in seen:
            continue
        seen.add(host)
        sites.append((host, (url or "").strip().rstrip("/")))
    return sites


def scan_chan(host, site_url, fetch_titles=True):
    """Scan one chan and update the local cache. Returns a summary dict."""
    base = _generic_scraper_url()
    if not base:
        record_scan_failure(host, site_url, "GENERIC_AGGREGATOR_URL is not configured")
        return {"host": host, "ok": False, "error": "no scraper configured"}
    try:
        response = requests.get(
            "%s/sites/boards" % base,
            params={"site": site_url, "titles": "1" if fetch_titles else "0"},
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        response.raise_for_status()
        payload = response.json() or {}
        boards = payload.get("boards") or []
    except Exception as exc:
        record_scan_failure(host, site_url, exc)
        app.logger.info("chan board scan failed for %s: %s", host, exc)
        return {"host": host, "ok": False, "error": str(exc)}

    if not boards:
        # Treat "nothing found" as a failed scan, NOT as "every board was
        # deleted" — otherwise a site behind Cloudflare wipes its cached list.
        record_scan_failure(host, site_url, "no boards discovered")
        return {"host": host, "ok": False, "error": "no boards discovered", "boards": 0}

    added, updated, removed = apply_scan_result(host, site_url, boards)
    if added or removed:
        app.logger.info(
            "chan board scan %s: %d board(s) (+%d new, %d gone)",
            host, len(boards), added, removed,
        )
    return {
        "host": host, "ok": True, "boards": len(boards),
        "added": added, "updated": updated, "removed": removed,
    }


def scan_due_chans(limit=DEFAULT_BATCH_SIZE, interval_days=REFRESH_INTERVAL_DAYS):
    """Scan the chans that are due. Returns a list of per-chan summaries."""
    try:
        due = hosts_due_for_scan(known_chan_sites(), limit=limit, interval_days=interval_days)
    except Exception:
        db.session.rollback()
        app.logger.exception("could not determine which chans need a board scan")
        return []
    results = []
    for host, site_url in due:
        try:
            results.append(scan_chan(host, site_url))
        except Exception:
            db.session.rollback()
            app.logger.exception("chan board scan crashed for %s", host)
    return results


def _loop():
    with app.app_context():
        while True:
            try:
                from services.singleton_worker import is_maintenance_leader

                # Leader-gated: a scan can hold a connection for up to
                # DEFAULT_BATCH_SIZE x SCAN_TIMEOUT_SECONDS, and running it in all
                # four workers quadrupled both that and the load on remote sites.
                if is_maintenance_leader():
                    scan_due_chans()
            except Exception:
                app.logger.exception("chan board discovery pass failed")
            finally:
                # A long-lived background thread must not hold a session open;
                # the next pass gets a fresh one.
                try:
                    db.session.remove()
                except Exception:
                    pass
            _stop.wait(timeout=max(60, LOOP_INTERVAL_SECONDS))


_stop = threading.Event()


def start_background_discovery():
    """Start the weekly board-rescan loop once per process.

    Called from app startup. Returns True if this call started the thread.
    """
    global _loop_thread
    if (os.getenv("CHAN_BOARD_DISCOVERY", "true") or "").strip().lower() in ("0", "false", "no"):
        return False
    with _loop_lock:
        if _loop_thread is not None and _loop_thread.is_alive():
            return False
        _loop_thread = threading.Thread(
            target=_loop, name="chan-board-discovery", daemon=True
        )
        _loop_thread.start()
        return True


__all__ = [
    "DEFAULT_BATCH_SIZE", "known_chan_sites", "scan_chan", "scan_due_chans",
    "start_background_discovery",
]
