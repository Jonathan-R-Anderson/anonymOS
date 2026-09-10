"""
scraper_client.py — HTTP client for the thread scraper services.

Scrapers no longer crawl whole boards or subreddits. Each scraper exposes a
thread registry, and only registered threads are fetched and kept fresh:
  GET  /threads                        → {"threads": [{"board": ..., "thread_id": ...}]}
  POST /threads                        → {"board": "<name>", "thread_id": "<id>"} →
                                         registers a thread, triggers an immediate fetch
  DELETE /threads/<board>/<thread_id>  → removes a thread and its stored posts

Environment variables:
  FOURCHAN_AGGREGATOR_URL e.g. http://fourchan-aggregator:8000
  EIGHTCHAN_AGGREGATOR_URL e.g. http://eightchan-aggregator:8000
  SEVENCHAN_AGGREGATOR_URL e.g. http://sevenchan-aggregator:8000
  REDDIT_AGGREGATOR_URL e.g. http://reddit-aggregator:8000
"""

import logging
import os
from typing import List, Optional, Tuple
from urllib.parse import quote, urlparse, urlunparse

import requests

log = logging.getLogger(__name__)

_TIMEOUT = 5  # seconds
_DOCKER_SERVICE_URLS = {
    "4chan": "http://fourchan-aggregator:8000",
    "8chan": "http://eightchan-aggregator:8000",
    "7chan": "http://sevenchan-aggregator:8000",
    "reddit": "http://reddit-aggregator:8000",
    "generic": "http://generic-aggregator:8000",
}


def _configured_url(env_name: str) -> "Optional[str]":
    value = (os.getenv(env_name) or "").strip().rstrip("/")
    return value or None


def _running_in_docker() -> bool:
    return os.path.exists("/.dockerenv")


def _running_in_kubernetes() -> bool:
    """Kubernetes has no /.dockerenv.

    That file is created by the Docker daemon; under k3s/containerd it does not
    exist, so _running_in_docker() is False in the cluster. The loopback-rewrite
    below was therefore skipped in production and the stale development .env
    values (localhost:8002-8005) were used verbatim -- which is exactly what the
    admin page reported as "scraper unreachable" while every aggregator was
    healthy and answering on its service name.
    """
    return bool(os.getenv("KUBERNETES_SERVICE_HOST"))


def _prefer_internal_service_url(source_type: str, base_url: "Optional[str]") -> "Optional[str]":
    # Rewrite under EITHER runtime. Keying only on Docker meant Kubernetes fell
    # through to whatever loopback value .env happened to carry.
    if not base_url or not (_running_in_docker() or _running_in_kubernetes()):
        return base_url
    try:
        parsed = urlparse(base_url)
    except Exception:
        return base_url
    if parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        return base_url
    # Generic aggregated chans use their HOST as the source_type ("lainchan.org"),
    # and all of them are served by the one shared generic scraper -- so they
    # must map to the generic service rather than falling through unrewritten.
    replacement = _DOCKER_SERVICE_URLS.get(source_type)
    if not replacement and _is_generic_source_type(source_type):
        replacement = _DOCKER_SERVICE_URLS.get("generic")
    if not replacement:
        return base_url
    replacement_parts = urlparse(replacement)
    rewritten = parsed._replace(
        scheme=replacement_parts.scheme,
        netloc=replacement_parts.netloc,
    )
    return urlunparse(rewritten).rstrip("/")


def _url_for(source_type: str) -> "Optional[str]":
    """Return the base URL for a scraper type, or None if unconfigured.

    ONE crawler now, for every source. 4chan, 8kun and 7chan each had their own
    container differing only by a ConfigMap — their own manifests said so — and
    Reddit had a separate 2,900 line program because the parsing selectors were
    module constants that could not bend. Both of those are fixed in the
    crawler: selectors are per-site profiles, and mirror rotation and
    proof-of-work solving moved across with Reddit.

    The legacy per-site variables are still read as a FALLBACK. An operator
    mid-upgrade, or a deployment that has not applied the new manifests, keeps
    working instead of losing every source at once — and a stale variable
    pointing at a container that no longer exists simply fails over to the
    generic URL rather than being an outage nobody can explain.
    """
    generic = _configured_url("GENERIC_AGGREGATOR_URL")
    legacy = {
        "4chan": "FOURCHAN_AGGREGATOR_URL",
        "8chan": "EIGHTCHAN_AGGREGATOR_URL",
        "7chan": "SEVENCHAN_AGGREGATOR_URL",
        "reddit": "REDDIT_AGGREGATOR_URL",
    }.get(source_type)
    if legacy:
        return _prefer_internal_service_url(
            source_type, _configured_url(legacy) or generic)
    # Generic aggregated-chan site (source_type is its host): served by the one
    # shared crawler, which crawls any site it is pointed at.
    if _is_generic_source_type(source_type):
        return _prefer_internal_service_url(source_type, generic)
    return None


def _is_generic_source_type(source_type: str) -> bool:
    value = (source_type or "").strip().lower()
    if not value or value in _DOCKER_SERVICE_URLS or value == "local":
        return False
    return "." in value and "/" not in value and " " not in value


def reset_storage(source_type: str) -> bool:
    """Tell the scraper to recreate its local SQLite storage.

    Returns True on success, False if the scraper is unreachable or unconfigured.
    """
    base = _url_for(source_type)
    if not base:
        log.debug("scraper_client: no URL configured for %s, skipping reset", source_type)
        return False
    try:
        r = requests.post(f"{base}/reset", timeout=_TIMEOUT)
        r.raise_for_status()
        log.info("scraper_client: reset %s storage → %s", source_type, r.json())
        return True
    except Exception as exc:
        log.warning("scraper_client: could not reset %s storage: %s", source_type, exc)
        return False


def register_thread(source_type: str, name: str, thread_id: str) -> bool:
    """Tell the scraper to fetch *thread_id* on *name* and keep it fresh.

    Returns True on success, False if the scraper is unreachable or unconfigured.
    """
    base = _url_for(source_type)
    if not base:
        log.debug("scraper_client: no URL configured for %s, skipping register", source_type)
        return False
    # "*" means "follow the whole board" and is not a thread id. Guarded here too
    # so no caller can turn it into a 400 -> storage-reset cascade.
    if str(thread_id) == "*":
        log.debug("scraper_client: skipping whole-board source %s/%s", source_type, name)
        return False
    # NEVER register a generic aggregated-chan thread this way. POST /threads puts
    # the thread in the shared generic scraper's global monitor pool, and that pool
    # is keyed (board, thread_id) with NO site component — so a worker picks it up
    # with no site bound, falls back to the container's placeholder BASE_URL and
    # fetches https://example.invalid/<board>/thread/<id>. Generic sites are crawled
    # by the monitored-board pass (which binds the site), so registration is both
    # unnecessary and actively harmful here.
    if _is_generic_source_type(source_type):
        log.debug(
            "scraper_client: not registering %s/%s/%s — generic sites are crawled "
            "via monitored boards, not the thread pool",
            source_type, name, thread_id,
        )
        return False
    payload = {"board": name, "thread_id": str(thread_id)}
    try:
        r = requests.post(f"{base}/threads", json=payload, timeout=_TIMEOUT)
        r.raise_for_status()
        log.info("scraper_client: registered %s/%s/%s → %s", source_type, name, thread_id, r.json())
        return True
    except Exception as exc:
        log.warning(
            "scraper_client: initial register failed for %s/%s/%s: %s",
            source_type, name, thread_id, exc,
        )
        # NEVER reset storage on a 4xx. A 4xx means this request was invalid, not
        # that the scraper's database is broken, and /reset wipes its runtime
        # state (active boards included) so it stops crawling entirely. Only a
        # transport/5xx failure is even arguably a storage problem.
        status = getattr(getattr(exc, "response", None), "status_code", None)
        if status is not None and 400 <= status < 500:
            log.warning(
                "scraper_client: %s rejected %s/%s/%s with HTTP %s — not resetting storage",
                source_type, source_type, name, thread_id, status,
            )
            return False
        if reset_storage(source_type):
            try:
                r = requests.post(f"{base}/threads", json=payload, timeout=_TIMEOUT)
                r.raise_for_status()
                log.info(
                    "scraper_client: registered %s/%s/%s after storage reset → %s",
                    source_type,
                    name,
                    thread_id,
                    r.json(),
                )
                return True
            except Exception as retry_exc:
                log.warning(
                    "scraper_client: could not register %s/%s/%s after storage reset: %s",
                    source_type,
                    name,
                    thread_id,
                    retry_exc,
                )
        return False


def unregister_thread(source_type: str, name: str, thread_id: str) -> bool:
    """Tell the scraper to stop tracking *thread_id* on *name*.

    Returns True on success, False if the scraper is unreachable or unconfigured.
    """
    base = _url_for(source_type)
    if not base:
        return False
    try:
        r = requests.delete(
            f"{base}/threads/{quote(str(name), safe='')}/{quote(str(thread_id), safe='')}",
            timeout=_TIMEOUT,
        )
        r.raise_for_status()
        log.info("scraper_client: unregistered %s/%s/%s", source_type, name, thread_id)
        return True
    except Exception as exc:
        log.warning(
            "scraper_client: could not unregister %s/%s/%s: %s",
            source_type, name, thread_id, exc,
        )
        return False


def list_threads(source_type: str) -> List[dict]:
    """Return the threads currently registered with the scraper, or [] on error."""
    base = _url_for(source_type)
    if not base:
        return []
    try:
        r = requests.get(f"{base}/threads", timeout=_TIMEOUT)
        r.raise_for_status()
        return r.json().get("threads", [])
    except Exception as exc:
        log.warning("scraper_client: could not list %s threads: %s", source_type, exc)
        return []


def get_challenge_status(source_type: str) -> Optional[dict]:
    """Return the challenge status of a scraper, or None if no challenge/error."""
    base = _url_for(source_type)
    if not base:
        return None
    try:
        r = requests.get(f"{base}/status", timeout=_TIMEOUT)
        r.raise_for_status()
        data = r.json()
        if data.get("challenge_active"):
            return {
                "active": True,
                "url": f"{base}/challenge",
            }
    except Exception:
        pass
    return None


def sync_all_threads(board_sources: List[Tuple[str, str, str]]) -> None:
    """Register every (source_type, name, thread_id) triple with its scraper.

    Called at startup so submitted threads survive scraper restarts.
    Silently skips scrapers that are unconfigured or unreachable.
    """
    for source_type, name, thread_id in board_sources:
        register_thread(source_type, name, thread_id)


def list_monitored_boards(source_type: str) -> "Optional[List[str]]":
    """Boards/subreddits THIS source continuously discovers threads on.

    Returns None when the scraper is unconfigured or unreachable, which the admin
    UI renders differently from "configured, but monitoring nothing".

    MUST filter by site. Every generic aggregated-chan source resolves to the one
    shared generic scraper, whose /boards/monitored reports the boards of ALL the
    sites it monitors. Returning that list unfiltered made every generic host in
    the admin listing show every other host's boards — the "it's conflating the
    sources" bug. Entries are objects ({site, board, site_key, db}); an earlier
    version str()'d them, so board names rendered as raw dict text too.
    """
    base = _url_for(source_type)
    if not base:
        return None
    try:
        r = requests.get(f"{base}/boards/monitored", timeout=_TIMEOUT)
        r.raise_for_status()
        payload = r.json() or {}
    except Exception as exc:
        # WARNING, not DEBUG: this is the exact condition the admin panel renders
        # as "scraper unreachable", and at DEBUG the reason is invisible in
        # production — leaving the badge with no way to tell a booting scraper
        # from a misconfigured URL from a genuine outage.
        log.warning(
            "scraper_client: %s unreachable at %s (%s: %s)",
            source_type, base, type(exc).__name__, exc,
        )
        return None

    entries = payload.get("monitored_boards")
    if isinstance(entries, list) and any(isinstance(e, dict) for e in entries):
        wanted = (source_type or "").strip().lower()
        is_generic = _is_generic_source_type(source_type)
        boards = []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            board = str(entry.get("board") or "").strip().strip("/")
            if not board:
                continue
            site = (entry.get("site") or "").strip()
            site_key = str(entry.get("site_key") or "").strip().lower()
            if is_generic:
                # Only this host's own boards.
                if site_key != wanted:
                    continue
            elif site:
                # A dedicated scraper owns only its un-sited entries; anything
                # carrying a site belongs to some other site entirely.
                continue
            if board not in boards:
                boards.append(board)
        return boards

    # Older crawler: a flat list of board names for the container's own site.
    legacy = payload.get("boards")
    if isinstance(legacy, list):
        return [str(b).strip().strip("/") for b in legacy if isinstance(b, str) and str(b).strip()]
    return []


def add_monitored_board(source_type: str, board: str, site: str = None) -> bool:
    """Start continuous monitoring of a board/subreddit on this scraper.

    `site` is the remote site's base URL, required for generic aggregated-chan
    sources so the shared generic scraper knows which site to crawl. The built-in
    scrapers ignore it (their base URL is fixed by their container's env).
    """
    base = _url_for(source_type)
    if not base:
        return False
    payload = {"board": board}
    if site:
        payload["site"] = site
    try:
        r = requests.post(
            f"{base}/boards/monitored", json=payload, timeout=_TIMEOUT
        )
        r.raise_for_status()
        log.info("scraper_client: monitoring %s:%s", source_type, board)
        return True
    except Exception as exc:
        log.warning("scraper_client: could not monitor %s:%s → %s", source_type, board, exc)
        return False


def remove_monitored_board(source_type: str, board: str, site: str = None) -> bool:
    """Stop discovering new threads on a board/subreddit."""
    base = _url_for(source_type)
    if not base:
        return False
    url = f"{base}/boards/monitored/{quote(str(board), safe='')}"
    if site:
        url += "?site=" + quote(str(site), safe="")
    try:
        r = requests.delete(url, timeout=_TIMEOUT)
        r.raise_for_status()
        return True
    except Exception as exc:
        log.warning("scraper_client: could not unmonitor %s:%s → %s", source_type, board, exc)
        return False
