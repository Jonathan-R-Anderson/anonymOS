"""NNTPChan pull sync: read enabled peers, import mapped newsgroups.

A background thread runs `sync_once` every `nntpchan_sync_interval_minutes`
(sysop-configurable on the admin dashboard; 0 disables). `sync_now` runs one
pass on demand. For each enabled peer we list its overchan groups, and for each
group mapped to a local board we pull the most recent articles, dedup by
Message-ID, import OPs before replies (so replies find their thread), and
commit per group. Media hash-blocking and the address blocklist are enforced
inside importer.import_article.
"""
import os
import threading
import time as _time

import shared
from shared import app, db
from model.SiteSetting import get_setting
from model.NntpPeer import list_peers, record_peer_result
from model.NntpGroupMap import list_group_maps
from model.NntpArticle import is_message_seen
from services.nntpchan.client import NNTPClient, NNTPError
from services.nntpchan.overchan import parse_article
from services.nntpchan.importer import import_article
from model.NntpDeletedThread import is_thread_tombstoned, purge_expired_tombstones

import re as _re
_MID_RE = _re.compile(r"<[^<>]+>")


def _root_from_over(references, message_id):
    """Thread root from an OVER row: first Message-ID in References, else self."""
    match = _MID_RE.search(references or "")
    return match.group(0) if match else message_id


INTERVAL_SETTING = "nntpchan_sync_interval_minutes"
DEFAULT_INTERVAL_MINUTES = 30
# Bounded per cycle so one sync can't fetch/decode a huge batch of large
# articles and starve the web workers (the "async queue is full" crash). Small +
# frequent beats big + rare; dedup means nothing is re-fetched.
MAX_ARTICLES_PER_GROUP = 20
_IDLE_SLEEP_SECONDS = 600
# Distinct from the aggregator (741311) and video-offload advisory locks so the
# NNTP sync elects its OWN single leader worker instead of running in all four.
NNTPCHAN_ADVISORY_LOCK_ID = 741321

# Only one sync runs at a time per worker: a "Sync now" click or an overlapping
# cycle is skipped instead of stacking heavy work onto the gevent hub.
_sync_running = threading.Lock()
_lock_connection = None
_lock_owner = None


def sync_interval_seconds():
    raw = get_setting(INTERVAL_SETTING, str(DEFAULT_INTERVAL_MINUTES))
    try:
        minutes = int(str(raw).strip())
    except (TypeError, ValueError):
        minutes = DEFAULT_INTERVAL_MINUTES
    return max(0, minutes) * 60  # 0 => disabled


def nntp_should_run():
    """True only in the single worker holding the NNTP sync advisory lock, so
    the background loop runs once cluster-wide, not once per uwsgi worker.
    (SQLite/dev: always the single leader.)"""
    global _lock_connection, _lock_owner
    from services.aggregator_sync.state import (
        _open_background_sync_connection, _set_connection_autocommit, _close_raw_connection,
    )
    try:
        backend = db.engine.url.get_backend_name()
    except Exception:
        backend = "postgresql"
    if backend not in ("postgresql", "postgres"):
        return True
    if _lock_connection is not None:
        try:
            cursor = _lock_connection.cursor(); cursor.execute("SELECT 1"); cursor.close()
            return True
        except Exception:
            try:
                _close_raw_connection(_lock_connection)
            except Exception:
                pass
            _lock_connection = None; _lock_owner = None
    raw = None
    try:
        raw = _open_background_sync_connection()
        _set_connection_autocommit(raw, True)
        cursor = raw.cursor()
        cursor.execute("SELECT pg_try_advisory_lock(%s)", (NNTPCHAN_ADVISORY_LOCK_ID,))
        row = cursor.fetchone(); cursor.close()
        if row and row[0]:
            _lock_connection = raw
            owner = "pid-%s" % os.getpid()
            if _lock_owner != owner:
                _lock_owner = owner
                app.logger.info("NNTPChan: worker %s acquired the sync advisory lock", owner)
            return True
        _close_raw_connection(raw)
        return False
    except Exception:
        if raw is not None:
            try:
                _close_raw_connection(raw)
            except Exception:
                pass
        return False


def _group_board_index():
    index = {}
    for group_map in list_group_maps(enabled_only=True):
        index.setdefault(group_map.newsgroup, []).append(group_map.board_id)
    return index


def _ingest_banlist_group(client, group, stats):
    from services.nntpchan import banlist
    from model.BannedImageFingerprint import remote_ban_seen
    try:
        _count, first, last = client.group(group)
    except NNTPError:
        return
    if last <= 0 or last < first:
        return
    start = max(first, last - MAX_ARTICLES_PER_GROUP + 1)
    for _artnum, message_id, _references in client.over_message_ids(start, last):
        if remote_ban_seen(message_id):
            continue  # already ingested (dedup by Message-ID)
        raw = client.article(message_id)
        if not raw:
            continue
        parsed = parse_article(raw)
        if parsed is None:
            continue
        try:
            if banlist.ingest_ban_article(parsed):
                stats["ingested_bans"] += 1
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan: banlist ingest failed for %s", parsed.message_id)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()


def _sync_peer(peer, group_index, stats):
    from services.nntpchan import banlist
    banlist_group = banlist.banlist_group()
    with NNTPClient(peer.host, peer.port, peer.use_tls) as client:
        # Broadcast our own pending distance-bans first; one accepted POST is
        # enough since NNTP flooding propagates it across the mesh.
        try:
            stats["broadcast"] += banlist.broadcast_pending(client)
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan: banlist broadcast failed")

        # Publish our own local posts (outbound content federation) so the other
        # instance can pull and import them. No-op unless publishing is enabled.
        try:
            from services.nntpchan import publisher
            stats["published"] += publisher.publish_pending(client)
        except Exception:
            db.session.rollback()
            app.logger.exception("NNTPChan: content publish failed")

        # Pull every MAPPED newsgroup (+ the banlist group) directly. We do NOT
        # gate on list_overchan_groups() — that discovery list only surfaces
        # overchan.* groups, so a group the operator explicitly mapped but that
        # isn't under overchan.* (e.g. "syndichan.random") would never be pulled.
        # Attempting GROUP resolves existence: a group the peer doesn't carry
        # returns 411 and client.group() raises NNTPError, which we skip.
        groups_to_pull = set(group_index.keys())
        if banlist_group:
            groups_to_pull.add(banlist_group)

        for group in sorted(groups_to_pull):
            if group == banlist_group and group not in group_index:
                _ingest_banlist_group(client, group, stats)
                continue
            try:
                _count, first, last = client.group(group)
            except NNTPError:
                continue
            if last <= 0 or last < first:
                continue
            start = max(first, last - MAX_ARTICLES_PER_GROUP + 1)
            pairs = client.over_message_ids(start, last)

            articles = []
            for _artnum, message_id, references in pairs:
                if is_message_seen(message_id):
                    continue
                # Skip (without fetching) a thread a moderator deleted here — its
                # tombstone blocks re-import until the retention window lapses.
                if is_thread_tombstoned(_root_from_over(references, message_id)):
                    stats["tombstoned"] = stats.get("tombstoned", 0) + 1
                    continue
                raw = client.article(message_id)
                if not raw:
                    continue
                parsed = parse_article(raw)
                if parsed is not None:
                    articles.append(parsed)

            if not articles:
                continue

            # OPs first so replies in the same batch can attach to their thread.
            roots = [a for a in articles if a.is_root]
            replies = [a for a in articles if not a.is_root]
            for board_id in group_index.get(group, []):
                for parsed in roots + replies:
                    try:
                        result = import_article(parsed, board_id)
                    except Exception:
                        db.session.rollback()
                        app.logger.exception(
                            "NNTPChan: import failed for %s", parsed.message_id
                        )
                        continue
                    if result in stats:
                        stats[result] += 1
                    if result in ("imported", "blocked"):
                        stats["affected_boards"].add(board_id)
                    _time.sleep(0)  # release the GIL so web workers keep serving
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    app.logger.exception("NNTPChan: commit failed for group %s", group)


def sync_once():
    """Run one sync pass, but never overlap another already in progress on this
    worker (a stacked 'Sync now' or a slow cycle would pile heavy work onto the
    gevent hub and exhaust the async queue)."""
    if not _sync_running.acquire(blocking=False):
        app.logger.info("NNTPChan: a sync is already running; skipping this trigger")
        return {"imported": 0, "blocked": 0, "published": 0, "broadcast": 0,
                "ingested_bans": 0, "affected_boards": set(), "skipped_busy": True}
    try:
        return _sync_once_impl()
    finally:
        _sync_running.release()


def _sync_once_impl():
    peers = list_peers(enabled_only=True)
    group_index = _group_board_index()
    stats = {"imported": 0, "blocked": 0, "skipped": 0, "deferred": 0,
             "error": 0, "affected_boards": set(), "broadcast": 0, "ingested_bans": 0,
             "published": 0, "peers": len(peers), "groups": len(group_index)}
    # Expire old deleted-thread tombstones so a long-ago deletion no longer
    # blocks a thread the peer still carries.
    try:
        removed = purge_expired_tombstones()
        if removed:
            db.session.commit()
    except Exception:
        db.session.rollback()

    # Refresh the public catalogue BEFORE the peer check, because it describes
    # OUR hub and has nothing to do with whether we pull from anyone. Doing it
    # at the end of the pass meant it never ran at all on this deployment: there
    # are no peers configured, so the early return below fires every time and
    # the federation page would have advertised an empty hub forever.
    _refresh_hub_catalog(stats)

    # Proceed as long as there is a peer: even with no content newsgroups mapped
    # we still broadcast our distance-bans and ingest the banlist group.
    if not peers:
        return stats

    for peer in peers:
        error = None
        try:
            _sync_peer(peer, group_index, stats)
        except Exception as exc:
            error = exc
            db.session.rollback()
            app.logger.exception("NNTPChan: sync failed for peer %s:%s", peer.host, peer.port)
        try:
            record_peer_result(peer, error)
            db.session.commit()
        except Exception:
            db.session.rollback()

    if stats["affected_boards"]:
        try:
            from thread import invalidate_board_cache
            for board_id in stats["affected_boards"]:
                invalidate_board_cache(board_id)
        except Exception:
            app.logger.exception("NNTPChan: cache invalidation failed")

    return stats


def _refresh_hub_catalog(stats):
    """Cache what our hub carries, for the public federation page.

    In the background loop, never in a request: an NNTP round trip inside a
    page render is the shape that once hung GET / on an inline news sync and
    read as the whole site being down.
    """
    try:
        from services.nntpchan.hub_catalog import refresh as refresh_catalog

        record = refresh_catalog()
        stats["hub_groups"] = len(record.get("groups") or [])
    except Exception:
        app.logger.exception("NNTPChan: hub catalogue refresh failed")


def sync_now():
    """Run one sync pass inside an app context (for the admin 'sync now' button)."""
    with app.app_context():
        return sync_once()


def start_background_sync(flask_app):
    def _loop():
        _time.sleep(120)  # let the app fully settle before the first sync
        while True:
            interval = 0
            try:
                with flask_app.app_context():
                    interval = sync_interval_seconds()
                    # Only the elected leader worker syncs — never all four.
                    if interval > 0 and nntp_should_run():
                        stats = sync_once()
                        if (stats.get("imported") or stats.get("blocked")
                                or stats.get("broadcast") or stats.get("ingested_bans")
                                or stats.get("published")):
                            flask_app.logger.info(
                                "NNTPChan: imported %d, blocked %d across %d board(s); "
                                "published %d; banlist broadcast %d, ingested %d",
                                stats["imported"], stats["blocked"],
                                len(stats["affected_boards"]),
                                stats.get("published", 0),
                                stats.get("broadcast", 0), stats.get("ingested_bans", 0),
                            )
            except Exception:
                try:
                    with flask_app.app_context():
                        db.session.rollback()
                except Exception:
                    pass
                flask_app.logger.exception("NNTPChan: sync loop iteration failed")
            _time.sleep(interval if interval > 0 else _IDLE_SLEEP_SECONDS)

    shared.spawn_native_thread(target=_loop, name="nntpchan-sync", daemon=True)


def preflight():
    """What NNTPChan needs before it can do anything, and whether it has it.

    Written because the admin card cheerfully accepted peers and reported "sync
    started" on a deployment where syncing was impossible: NNTPChan peers are
    I2P destinations, reaching one needs a SOCKS proxy, and nothing anywhere
    said the proxy was absent. An operator adding peers into a void has no way
    to tell that from an empty network.

    Every check is cheap and read-only, so the card can run them on load.
    """
    import os
    import socket

    from model.NntpPeer import list_peers

    checks = []

    peers = list_peers(enabled_only=True)
    i2p_peers = [p for p in peers if p.transport == "i2p"]

    checks.append((
        "Enabled peers", bool(peers),
        "%d enabled (%d over I2P, %d clearnet)"
        % (len(peers), len(i2p_peers), len(peers) - len(i2p_peers)) if peers else
        "None. Add at least one peer below — a .b32.i2p destination, or an "
        "ordinary NNTP host if you are federating over the open internet.",
    ))

    # Only required if something actually needs it. Demanding an I2P router on a
    # deployment federating over the clearnet would report a fault that is not
    # one, and a checklist that cries wolf gets ignored on the day it is right.
    if i2p_peers:
        raw = (os.getenv("I2P_SOCKS_PROXY") or "127.0.0.1:4447").strip()
        host, _, port = raw.rpartition(":")
        detail = "I2P_SOCKS_PROXY=%s%s" % (
            raw, "" if os.getenv("I2P_SOCKS_PROXY") else " (default; the variable is not set)")
        try:
            probe = socket.create_connection((host or "127.0.0.1", int(port or 4447)), timeout=4)
            probe.close()
            checks.append(("I2P SOCKS proxy", True, detail))
        except Exception as exc:
            checks.append((
                "I2P SOCKS proxy", False,
                "%s — %s. %d peer(s) are .b32.i2p destinations and cannot be "
                "reached without it." % (detail, exc, len(i2p_peers)),
            ))

    groups = _group_board_index()
    checks.append((
        "Newsgroups mapped to boards", bool(groups),
        "%d mapped" % len(groups) if groups else
        "None. Articles have nowhere to land, so nothing will be imported even "
        "from a working peer.",
    ))

    clearnet = [p for p in peers if p.transport != "i2p"]
    return {
        "checks": [{"name": n, "ok": ok, "detail": d} for n, ok, d in checks],
        "ready": all(ok for _, ok, _ in checks),
        # Surfaced separately from the checks because it is not a fault to fix.
        # It is a property of the configuration the operator chose, and they
        # should be able to see it without it being flagged as an error.
        "clearnet_peers": len(clearnet),
    }
