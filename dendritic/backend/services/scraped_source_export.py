"""Export every configured scrape source as one reviewable text file.

WHY
---
Reviewing sources by hand takes hours: there are ~112 `board_source` rows across
~25 sites, and judging whether one is actually working means cross-checking four
separate places — is a scraper crawling it, has it imported anything, is the
remote site even reachable, and has it been retired. This renders all of that as
one sorted text file so the broken ones are visible at a glance.

GRANULARITY: one line per (site, remote board, local board)
-----------------------------------------------------------
NOT one line per `board_source` row. The dedicated scrapers store one row per
submitted THREAD — `4chan` has 30 rows that are really "6 boards with N threads
each" — and imported-thread counts are keyed by (source_type, source_name), so a
per-row file would repeat the same count 12 times and read as 12 separate
problems. Individual threads are collapsed into the MODE column instead.

The local board is part of the key because one remote board legitimately feeds
several local boards (`4chan /pol/` targets both `/pol/` and `/thug/`), and those
are genuinely different things to review.

NO NETWORK I/O. NOT EVEN ONE REQUEST.
-------------------------------------
Reachability comes from the CACHED ping columns on `chan_board_scan`, written by
the background sweep in services/chan_ping.py. This module must never ping,
fetch, or call a scraper endpoint: it is reachable from an admin request handler,
and doing network work while holding a DB connection is precisely what exhausted
the connection pool on 2026-07-26. `chan_ping.py` carries the same warning for
the same reason.

EVERY EXTERNAL READ MUST FAIL SOFT
----------------------------------
16 of the 21 configured generic hosts have no scraper SQLite at all. That
condition is a HEADLINE RESULT here (verdict NEVER-CRAWLED), not an error — a
missing, unreadable, corrupt or schema-less scraper DB must never abort the
export. (`list_source_thread_ids` used to raise
`sqlite3.OperationalError: unable to open database file` for these on every sync
cycle; it now short-circuits on os.path.exists and returns [] instead.)
"""
import datetime as _datetime
import os
import sqlite3

from model.Board import Board
from model.BoardSource import BoardSource
from model.Thread import Thread
from shared import app, db

# Verdicts, worst first. The file is sorted by this order so whatever needs
# attention is at the top and "OK" rows sink to the bottom.
# One label per source, worst-first — the file is sorted by this order so whatever
# needs attention is at the top.
#
# UNREACHABLE means "the site gave NO HTTP RESPONSE AT ALL" (DNS failure, refused,
# timeout, needs a Tor/I2P proxy). It deliberately does NOT key off
# `ChanBoardScan.ping_ok`, which is `200 <= code < 400` (model/ChanBoard.py): a
# chan that answers 403 to a bare HEAD is plainly UP, just refusing an
# unadorned request. awsumchan.org and bernd.group do exactly that while their
# scrapers read them fine, and keying on ping_ok labelled awsumchan.org /ra/
# UNREACHABLE while it was importing normally. A 403/429 therefore shows as a
# plain status code, not as an outage.
VERDICT_ORDER = [
    "UNREACHABLE",
    "NEVER-CRAWLED",
    "NOT-MONITORED",
    "NO-IMPORT",
    "STALE",
    "RETIRED",
    "OK",
]
_VERDICT_RANK = {name: index for index, name in enumerate(VERDICT_ORDER)}

# A source that imported something, but nothing recently, is STALE. Generous on
# purpose: quiet boards are normal on small chans, so this flags "probably
# broken", not "not busy".
STALE_AFTER_DAYS = int(os.getenv("SOURCE_EXPORT_STALE_DAYS", "3") or 3)

DEFAULT_EXPORT_BASENAME = "aggregated_chans.txt"


# A file that exists at the repo root and nowhere else in the tree.
_ROOT_MARKERS = ("docker-compose.yml", ".git")


def _project_root():
    """Best-effort repo root.

    Walks UP looking for a root marker rather than counting directory levels,
    because the layout differs between checkout and container:
      * repo:      backend/services/scraped_source_export.py  (root is 3 up)
      * container: /maniwani/services/scraped_source_export.py (root is 2 up)
    Counting three levels would resolve to "/" inside the container and try to
    write /aggregated_chans.txt. Falls back to the app root (the directory holding
    services/) when no marker is found, which is always writable-ish and at least
    never "/".
    """
    here = os.path.dirname(os.path.abspath(__file__))       # .../services
    app_root = os.path.dirname(here)                         # backend/ or /maniwani
    candidate = app_root
    for _ in range(4):
        if any(os.path.exists(os.path.join(candidate, m)) for m in _ROOT_MARKERS):
            return candidate
        parent = os.path.dirname(candidate)
        if not parent or parent == candidate:
            break
        candidate = parent
    return app_root


def default_export_path():
    """Where the export lands by default.

    `SCRAPED_SOURCE_EXPORT_PATH` wins, because the repo root is NOT writable or
    persistent everywhere: in this deployment the maniwani container has the code
    baked into the image rather than bind-mounted, so a file written to the repo
    root inside the container vanishes with the container.
    """
    override = (os.getenv("SCRAPED_SOURCE_EXPORT_PATH") or "").strip()
    if override:
        return override
    return os.path.join(_project_root(), DEFAULT_EXPORT_BASENAME)


# --------------------------------------------------------------------------
# scraper-side (SQLite) facts
# --------------------------------------------------------------------------

def _scraper_board_stats(source_type):
    """Per-board crawl counts from one scraper's own SQLite.

    Returns (status, {board_name: {"threads": n, "posts": n, "last": iso}}) where
    status is one of "ok" | "no-db" | "unreadable". Never raises — the caller
    needs "no data" as a reportable state, not an exception. Mirrors the
    defensive shape of scraper_db.source_thread_health().
    """
    from services.aggregator_sync.scraper_db import (
        _read_scraper_db,
        _scraper_posts_source_column,
        _sqlite_table_exists,
        aggregator_db_path,
    )

    try:
        db_path = aggregator_db_path(source_type)
    except ValueError:
        # No scraper is configured for this source_type at all.
        return "no-db", {}
    if not db_path or not os.path.exists(db_path):
        return "no-db", {}

    def _reader(connection):
        if not _sqlite_table_exists(connection, "posts"):
            return {}
        # Reddit's universal schema names this column `subreddit`; the chan
        # schema uses `board`. Ask rather than assume.
        column = _scraper_posts_source_column(connection, source_type)
        sql = (
            "SELECT %s AS source_name, COUNT(DISTINCT thread_id) AS threads, "
            "COUNT(*) AS posts, MAX(scraped_at) AS last_scraped "
            "FROM posts WHERE %s IS NOT NULL GROUP BY %s" % (column, column, column)
        )
        out = {}
        for row in connection.execute(sql).fetchall():
            name = str(row["source_name"])
            out[name] = {
                "threads": int(row["threads"] or 0),
                "posts": int(row["posts"] or 0),
                "last": row["last_scraped"],
            }
        return out

    try:
        return "ok", (_read_scraper_db(db_path, _reader) or {})
    except (sqlite3.Error, OSError) as exc:
        app.logger.debug(
            "source export: could not read scraper db for %s: %s", source_type, exc
        )
        return "unreadable", {}
    except Exception as exc:  # noqa: BLE001 - an export must never abort
        app.logger.debug(
            "source export: unexpected scraper db error for %s: %s", source_type, exc
        )
        return "unreadable", {}


# --------------------------------------------------------------------------
# maniwani-side (Postgres) facts
# --------------------------------------------------------------------------

def _imported_counts():
    """{(source_type, source_name, board_id): {threads, newest}}

    One grouped query, not one per source: with ~50 groups the N+1 version would
    be ~50 round trips for data a single GROUP BY already produces.
    """
    rows = (
        db.session.query(
            Thread.source_type,
            Thread.source_name,
            Thread.board,
            db.func.count(Thread.id),
            db.func.max(Thread.last_updated),
        )
        .filter(Thread.source_type.isnot(None), Thread.source_type != "local")
        .group_by(Thread.source_type, Thread.source_name, Thread.board)
        .all()
    )
    out = {}
    for source_type, source_name, board_id, threads, newest in rows:
        out[(source_type, source_name, board_id)] = {
            "threads": int(threads or 0),
            "newest": newest,
        }
    return out


def _ping_by_host():
    """Cached reachability per host from chan_board_scan. NEVER pings."""
    from model.ChanBoard import ChanBoardScan

    out = {}
    for row in db.session.query(ChanBoardScan).all():
        out[(row.host or "").lower()] = {
            "status_code": row.ping_status_code,
            "ok": row.ping_ok,
            "error": row.ping_error,
            "ms": row.ping_ms,
            "last_ping_at": row.last_ping_at,
            "board_count": row.board_count,
            "consecutive_failures": row.consecutive_failures or 0,
            "last_error": row.last_error,
            "site_url": row.site_url,
        }
    return out


def _group_sources():
    """Collapse board_source rows into (source_type, source_name, board) groups."""
    rows = (
        db.session.query(BoardSource, Board.name, Board.id)
        .join(Board, Board.id == BoardSource.board_id)
        .filter(BoardSource.source_type != "local")
        .all()
    )
    groups = {}
    for source, board_name, board_id in rows:
        key = (source.source_type, source.source_name, board_id)
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "source_type": source.source_type,
                "source_name": source.source_name,
                "board_id": board_id,
                "board_name": board_name,
                "whole_board": False,
                "thread_rows": 0,
                "retired_rows": 0,
                "total_rows": 0,
                "site_url": None,
                "oldest_created": None,
            }
        group["total_rows"] += 1
        if source.retired:
            group["retired_rows"] += 1
        if str(source.source_thread_id or "") == "*":
            group["whole_board"] = True
        else:
            group["thread_rows"] += 1
        if source.source_site and not group["site_url"]:
            group["site_url"] = source.source_site
        created = source.created_at
        if created and (group["oldest_created"] is None or created < group["oldest_created"]):
            group["oldest_created"] = created
    return groups


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def _site_unreachable(ping):
    """True only when the last check got NO HTTP response at all.

    A status code — any status code, including 403/429 — means the site answered
    and is therefore reachable. See VERDICT_ORDER for why this distinction is
    load-bearing.
    """
    if not ping or ping.get("last_ping_at") is None:
        return False
    return ping.get("status_code") is None and bool(ping.get("error"))


def _verdict(group, imported, crawled, db_status, ping, now):
    """Single worst-thing-first judgement for one source group."""
    # Retired is only the headline when EVERY row is retired; a partially retired
    # group is still live and should be judged on whether it imports.
    fully_retired = group["total_rows"] > 0 and group["retired_rows"] == group["total_rows"]

    imported_threads = (imported or {}).get("threads", 0)
    newest = (imported or {}).get("newest")
    recently_active = (
        newest is not None and (now - newest).days < STALE_AFTER_DAYS
    )
    # Unreachability is the ROOT CAUSE of everything downstream, so it outranks
    # the other labels — EXCEPT when content is still arriving. If a source
    # imported something recently then the site demonstrably works and it is the
    # cached ping that is wrong; observed data beats a stale probe.
    if _site_unreachable(ping) and not (imported_threads and recently_active):
        return "UNREACHABLE"

    if db_status == "no-db":
        # Nothing has ever crawled this site: the scraper SQLite does not exist.
        # This is the actionable one — it is also what spams the log with
        # "unable to open database file".
        return "RETIRED" if fully_retired else "NEVER-CRAWLED"
    if fully_retired:
        return "RETIRED"
    if db_status == "unreadable":
        return "NOT-MONITORED"
    crawled_threads = (crawled or {}).get("threads", 0)
    if not crawled_threads:
        # The scraper runs for this site but is not crawling THIS board.
        return "NOT-MONITORED"
    if not imported_threads:
        return "NO-IMPORT"
    if newest is not None and not recently_active:
        return "STALE"
    return "OK"


def _fmt_time(value):
    if not value:
        return "never"
    try:
        return value.strftime("%Y-%m-%d %H:%M")
    except AttributeError:
        text = str(value)
        return text[:16] if text else "never"


def _fmt_ping(source_type, ping):
    """Compact reachability cell."""
    from services.aggregator_sync.scraper_db import is_generic_source_type

    if not is_generic_source_type(source_type):
        # 4chan/8chan/7chan/reddit are crawled by dedicated containers whose base
        # URL is fixed in env; the chan-ping sweep does not cover them.
        return "n/a"
    if not ping or ping.get("last_ping_at") is None:
        return "unpinged"
    code = ping.get("status_code")
    if code is not None:
        # The site ANSWERED. 403/429 here means "up, but refused this bare
        # request" — normal for chans that filter on User-Agent, and not a
        # problem when the scraper reads them fine.
        return str(code)
    error = ping.get("error")
    if error:
        # No HTTP response at all: DNS failure, refused, timeout, needs Tor.
        # Prefixed so it is greppable as a real outage.
        return "DOWN:%s" % str(error)[:16]
    return "?"


def collect_rows(now=None):
    """Gather one row per source group. Pure reads; no network."""
    now = now or _datetime.datetime.utcnow()
    groups = _group_sources()
    imported = _imported_counts()
    pings = _ping_by_host()

    # One SQLite open per distinct source_type, not per row.
    db_cache = {}
    for source_type in sorted({g["source_type"] for g in groups.values()}):
        db_cache[source_type] = _scraper_board_stats(source_type)

    rows = []
    for key, group in groups.items():
        source_type, source_name, board_id = key
        db_status, board_stats = db_cache.get(source_type, ("no-db", {}))
        crawled = (board_stats or {}).get(str(source_name))
        imported_row = imported.get((source_type, source_name, board_id))
        ping = pings.get((source_type or "").lower())
        verdict = _verdict(group, imported_row, crawled, db_status, ping, now)
        rows.append({
            "verdict": verdict,
            "source_type": source_type,
            "source_name": source_name,
            "board_name": group["board_name"],
            "whole_board": group["whole_board"],
            "thread_rows": group["thread_rows"],
            "retired_rows": group["retired_rows"],
            "total_rows": group["total_rows"],
            "imported_threads": (imported_row or {}).get("threads", 0),
            "newest": (imported_row or {}).get("newest"),
            "crawled_threads": (crawled or {}).get("threads", 0),
            "crawled_posts": (crawled or {}).get("posts", 0),
            "db_status": db_status,
            "ping": ping,
            "site_url": group["site_url"] or (ping or {}).get("site_url") or "",
            "created_at": group["oldest_created"],
        })

    rows.sort(key=lambda r: (
        _VERDICT_RANK.get(r["verdict"], 99),
        r["source_type"],
        str(r["source_name"]),
        str(r["board_name"]),
    ))
    return rows


def summarize(rows):
    """Counts for the header block."""
    from services.aggregator_sync.scraper_db import is_generic_source_type

    sites = {r["source_type"] for r in rows}
    generic_sites = {s for s in sites if is_generic_source_type(s)}
    never_crawled_sites = {
        r["source_type"] for r in rows if r["db_status"] == "no-db"
        and is_generic_source_type(r["source_type"])
    }
    by_verdict = {}
    for row in rows:
        by_verdict[row["verdict"]] = by_verdict.get(row["verdict"], 0) + 1
    down_sites = sorted({
        r["source_type"] for r in rows
        if (r["ping"] or {}).get("last_ping_at") is not None
        and (r["ping"] or {}).get("status_code") is None
        and (r["ping"] or {}).get("error")
    })
    return {
        "down_sites": down_sites,
        "lines": len(rows),
        "source_rows": sum(r["total_rows"] for r in rows),
        "sites": len(sites),
        "generic_sites": len(generic_sites),
        "never_crawled_sites": len(never_crawled_sites),
        "never_crawled_site_names": sorted(never_crawled_sites),
        "importing": sum(1 for r in rows if r["imported_threads"] > 0),
        "importing_nothing": sum(1 for r in rows if r["imported_threads"] == 0),
        "retired_rows": sum(r["retired_rows"] for r in rows),
        "by_verdict": by_verdict,
    }


_LEGEND = [
    ("UNREACHABLE", "the site gave no HTTP response at all on the last check (a 403/429 is NOT this)"),
    ("NEVER-CRAWLED", "no scraper database for this site at all — nothing has ever crawled it"),
    ("NOT-MONITORED", "the site's scraper exists but is not crawling this board"),
    ("NO-IMPORT", "the crawler has threads for this board, but none imported here"),
    ("STALE", "imported before; nothing new for %d+ days" % STALE_AFTER_DAYS),
    ("RETIRED", "every source row retired — kept for its content, no longer fetched"),
    ("OK", "crawling and importing, with recent activity"),
]

_COLUMNS = [
    ("verdict", "VERDICT", 14, "left"),
    ("site", "SITE", 21, "left"),
    ("remote", "REMOTE", 18, "left"),
    ("local", "LOCAL", 10, "left"),
    ("mode", "MODE", 9, "left"),
    ("imported", "IMPORTED", 8, "right"),
    ("crawled", "CRAWLED", 7, "right"),
    ("newest", "NEWEST", 16, "left"),
    ("ping", "PING", 10, "left"),
]


def _cells(row):
    if row["whole_board"]:
        mode = "whole"
    elif row["thread_rows"]:
        mode = "%d thr" % row["thread_rows"]
    else:
        mode = "-"
    if row["retired_rows"] and row["retired_rows"] != row["total_rows"]:
        mode += "*"  # partially retired
    return {
        "verdict": row["verdict"],
        "site": row["source_type"],
        "remote": str(row["source_name"]),
        "local": "/%s/" % row["board_name"],
        "mode": mode,
        "imported": str(row["imported_threads"]),
        "crawled": str(row["crawled_threads"]) if row["db_status"] == "ok" else "-",
        "newest": _fmt_time(row["newest"]),
        "ping": _fmt_ping(row["source_type"], row["ping"]),
    }


def render(rows, summary=None, now=None, tsv=False):
    """Render the export. `tsv=True` gives a machine-readable variant."""
    summary = summary or summarize(rows)
    now = now or _datetime.datetime.utcnow()
    keys = [c[0] for c in _COLUMNS]

    if tsv:
        out = ["\t".join(c[1] for c in _COLUMNS)]
        for row in rows:
            cells = _cells(row)
            out.append("\t".join(cells[k] for k in keys))
        return "\n".join(out) + "\n"

    lines = []
    add = lines.append
    add("# syndichan — configured scrape sources")
    add("# generated %s UTC" % now.strftime("%Y-%m-%d %H:%M"))
    add("#")
    add("# One line per (site, remote board, local board). Individually submitted")
    add("# threads are collapsed into MODE, so '12 thr' means twelve thread-level")
    add("# sources for that board. A trailing '*' on MODE means some (not all) of")
    add("# them are retired.")
    add("#")
    add("# Sorted worst-first: anything needing attention is at the top.")
    add("#")
    add("# SUMMARY")
    add("#   %d source rows -> %d lines, across %d sites (%d generic)"
        % (summary["source_rows"], summary["lines"], summary["sites"], summary["generic_sites"]))
    add("#   %d lines importing content, %d importing nothing"
        % (summary["importing"], summary["importing_nothing"]))
    add("#   %d generic site(s) have NEVER been crawled (no scraper database)"
        % summary["never_crawled_sites"])
    if summary["never_crawled_site_names"]:
        add("#     %s" % ", ".join(summary["never_crawled_site_names"]))
    add("#   %d retired source row(s)" % summary["retired_rows"])
    if summary.get("down_sites"):
        add("#   %d site(s) gave NO HTTP response on the last check: %s"
            % (len(summary["down_sites"]), ", ".join(summary["down_sites"])))
    add("#")
    for name, _desc in _LEGEND:
        count = summary["by_verdict"].get(name, 0)
        if count:
            add("#   %-14s %d" % (name, count))
    add("#")
    add("# VERDICTS")
    for name, desc in _LEGEND:
        add("#   %-14s %s" % (name, desc))
    add("#")
    add("# COLUMNS")
    add("#   IMPORTED  threads visible on this site's local board")
    add("#   CRAWLED   threads the scraper has for that remote board ('-' = no scraper db)")
    add("#   NEWEST    most recent imported-thread activity")
    add("#   PING      last cached reachability check. A bare status code means the site")
    add("#             ANSWERED (403/429 = up but refusing a bare request, which is fine")
    add("#             if its scraper still reads it). 'DOWN:x' means no HTTP response at")
    add("#             all. 'n/a' = dedicated scraper, not covered by the ping sweep.")
    add("#")

    header = "  ".join(
        (label.ljust(width) if align == "left" else label.rjust(width))
        for _key, label, width, align in _COLUMNS
    )
    add("# " + header.rstrip())
    add("# " + "-" * (len(header.rstrip()) + 0))
    for row in rows:
        cells = _cells(row)
        rendered = "  ".join(
            (cells[key].ljust(width) if align == "left" else cells[key].rjust(width))
            for key, _label, width, align in _COLUMNS
        )
        add("  " + rendered.rstrip())

    add("")
    add("# SITE URLS")
    seen = {}
    for row in rows:
        if row["site_url"] and row["source_type"] not in seen:
            seen[row["source_type"]] = row["site_url"]
    for source_type in sorted(seen):
        add("#   %-21s %s" % (source_type, seen[source_type]))
    return "\n".join(lines) + "\n"


def build_export(now=None, tsv=False):
    """Collect + render in one call. Returns (text, rows, summary)."""
    now = now or _datetime.datetime.utcnow()
    rows = collect_rows(now=now)
    summary = summarize(rows)
    return render(rows, summary, now=now, tsv=tsv), rows, summary


def write_export(path=None, now=None, tsv=False):
    """Write the export to `path` (default: <repo root>/aggregated_chans.txt).

    Writes to a temp file in the same directory and renames, so a reader never
    observes a half-written file and a failure leaves the previous export intact.
    """
    target = path or default_export_path()
    text, rows, summary = build_export(now=now, tsv=tsv)
    directory = os.path.dirname(os.path.abspath(target)) or "."
    if not os.path.isdir(directory):
        os.makedirs(directory, exist_ok=True)
    temp_path = os.path.join(directory, ".%s.tmp" % os.path.basename(target))
    with open(temp_path, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temp_path, target)
    return target, rows, summary


__all__ = [
    "DEFAULT_EXPORT_BASENAME", "STALE_AFTER_DAYS", "VERDICT_ORDER", "build_export",
    "collect_rows", "default_export_path", "render", "summarize", "write_export",
]
