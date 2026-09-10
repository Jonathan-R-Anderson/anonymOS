"""Locally cached list of the boards each aggregated chan hosts.

Populated by scanning every chan in the aggregated list (see
services/chan_board_discovery.py, which delegates the actual HTTP to the generic
scraper's GET /sites/boards). The admin board-monitoring picker reads this table,
so choosing what to scrape is a dropdown of real boards instead of typing a board
name and hoping it exists.

Refresh policy: scanned once at startup for chans never scanned, then re-scanned
weekly. A board that disappears from a rescan is DELETED from this table, per the
requirement that removed boards not linger locally. Deletion is guarded: a scan
that returns nothing at all is treated as a failed scan, not as "the site removed
every board", so a site being briefly unreachable cannot wipe its board list.

This table is a cache and is safe to truncate; it is rebuilt on the next scan.
"""
import datetime as _datetime

from shared import db

# Re-scan a chan's board list this often.
REFRESH_INTERVAL_DAYS = 7


class ChanBoard(db.Model):
    __tablename__ = "chan_board"

    id = db.Column(db.Integer, primary_key=True)
    # Host of the owning chan, matching AggregatedChan-derived hosts and the
    # source_type used for generic scraping, so the two line up.
    host = db.Column(db.String(255), nullable=False, index=True)
    # Full site URL as listed, so the scraper can be pointed at it directly.
    site_url = db.Column(db.String(500), nullable=False)
    # Board slug ("b") and the path that reaches it ("/b/").
    board = db.Column(db.String(64), nullable=False)
    path = db.Column(db.String(128), nullable=False)
    # Human name, from a structured endpoint or the board page's <title>.
    name = db.Column(db.String(120), nullable=True)
    first_seen_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )
    last_seen_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )

    __table_args__ = (
        db.UniqueConstraint("host", "board", name="uq_chan_board"),
    )

    @property
    def label(self):
        return "/%s/ %s" % (self.board, self.name) if self.name else "/%s/" % self.board


class ChanBoardScan(db.Model):
    """Per-chan scan bookkeeping: when it last ran and how it went.

    Separate from ChanBoard so a chan that currently has no discoverable boards
    still records an attempt and is not rescanned on every pass.
    """
    __tablename__ = "chan_board_scan"

    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False, unique=True)
    site_url = db.Column(db.String(500), nullable=False)
    last_scanned_at = db.Column(db.DateTime, nullable=True)
    last_ok_at = db.Column(db.DateTime, nullable=True)
    board_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    last_error = db.Column(db.String(500), nullable=True)
    consecutive_failures = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    # --- Reachability ping (separate from the board-list scan) ----------------
    # A cheap "is this chan up, and what does it answer?" check, stored so the
    # admin list can be read at a glance. NEVER pinged from a request handler —
    # 300 sites x a network timeout would hang the page (see the front-page
    # render-blocking incident); a background sweep fills these in.
    last_ping_at = db.Column(db.DateTime, nullable=True)
    ping_status_code = db.Column(db.Integer, nullable=True)   # HTTP status, null if no response
    ping_ms = db.Column(db.Integer, nullable=True)            # round trip, milliseconds
    ping_error = db.Column(db.String(200), nullable=True)     # "timeout", "dns", "tls", ...
    ping_ok = db.Column(db.Boolean, nullable=True)            # null = never pinged


def boards_for_host(host):
    return (
        db.session.query(ChanBoard)
        .filter(ChanBoard.host == (host or "").strip().lower())
        .order_by(ChanBoard.board.asc())
        .all()
    )


def boards_by_host():
    """{host: [ChanBoard, ...]} for the whole cache, for the admin picker."""
    grouped = {}
    for row in db.session.query(ChanBoard).order_by(ChanBoard.host.asc(), ChanBoard.board.asc()).all():
        grouped.setdefault(row.host, []).append(row)
    return grouped


def scan_state(host):
    return (
        db.session.query(ChanBoardScan)
        .filter(ChanBoardScan.host == (host or "").strip().lower())
        .one_or_none()
    )


def hosts_due_for_scan(known_sites, limit=10, interval_days=REFRESH_INTERVAL_DAYS):
    """Pick chans to scan now: never-scanned first, then oldest past the interval.

    ``known_sites`` is [(host, site_url)] from the aggregated-chan list, so a chan
    removed from that list is simply never scanned again.
    """
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(days=interval_days)
    states = {
        state.host: state
        for state in db.session.query(ChanBoardScan).all()
    }
    never, stale = [], []
    for host, site_url in known_sites:
        state = states.get(host)
        if state is None or state.last_scanned_at is None:
            never.append((host, site_url, None))
        elif state.last_scanned_at < cutoff:
            stale.append((host, site_url, state.last_scanned_at))
    stale.sort(key=lambda row: row[2])
    ordered = never + stale
    return [(host, site_url) for host, site_url, _ in ordered[:max(0, limit)]]


def record_scan_failure(host, site_url, error):
    host = (host or "").strip().lower()
    state = scan_state(host)
    if state is None:
        state = ChanBoardScan(host=host, site_url=site_url or "")
        db.session.add(state)
    state.site_url = site_url or state.site_url
    state.last_scanned_at = _datetime.datetime.utcnow()
    state.last_error = (str(error) or "")[:500] or None
    state.consecutive_failures = (state.consecutive_failures or 0) + 1
    db.session.commit()
    return state


def apply_scan_result(host, site_url, discovered):
    """Replace a chan's cached boards with a fresh scan result.

    ``discovered`` is [{"board","path","name"}]. Returns
    (added, updated, removed).

    An EMPTY result never deletes anything: a site that is down, rate-limiting or
    Cloudflare-walled returns nothing, and treating that as "all boards deleted"
    would clear a good cache and then re-add everything on the next success.
    Callers should report empty results through record_scan_failure instead.
    """
    host = (host or "").strip().lower()
    now = _datetime.datetime.utcnow()
    normalized = {}
    for row in discovered or []:
        board = str((row or {}).get("board") or "").strip().strip("/")
        if not board:
            continue
        normalized[board[:64]] = {
            "path": (str(row.get("path") or "/%s/" % board))[:128],
            "name": (str(row.get("name") or "").strip() or None),
        }

    existing = {row.board: row for row in boards_for_host(host)}
    added = updated = removed = 0

    for board, info in normalized.items():
        row = existing.get(board)
        if row is None:
            db.session.add(ChanBoard(
                host=host, site_url=site_url or "", board=board,
                path=info["path"], name=(info["name"] or None),
                first_seen_at=now, last_seen_at=now,
            ))
            added += 1
            continue
        changed = False
        if info["name"] and row.name != info["name"]:
            row.name = info["name"][:120]
            changed = True
        if info["path"] and row.path != info["path"]:
            row.path = info["path"]
            changed = True
        if site_url and row.site_url != site_url:
            row.site_url = site_url
            changed = True
        row.last_seen_at = now
        db.session.add(row)
        updated += changed

    if normalized:
        for board, row in existing.items():
            if board not in normalized:
                # Gone from the remote site -> drop it locally.
                db.session.delete(row)
                removed += 1

    state = scan_state(host)
    if state is None:
        state = ChanBoardScan(host=host, site_url=site_url or "")
        db.session.add(state)
    state.site_url = site_url or state.site_url
    state.last_scanned_at = now
    state.last_ok_at = now
    state.board_count = len(normalized)
    state.last_error = None
    state.consecutive_failures = 0
    db.session.commit()
    return added, updated, removed




def ping_summary(state):
    """Short human label for a chan's last ping, for the admin list."""
    if state is None or state.last_ping_at is None:
        return {"label": "not checked", "kind": "unknown", "detail": None}
    if state.ping_status_code:
        code = int(state.ping_status_code)
        kind = "ok" if 200 <= code < 300 else "warn" if 300 <= code < 400 else "bad"
        label = str(code)
        if state.ping_ms is not None:
            label += " · %dms" % state.ping_ms
        return {"label": label, "kind": kind, "detail": state.ping_error}
    return {
        "label": (state.ping_error or "unreachable")[:40],
        "kind": "bad",
        "detail": state.ping_error,
    }


def hosts_due_for_ping(known_sites, limit=25, max_age_minutes=60):
    """Chans to ping now: never-pinged first, then the stalest."""
    cutoff = _datetime.datetime.utcnow() - _datetime.timedelta(minutes=max_age_minutes)
    states = {s.host: s for s in db.session.query(ChanBoardScan).all()}
    never, stale = [], []
    for host, site_url in known_sites:
        state = states.get(host)
        if state is None or state.last_ping_at is None:
            never.append((host, site_url, None))
        elif state.last_ping_at < cutoff:
            stale.append((host, site_url, state.last_ping_at))
    stale.sort(key=lambda row: row[2])
    return [(h, u) for h, u, _ in (never + stale)[:max(0, limit)]]


def record_ping(host, site_url, status_code=None, elapsed_ms=None, error=None):
    """Store one ping result. Returns the ChanBoardScan row."""
    host = (host or "").strip().lower()
    state = scan_state(host)
    if state is None:
        state = ChanBoardScan(host=host, site_url=site_url or "")
        db.session.add(state)
    state.site_url = site_url or state.site_url
    state.last_ping_at = _datetime.datetime.utcnow()
    state.ping_status_code = int(status_code) if status_code else None
    state.ping_ms = int(elapsed_ms) if elapsed_ms is not None else None
    state.ping_error = (str(error)[:200] if error else None)
    state.ping_ok = bool(status_code and 200 <= int(status_code) < 400)
    db.session.commit()
    return state


__all__ = [
    "ChanBoard", "ChanBoardScan", "REFRESH_INTERVAL_DAYS", "apply_scan_result",
    "hosts_due_for_ping", "ping_summary", "record_ping",
    "boards_by_host", "boards_for_host", "hosts_due_for_scan",
    "record_scan_failure", "scan_state",
]
