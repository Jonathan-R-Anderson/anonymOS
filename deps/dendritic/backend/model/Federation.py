"""The public list of chans this site aggregates from, plus operator-submitted
requests to be added to or removed from that list.

The list is DB-backed (so the admin can manage it) and seeded once from the
bundled resources/aggregated_chans.txt (the same set the crawler targets). The
public /federation page renders it and offers a request form; requests land in
chan_request for the admin to review + apply.
"""
import datetime as _datetime
import os

from shared import db

_SEED_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "resources", "aggregated_chans.txt",
)

REQUEST_ACTIONS = ("add", "remove")


class AggregatedChan(db.Model):
    __tablename__ = "aggregated_chan"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False, unique=True)
    name = db.Column(db.String(200), nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )


class RemovedAggregatedChan(db.Model):
    """URLs deliberately taken off the list.

    Exists so seeding can RECONCILE (top up anything missing from the bundled
    file) without resurrecting a chan that was removed on purpose — e.g. via an
    operator removal request. Without this record, "repair the list" and "respect
    removals" are mutually exclusive.
    """
    __tablename__ = "removed_aggregated_chan"
    id = db.Column(db.Integer, primary_key=True)
    url = db.Column(db.String(500), nullable=False, unique=True)
    removed_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )


class ChanRequest(db.Model):
    __tablename__ = "chan_request"
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(10), nullable=False)  # "add" | "remove"
    url = db.Column(db.String(500), nullable=False)
    name = db.Column(db.String(200), nullable=True)
    message = db.Column(db.Text, nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )
    handled = db.Column(db.Boolean, nullable=False, default=False, server_default="0")


def _display_name_from_url(url):
    host = (url or "").split("://", 1)[-1].split("/", 1)[0]
    return host or url


def seed_aggregated_chans():
    """Reconcile the chan list against the bundled file. Best-effort; never
    blocks startup. Returns the number of rows added.

    RECONCILES rather than seeding-once-if-empty. The old behaviour returned
    early whenever the table had any row at all, which made a partially populated
    list permanently unrepairable: the live site had 142 of 304 chans and no
    amount of restarting would top it up, because "not empty" was treated as
    "already seeded". Growing the bundled file had the same problem.

    Chans in removed_aggregated_chan are skipped, so topping up never resurrects
    something taken off the list on purpose.
    """
    added = 0
    try:
        if not os.path.isfile(_SEED_FILE):
            return 0
        # Compare on the CANONICAL key, never the raw string. Comparing raw text
        # meant a seed line "https://x" did not match an existing "https://x/", so
        # every restart could add a second row for the same chan — and the
        # removed-chan guard was defeated the same way, resurrecting a chan that
        # had been taken off the list with a differently-slashed URL.
        existing = {
            key for key in (
                chan_dedupe_key(url)
                for (url,) in db.session.query(AggregatedChan.url).all()
            ) if key
        }
        removed = {
            key for key in (
                chan_dedupe_key(url)
                for (url,) in db.session.query(RemovedAggregatedChan.url).all()
            ) if key
        }
        seen = set()
        for line in open(_SEED_FILE, "r", encoding="utf-8"):
            raw_line = line.strip()
            if not raw_line or raw_line.startswith("#"):
                continue
            url = (canonical_chan_url(raw_line) or "")[:500]
            if not url:
                continue
            key = chan_dedupe_key(url)
            if not key or key in seen or key in existing or key in removed:
                continue
            seen.add(key)
            db.session.add(
                AggregatedChan(url=url, name=_display_name_from_url(url)[:200])
            )
            added += 1
        if added:
            db.session.commit()
        return added
    except Exception:
        db.session.rollback()
        return 0


def list_aggregated_chans():
    return (
        db.session.query(AggregatedChan)
        .order_by(AggregatedChan.name.asc(), AggregatedChan.url.asc())
        .all()
    )


def normalize_chan_url(raw):
    """Normalize an operator-entered chan URL to a comparable form.

    Adds a scheme when missing and drops a trailing slash, so "example.org" and
    "https://example.org/" do not both end up in the list as separate rows.
    Raises ValueError with an operator-facing message.
    """
    url = (raw or "").strip()
    if not url:
        raise ValueError("Enter the chan's URL.")
    if " " in url:
        raise ValueError("That doesn't look like a URL.")
    if "://" not in url:
        url = "https://" + url
    scheme, _, rest = url.partition("://")
    if scheme.lower() not in ("http", "https"):
        raise ValueError("Only http and https URLs can be aggregated.")
    host = rest.split("/", 1)[0]
    if not host or "." not in host:
        raise ValueError("That doesn't look like a URL.")
    if len(url) > 500:
        raise ValueError("That URL is too long (max 500 characters).")
    return url.rstrip("/")


def canonical_chan_url(raw):
    """normalize_chan_url without the exception, or None if unusable.

    Seeding and dedupe need a comparable form for input they cannot vouch for, and
    must skip a bad line rather than abort the whole pass.
    """
    try:
        return normalize_chan_url(raw)
    except ValueError:
        return None


def chan_dedupe_key(url):
    """Case-insensitive identity for a chan URL, or None.

    Folds a trailing slash and host letter-case. Deliberately does NOT fold
    http vs https: several listed chans are http-only (tf2chan.net,
    tohno-chan.com, touhou.fi), and treating those as the same row as an https
    variant would silently rewrite a working URL into a broken one.
    """
    value = canonical_chan_url(url)
    if not value:
        return None
    scheme, _, rest = value.partition("://")
    host, slash, path = rest.partition("/")
    return "%s://%s%s" % (scheme.lower(), host.lower(), (slash + path) if slash else "")


def dedupe_aggregated_chans():
    """Collapse chan rows that differ only by trailing slash or host case.

    Returns (removed_count, kept_count). Idempotent.

    Why this was needed: seed_aggregated_chans() compared RAW strings against the
    table, so a seed line "https://x" did not match an existing row "https://x/"
    and a second row was inserted. Production reached 46 rows for 30 real chans —
    16 duplicate pairs, every one differing only by a trailing slash — and the
    public federation page listed each of them twice.

    Keeps the canonical (slash-stripped) URL and preserves a name from whichever
    duplicate has one, so the surviving row is never worse than what it replaced.
    """
    groups = {}
    for row in db.session.query(AggregatedChan).order_by(AggregatedChan.id.asc()).all():
        key = chan_dedupe_key(row.url)
        if key is None:
            # Unparseable: leave it alone rather than guess.
            continue
        groups.setdefault(key, []).append(row)

    removed = 0
    kept = 0
    for key, rows in groups.items():
        kept += 1
        keeper = rows[0]
        canonical = canonical_chan_url(keeper.url) or keeper.url
        if keeper.url != canonical:
            keeper.url = canonical
            db.session.add(keeper)
        if len(rows) == 1:
            continue
        for duplicate in rows[1:]:
            # Do not lose a human-set name just because that row sorted later.
            if not (keeper.name or "").strip() and (duplicate.name or "").strip():
                keeper.name = duplicate.name
                db.session.add(keeper)
            db.session.delete(duplicate)
            removed += 1
    if removed or kept:
        db.session.commit()
    return removed, kept


def add_aggregated_chan(url, name=None):
    """Add a chan to the public aggregation list. Returns the row.

    Raises ValueError if the URL is unusable or already listed, so the admin sees
    why nothing happened instead of a silent no-op.
    """
    url = normalize_chan_url(url)
    existing = (
        db.session.query(AggregatedChan)
        .filter(db.func.lower(AggregatedChan.url) == url.lower())
        .one_or_none()
    )
    if existing is not None:
        raise ValueError("%s is already on the list." % url)
    chan = AggregatedChan(
        url=url[:500],
        name=((name or "").strip() or _display_name_from_url(url))[:200],
    )
    db.session.add(chan)
    db.session.commit()
    return chan


def remove_aggregated_chan(chan_id):
    """Remove one chan from the list by id. Returns the removed URL or None.

    Records the URL in removed_aggregated_chan so startup reconciliation does not
    add it straight back from the bundled seed file.
    """
    chan = db.session.query(AggregatedChan).filter(AggregatedChan.id == chan_id).one_or_none()
    if chan is None:
        return None
    url = chan.url
    db.session.delete(chan)
    _remember_removal(url)
    db.session.commit()
    return url


def remove_aggregated_chans(chan_ids):
    """Remove several chans at once. Returns the list of removed URLs.

    Each removal is recorded in removed_aggregated_chan exactly as the single
    remove does, so startup reconciliation does not add them straight back from
    the bundled seed file. One commit for the whole batch.
    """
    wanted = []
    for raw in chan_ids or []:
        try:
            wanted.append(int(raw))
        except (TypeError, ValueError):
            continue
    if not wanted:
        return []
    removed = []
    for chan in (
        db.session.query(AggregatedChan)
        .filter(AggregatedChan.id.in_(wanted))
        .all()
    ):
        removed.append(chan.url)
        db.session.delete(chan)
        _remember_removal(chan.url)
    if removed:
        db.session.commit()
    return removed


def _remember_removal(url):
    url = (url or "").strip()[:500]
    if not url:
        return
    exists = (
        db.session.query(RemovedAggregatedChan.id)
        .filter(RemovedAggregatedChan.url == url)
        .first()
    )
    if exists is None:
        db.session.add(RemovedAggregatedChan(url=url))


def restore_aggregated_chan(url):
    """Undo a removal so the next reconcile re-adds it."""
    url = (url or "").strip()[:500]
    (db.session.query(RemovedAggregatedChan)
     .filter(RemovedAggregatedChan.url == url)
     .delete(synchronize_session=False))
    db.session.commit()


def record_chan_request(action, url, name=None, message=None):
    action = (action or "").strip().lower()
    url = (url or "").strip()
    if action not in REQUEST_ACTIONS or not url:
        return None
    req = ChanRequest(
        action=action,
        url=url[:500],
        name=(name or "").strip()[:200] or None,
        message=(message or "").strip()[:2000] or None,
    )
    db.session.add(req)
    db.session.commit()
    return req


def pending_chan_requests(limit=100):
    return (
        db.session.query(ChanRequest)
        .filter(ChanRequest.handled.is_(False))
        .order_by(ChanRequest.created_at.desc())
        .limit(limit)
        .all()
    )


def apply_chan_request(request_id):
    """Apply a pending request to the live list, then mark it handled."""
    req = db.session.query(ChanRequest).filter(ChanRequest.id == request_id).one_or_none()
    if req is None:
        return False
    if req.action == "add":
        exists = db.session.query(AggregatedChan.id).filter(AggregatedChan.url == req.url).first()
        if exists is None:
            db.session.add(AggregatedChan(url=req.url[:500], name=(req.name or _display_name_from_url(req.url))[:200]))
    elif req.action == "remove":
        db.session.query(AggregatedChan).filter(AggregatedChan.url == req.url).delete(synchronize_session=False)
        # Remember it, or the next startup reconcile puts it straight back.
        _remember_removal(req.url)
    req.handled = True
    db.session.commit()
    return True


def dismiss_chan_request(request_id):
    req = db.session.query(ChanRequest).filter(ChanRequest.id == request_id).one_or_none()
    if req is None:
        return False
    req.handled = True
    db.session.commit()
    return True
