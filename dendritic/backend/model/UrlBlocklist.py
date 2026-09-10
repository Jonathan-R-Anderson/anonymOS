"""Spam URL/token blocklist enforced at post-submission time.

A post whose body or subject matches any enabled entry is rejected before it is
ever stored. This is the classic imageboard `spam.txt` mechanism: mostly spam
domains and URL shorteners, plus a few bare tokens and regular expressions.

Entries come in three forms, and each is matched the way that form implies:

  * domain -- ``moromie-douga.com``, ``.by.ru``, or a hosts-file line
    (``0.0.0.0  spam.example``). Matched by extracting every hostname from the
    post and walking its parent domains, so ``sub.up.to/free`` hits the entry
    ``up.to`` while the word "backup.tools" does not. This is a dict lookup, not
    a scan, which is what makes a 40k+ domain list usable (see below).
  * substring -- ``phentermine``, ``365669``, ``tripod.com/?``. Anything with no
    dot, a path, or a bare IP. Case-insensitive substring test.
  * regex -- ``/\\bcialis\\b/i``, slash-delimited with optional trailing flags
    (``i`` ignorecase, ``s`` dotall, ``m`` multiline).

Why the domain form is a lookup rather than a loop: these lists are big. A
per-entry scan costs O(entries) per post -- fine at 500 entries (~0.2ms), roughly
40ms at 40k. Extracting hostnames from the post and walking their parents is
O(hostnames in the post) regardless of list size, so importing a full public
hosts blocklist does not slow posting down.

Exemptions (important): a domain match is suppressed when the hostname, or any
of its parent domains, belongs to a site we aggregate (``AggregatedChan``) or is
one of the built-in scraper hosts. Public porn/spam hosts lists routinely include
imageboards -- the AntiPorn list contains ``4chan.org``, ``7chan.org``,
``420chan.org``, ``bbw-chan.nl``, ``pregchan.com``, ``u18chan.com`` and
``motherless.com`` -- and without this, importing one would stop users linking or
discussing this site's own sources. The exemption is evaluated at match time
against the live chan list, so adding a chan later immediately un-blocks it
rather than leaving a stale import-time decision behind.

The list is DB-backed so the admin can add/remove entries at runtime, and is
seeded once from the bundled resources/url_blocklist*.txt files so a fresh
install is never running with an empty list. Removals by the admin are permanent
-- the seed is guarded by a SiteSetting marker rather than an "is it empty?"
check, so an intentionally emptied list does not refill itself on the next
restart.

Matching is on the wordfiltered text (see post.create_post), i.e. exactly what
would have been stored, so a wordfilter cannot be used to smuggle a blocked
domain past this gate.
"""
import datetime as _datetime
import os
import re

from shared import db
from model.SiteSetting import get_setting, set_setting

_RESOURCE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources"
)
# Seeded in order. Add another file here to ship another default list; each is
# tolerant of both bare-entry and hosts-file ("0.0.0.0 domain") formats.
_SEED_FILES = (
    os.path.join(_RESOURCE_DIR, "url_blocklist.txt"),
    os.path.join(_RESOURCE_DIR, "url_blocklist_hosts.txt"),
)

# Hosts-file sink addresses to strip from "0.0.0.0  domain.example" lines.
_HOSTS_SINKS = ("0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:0")

# Multi-tenant hosts where one tenant is NOT the whole domain. When an
# aggregated chan lives on one of these (e.g. bbs.fc2.com), only that exact host
# and its subdomains are exempt -- never the shared parent, which would unblock
# every unrelated tenant on it. See _exempt_hosts().
_SHARED_HOSTING_SUFFIXES = frozenset((
    "fc2.com", "blogspot.com", "tumblr.com", "wordpress.com", "livedoor.jp",
    "neocities.org", "github.io", "herokuapp.com", "122mb.com", "dtiblog.com",
    "webcindario.com", "skyblog.com", "forumfree.net", "forumactif.net",
    "prohosting.com", "narod.ru", "ucoz.ru", "at.ua", "moy.su", "clan.su",
    "xrea.com", "ne.jp", "or.jp", "co.jp", "com.br", "co.uk", "com.au",
))

# Hostnames referenced anywhere in a post. Deliberately loose (it only produces
# lookup candidates) but requires an alphabetic TLD so bare IPs and version
# numbers are left to the substring matchers.
_HOST_RE = re.compile(
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,}"
)

# Source hosts the scrapers themselves target. Exempt from domain blocking for
# the same reason as the AggregatedChan list: public blocklists include them.
_BUILTIN_EXEMPT_HOSTS = frozenset((
    "4chan.org", "4channel.org", "boards.4chan.org",
    "8chan.moe", "8kun.top", "7chan.org", "reddit.com",
))

SEEDED_SETTING = "url_blocklist_seeded"
# When on, a post that trips the blocklist also bans the poster's IP. Off by
# default and deliberately so: several seeded entries are broad bare words
# ("holdem", "ringtones", "cvv"), and an IP ban punishes everyone behind a NAT
# or VPN exit. Rejecting the post is the safe default.
AUTOBAN_SETTING = "url_blocklist_autoban"
# Duration key from model.Ban._DURATIONS ("30d", "1w", "permanent", ...).
AUTOBAN_DURATION_SETTING = "url_blocklist_autoban_duration"
DEFAULT_AUTOBAN_DURATION = "30d"
AUTOBAN_REASON = "Automated spam blocklist match"

MAX_PATTERN_LENGTH = 512
MAX_NOTE_LENGTH = 256

# Rejection text shown to the poster. Deliberately does NOT echo which entry
# matched -- that would let a spammer bisect the list.
REJECTION_MESSAGE = (
    "Your post was rejected because it matches this site's spam blocklist. "
    "If you believe this is a mistake, remove any links and try again."
)


class UrlBlocklistEntry(db.Model):
    __tablename__ = "url_blocklist_entry"

    id = db.Column(db.Integer, primary_key=True)
    pattern = db.Column(db.String(MAX_PATTERN_LENGTH), nullable=False, unique=True)
    is_regex = db.Column(db.Boolean, nullable=False, default=False, server_default="0")
    note = db.Column(db.String(MAX_NOTE_LENGTH), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True, server_default="1", index=True)
    hit_count = db.Column(db.Integer, nullable=False, default=0, server_default="0")
    last_hit_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime, nullable=False,
        default=_datetime.datetime.utcnow, server_default=db.func.now(),
    )


_REGEX_FORM = re.compile(r"^/(?P<body>.+)/(?P<flags>[ismx]*)$", re.DOTALL)
_FLAG_MAP = {"i": re.IGNORECASE, "s": re.DOTALL, "m": re.MULTILINE, "x": re.VERBOSE}


def normalize_raw_line(raw):
    """Strip comments and hosts-file decoration from one input line.

    Accepts what people actually paste: bare entries, ``0.0.0.0  domain.example``
    hosts lines, and either with a trailing ``# comment``. Returns "" for a line
    that carries no entry (blank or pure comment).
    """
    line = (raw or "").replace("\t", " ").strip()
    if not line or line.startswith("#") or line.startswith("!"):
        return ""
    # Only strip a trailing comment for non-regex entries; "#" is legal inside a
    # regex body and stripping it there would silently corrupt the pattern.
    if not line.startswith("/") and "#" in line:
        line = line.split("#", 1)[0].strip()
        if not line:
            return ""
    parts = line.split()
    if len(parts) >= 2 and parts[0] in _HOSTS_SINKS:
        # Hosts-file line: the sink address is not part of the entry. Such a line
        # can only legitimately name a host, so a non-domain payload is corrupt
        # upstream data and is dropped rather than imported as a substring rule.
        # The shipped AntiPorn list really does contain a bare "0.0.0.0    be",
        # which as a substring would reject virtually every English post.
        candidate = parts[1].strip().lower()
        return candidate if entry_form(candidate) == "domain" else ""
    if len(parts) == 1:
        return parts[0].strip()
    return line


def parse_pattern(raw):
    """Normalize an operator-entered line into ``(pattern, is_regex)``.

    Raises ValueError with an operator-facing message for anything unusable, so
    a bad regex is reported at add time instead of breaking every submission.
    """
    pattern = normalize_raw_line(raw)
    if not pattern:
        raise ValueError("Enter a URL, domain, token or /regex/ to block.")
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(
            "Blocklist entries can be at most %d characters." % MAX_PATTERN_LENGTH
        )
    match = _REGEX_FORM.match(pattern)
    if match is None:
        return pattern, False
    try:
        _compile_regex(match.group("body"), match.group("flags"))
    except re.error as error:
        raise ValueError("That regular expression is invalid: %s" % error)
    return pattern, True


def _compile_regex(body, flags):
    compiled_flags = 0
    for flag in flags or "":
        compiled_flags |= _FLAG_MAP.get(flag, 0)
    return re.compile(body, compiled_flags)


def entry_form(pattern):
    """Classify a non-regex entry as ``"domain"`` or ``"substring"``.

    Domain form requires a dot, no path/whitespace, and an alphabetic TLD. Bare
    IPs and tokens fall through to substring so ``86.120.197.66`` and ``365669``
    keep working.
    """
    if not pattern or "/" in pattern or " " in pattern:
        return "substring"
    candidate = pattern[1:] if pattern.startswith(".") else pattern
    if "." not in candidate:
        return "substring"
    if _HOST_RE.fullmatch(candidate) is None:
        return "substring"
    return "domain"


def _parent_domains(host):
    """``a.b.example.com`` -> that, ``b.example.com``, ``example.com``.

    Stops before the bare TLD: a one-label entry would never be a useful block
    and matching it would blocklist an entire TLD by accident.
    """
    parts = (host or "").split(".")
    return [".".join(parts[index:]) for index in range(len(parts) - 1)]


# Match index, rebuilt only when the list actually changes. The revision is
# derived from the DB rather than an in-process counter so a change made in one
# uWSGI worker is picked up by all of them.
_CACHE = {"revision": None, "domains": {}, "substrings": (), "regexes": (), "exempt": frozenset()}


def _revision():
    # Two plain aggregates rather than a SUM(CASE ...): db.case()'s signature
    # differs between SQLAlchemy 1.3 and 1.4+, and SQLAlchemy is unpinned here.
    total, max_id = db.session.query(
        db.func.count(UrlBlocklistEntry.id), db.func.max(UrlBlocklistEntry.id)
    ).one()
    enabled = (
        db.session.query(db.func.count(UrlBlocklistEntry.id))
        .filter(UrlBlocklistEntry.enabled.is_(True))
        .scalar()
    )
    # Chan-list size participates so adding an aggregated chan re-derives the
    # exemption set without waiting for a blocklist edit.
    try:
        from model.Federation import AggregatedChan
        chans = db.session.query(db.func.count(AggregatedChan.id)).scalar() or 0
    except Exception:
        chans = 0
    return (total or 0, max_id or 0, enabled or 0, chans)


def _exempt_hosts():
    """Hosts never blocked by a domain entry: everything we aggregate.

    Includes each aggregated chan's own host plus its parent domains, because a
    public list may name the site at a different depth than we do -- our list has
    ``boards.420chan.org`` while the blocklist names ``420chan.org``, and blocking
    one while aggregating the other is incoherent. Parents on a shared-hosting
    suffix are deliberately NOT added, so a chan at ``bbs.fc2.com`` does not
    exempt all of ``fc2.com``.
    """
    hosts = set(_BUILTIN_EXEMPT_HOSTS)
    try:
        from model.Federation import AggregatedChan
        for (url,) in db.session.query(AggregatedChan.url).all():
            host = (url or "").split("://", 1)[-1].split("/", 1)[0].strip().lower()
            host = host.split("@")[-1].split(":")[0]
            if host.startswith("www."):
                host = host[4:]
            if not host or "." not in host:
                continue
            hosts.add(host)
            for parent in _parent_domains(host)[1:]:
                if parent in _SHARED_HOSTING_SUFFIXES:
                    break
                hosts.add(parent)
    except Exception:
        pass
    return frozenset(hosts)


def _index():
    revision = _revision()
    if _CACHE["revision"] == revision:
        return _CACHE
    domains, substrings, regexes = {}, [], []
    entries = (
        db.session.query(
            UrlBlocklistEntry.id, UrlBlocklistEntry.pattern, UrlBlocklistEntry.is_regex
        )
        .filter(UrlBlocklistEntry.enabled.is_(True))
        .order_by(UrlBlocklistEntry.id.asc())
        .all()
    )
    for entry_id, pattern, is_regex in entries:
        pattern = pattern or ""
        if is_regex:
            match = _REGEX_FORM.match(pattern)
            if match is None:
                continue
            try:
                regexes.append((entry_id, pattern, _compile_regex(
                    match.group("body"), match.group("flags"))))
            except re.error:
                # A pattern that no longer compiles (e.g. hand-edited in the DB)
                # is skipped rather than breaking every post on the site.
                continue
        elif entry_form(pattern) == "domain":
            key = pattern[1:] if pattern.startswith(".") else pattern
            domains.setdefault(key.lower(), (entry_id, pattern))
        else:
            substrings.append((entry_id, pattern, pattern.lower()))
    _CACHE.update({
        "revision": revision,
        "domains": domains,
        "substrings": tuple(substrings),
        "regexes": tuple(regexes),
        "exempt": _exempt_hosts(),
    })
    return _CACHE


def find_match(*texts):
    """Return ``(entry_id, pattern)`` for the first blocklist hit, else None.

    Order is cheapest-and-most-specific first: hostname lookups, then substring
    tokens, then operator regexes.
    """
    haystack = "\n".join(text for text in texts if text)
    if not haystack.strip():
        return None
    index = _index()
    domains, exempt = index["domains"], index["exempt"]

    if domains:
        for host in set(match.group(0).lower() for match in _HOST_RE.finditer(haystack)):
            chain = _parent_domains(host)
            # A host belonging to a site we aggregate is never spam-blocked, even
            # when a public list names it. Checked before the blocklist so the
            # exemption wins.
            if any(parent in exempt for parent in chain):
                continue
            for parent in chain:
                hit = domains.get(parent)
                if hit is not None:
                    return hit

    lowered = haystack.lower()
    for entry_id, pattern, literal in index["substrings"]:
        if literal and literal in lowered:
            return entry_id, pattern
    for entry_id, pattern, compiled in index["regexes"]:
        if compiled.search(haystack):
            return entry_id, pattern
    return None


def record_hit(entry_id):
    """Bump the hit counters for a matched entry. Best-effort: a bookkeeping
    failure must never turn a clean rejection into a 500."""
    try:
        (
            db.session.query(UrlBlocklistEntry)
            .filter(UrlBlocklistEntry.id == entry_id)
            .update(
                {
                    UrlBlocklistEntry.hit_count: UrlBlocklistEntry.hit_count + 1,
                    UrlBlocklistEntry.last_hit_at: _datetime.datetime.utcnow(),
                },
                synchronize_session=False,
            )
        )
        db.session.commit()
    except Exception:
        db.session.rollback()


def autoban_enabled():
    return (get_setting(AUTOBAN_SETTING, "") or "").strip().lower() in ("1", "true", "on", "yes")


def set_autoban_enabled(enabled):
    set_setting(AUTOBAN_SETTING, "1" if enabled else "0")


def autoban_duration():
    return (get_setting(AUTOBAN_DURATION_SETTING, "") or "").strip() or DEFAULT_AUTOBAN_DURATION


def set_autoban_duration(duration):
    set_setting(AUTOBAN_DURATION_SETTING, (duration or "").strip() or DEFAULT_AUTOBAN_DURATION)


def list_entries(include_disabled=True):
    query = db.session.query(UrlBlocklistEntry)
    if not include_disabled:
        query = query.filter(UrlBlocklistEntry.enabled.is_(True))
    return query.order_by(UrlBlocklistEntry.pattern.asc()).all()


def entry_count(enabled_only=True):
    query = db.session.query(db.func.count(UrlBlocklistEntry.id))
    if enabled_only:
        query = query.filter(UrlBlocklistEntry.enabled.is_(True))
    return query.scalar() or 0


def add_entry(raw, note=None, commit=True):
    pattern, is_regex = parse_pattern(raw)
    existing = (
        db.session.query(UrlBlocklistEntry)
        .filter(db.func.lower(UrlBlocklistEntry.pattern) == pattern.lower())
        .one_or_none()
    )
    if existing is not None:
        if not existing.enabled:
            existing.enabled = True
            db.session.add(existing)
            if commit:
                db.session.commit()
            return existing
        raise ValueError("%s is already on the blocklist." % pattern)
    entry = UrlBlocklistEntry(
        pattern=pattern,
        is_regex=is_regex,
        note=(note or "").strip()[:MAX_NOTE_LENGTH] or None,
    )
    db.session.add(entry)
    if commit:
        db.session.commit()
    return entry


def remove_entry(entry_id):
    entry = db.session.query(UrlBlocklistEntry).get(entry_id)
    if entry is None:
        return False
    db.session.delete(entry)
    db.session.commit()
    return True


def set_entry_enabled(entry_id, enabled):
    entry = db.session.query(UrlBlocklistEntry).get(entry_id)
    if entry is None:
        return False
    entry.enabled = bool(enabled)
    db.session.add(entry)
    db.session.commit()
    return True


def seed_url_blocklist():
    """Populate the list once from the bundled file. Idempotent, best-effort,
    and never blocks startup.

    Guarded by a SiteSetting marker instead of an emptiness check so that an
    admin who deliberately clears the list keeps it cleared.
    """
    try:
        if (get_setting(SEEDED_SETTING, "") or "").strip():
            return
        seen = {
            pattern.lower()
            for (pattern,) in db.session.query(UrlBlocklistEntry.pattern).all()
        }
        rows = []
        for seed_file in _SEED_FILES:
            if not os.path.isfile(seed_file):
                continue
            note = "seeded:%s" % os.path.basename(seed_file)[:MAX_NOTE_LENGTH - 8]
            with open(seed_file, "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    try:
                        pattern, is_regex = parse_pattern(line)
                    except ValueError:
                        continue
                    lowered = pattern.lower()
                    if lowered in seen:
                        continue
                    seen.add(lowered)
                    rows.append({"pattern": pattern, "is_regex": is_regex, "note": note,
                                 "enabled": True, "hit_count": 0,
                                 "created_at": _datetime.datetime.utcnow()})
        if rows:
            # bulk_insert_mappings rather than 40k+ ORM objects: the shipped
            # hosts list alone is ~42k rows and per-object INSERT is minutes.
            db.session.bulk_insert_mappings(UrlBlocklistEntry, rows)
        set_setting(SEEDED_SETTING, _datetime.datetime.utcnow().isoformat())
        db.session.commit()
    except Exception:
        db.session.rollback()


def add_entries_bulk(text, note=None):
    """Import many lines at once (paste or file upload).

    Tolerates bare entries, hosts-file lines and comments. Returns a summary
    dict: ``added``, ``duplicates``, ``exempt`` (skipped because the domain
    belongs to a site we aggregate), and ``errors`` (list of ``(line, reason)``,
    capped so one bad paste cannot balloon the response).
    """
    seen = {
        pattern.lower()
        for (pattern,) in db.session.query(UrlBlocklistEntry.pattern).all()
    }
    exempt = _exempt_hosts()
    added, duplicates, exempt_skipped, errors = 0, 0, [], []
    rows = []
    for line in (text or "").splitlines():
        if not normalize_raw_line(line):
            continue
        try:
            pattern, is_regex = parse_pattern(line)
        except ValueError as error:
            if len(errors) < 25:
                errors.append((line.strip()[:120], str(error)))
            continue
        lowered = pattern.lower()
        if lowered in seen:
            duplicates += 1
            continue
        # Never import a domain that would block one of our own sources; report
        # it instead of silently dropping or silently breaking those links.
        if not is_regex and entry_form(pattern) == "domain":
            key = lowered[1:] if lowered.startswith(".") else lowered
            if any(parent in exempt for parent in _parent_domains(key)) or key in exempt:
                if len(exempt_skipped) < 100:
                    exempt_skipped.append(pattern)
                continue
        seen.add(lowered)
        rows.append({"pattern": pattern, "is_regex": is_regex,
                     "note": (note or "imported")[:MAX_NOTE_LENGTH],
                     "enabled": True, "hit_count": 0,
                     "created_at": _datetime.datetime.utcnow()})
        added += 1
    if rows:
        db.session.bulk_insert_mappings(UrlBlocklistEntry, rows)
        db.session.commit()
    return {"added": added, "duplicates": duplicates,
            "exempt": exempt_skipped, "errors": errors}


__all__ = [
    "AUTOBAN_DURATION_SETTING",
    "AUTOBAN_REASON",
    "AUTOBAN_SETTING",
    "DEFAULT_AUTOBAN_DURATION",
    "autoban_duration",
    "set_autoban_duration",
    "REJECTION_MESSAGE",
    "UrlBlocklistEntry",
    "add_entries_bulk",
    "add_entry",
    "entry_form",
    "normalize_raw_line",
    "autoban_enabled",
    "entry_count",
    "find_match",
    "list_entries",
    "parse_pattern",
    "record_hit",
    "remove_entry",
    "seed_url_blocklist",
    "set_autoban_enabled",
    "set_entry_enabled",
]
