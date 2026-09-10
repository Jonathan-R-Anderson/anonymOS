"""What this hub carries, published so somebody can actually connect to it.

Federation is only useful if people can find it. This is the public answer to
"which newsgroups do you carry and how do I read them", built from what the hub
ACTUALLY serves rather than from what anybody intended it to serve.

THE PAGE MUST NEVER TALK TO THE HUB
-----------------------------------
This site has already taken an outage from exactly that shape: the front page
did an inline news sync inside the request, and one slow upstream hung `GET /`
until the whole site read as down while every API endpoint stayed fine. So the
catalogue is refreshed by the background sync loop and cached, and rendering
reads the cache and nothing else. A hub that is slow, wedged or gone makes the
page slightly stale. It cannot make the page hang.

WHY THE HUB IS ASKED RATHER THAN THE ADMIN CONFIG
-------------------------------------------------
The group MAPPINGS in the admin panel say which newsgroups are imported into
which local boards. That is a different question from what the hub serves to a
peer, and publishing the mapping as though it were the catalogue would advertise
groups a connecting reader cannot fetch — and omit ones they can. The mapping is
still shown, as what each group feeds locally, which is the part an operator
deciding whether to peer with us actually wants to know.
"""

import datetime as _datetime
import json

from shared import app

SETTING = "nntp_hub_catalog"

# Where a stranger connects. Settings rather than constants because the hub can
# be moved without redeploying, and a published address that has drifted from
# reality is worse than none — somebody follows it and concludes the federation
# is dead.
HOST_SETTING = "nntp_hub_public_host"
PORT_SETTING = "nntp_hub_public_port"
TLS_SETTING = "nntp_hub_public_tls"
NOTICE_SETTING = "nntp_hub_public_notice"
# Where the BACKEND looks for the hub, when neither the service name nor the
# published address is right. Separate from the published address because what
# a stranger connects to and what this process can reach are different
# questions on a deployment mid-migration.
PROBE_HOST_SETTING = "nntp_hub_probe_host"

# How the backend itself reaches the hub, which is not what strangers use: in
# the cluster it is a service name on the internal network.
INTERNAL_HOST = "nntp-hub"
INTERNAL_PORT = 119

# Beyond this the catalogue is shown as stale rather than current. A number
# somebody reads as live when it is a day old is worse than an admitted gap.
STALE_AFTER_SECONDS = 3 * 3600


def connection():
    """How to reach this hub, for publication."""
    from model.SiteSetting import get_setting

    host = (get_setting(HOST_SETTING, "") or "").strip()
    if not host:
        # The site's own domain is the sane default: the hub runs beside it and
        # port 119 is published from the same host.
        host = (app.config.get("DOMAIN") or app.config.get("SERVER_NAME")
                or "syndichan.org")
    try:
        port = int(str(get_setting(PORT_SETTING, "") or INTERNAL_PORT).strip())
    except (TypeError, ValueError):
        port = INTERNAL_PORT
    tls = str(get_setting(TLS_SETTING, "") or "").strip().lower() in (
        "1", "true", "yes", "on")
    return {
        "host": host,
        "port": port,
        "tls": tls,
        "notice": (get_setting(NOTICE_SETTING, "") or "").strip(),
    }


def refresh(client_factory=None):
    """Ask the hub what it carries and cache the answer. Never raises.

    Called from the sync loop, never from a request. Returns the catalogue it
    stored, or the previous one when the hub could not be reached — a failed
    refresh must not erase a catalogue that was correct an hour ago and will be
    correct again shortly.
    """
    from model.SiteSetting import set_setting
    from shared import db

    previous = catalog()
    try:
        groups = _ask_hub(client_factory)
    except Exception as error:
        app.logger.info("nntp hub catalog: could not refresh (%s)", error)
        return previous

    record = {
        "groups": groups,
        "refreshed_at": _datetime.datetime.utcnow().isoformat() + "Z",
    }
    try:
        set_setting(SETTING, json.dumps(record))
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("nntp hub catalog: could not store")
        return previous
    return record


def probe_targets():
    """Where to look for our own hub, best first.

    More than one because the answer differs by deployment and changes without
    warning. In the cluster `nntp-hub` is a Service name; on this deployment
    that Service currently has NO endpoints — the hub still runs under compose
    on the host, and the StatefulSet sits at zero replicas pending a cutover —
    so the internal name resolves and refuses. The published address works
    today, and the Service name will work after the cutover.

    Trying both means the catalogue keeps working across that change instead of
    going quietly empty on the day it happens, which is the sort of breakage
    nobody attributes to a DNS record for a week.
    """
    from model.SiteSetting import get_setting

    targets = []
    override = (get_setting(PROBE_HOST_SETTING, "") or "").strip()
    if override:
        targets.append((override, INTERNAL_PORT))
    targets.append((INTERNAL_HOST, INTERNAL_PORT))
    published = connection()
    if published["host"]:
        targets.append((published["host"], published["port"]))
    seen, ordered = set(), []
    for target in targets:
        if target not in seen:
            seen.add(target)
            ordered.append(target)
    return ordered


def _ask_hub(client_factory=None):
    """LIST ACTIVE against our hub. Returns [{name, articles}].

    `list_active_groups` yields (name, high, low) tuples.
    """
    from services.nntpchan.client import NNTPClient

    if client_factory is None:
        last_error = None
        for host, port in probe_targets():
            try:
                return _ask_one(
                    lambda: NNTPClient(host, port, use_tls=False, timeout=15))
            except Exception as error:
                last_error = error
                app.logger.debug("nntp hub catalog: %s:%s did not answer (%s)",
                                 host, port, error)
        raise last_error or OSError("no hub address answered")
    return _ask_one(client_factory)


def _ask_one(factory):
    groups = []
    with factory() as client:
        for entry in client.list_active_groups("*"):
            try:
                name, high, low = entry[0], int(entry[1]), int(entry[2])
            except (TypeError, ValueError, IndexError):
                continue
            name = str(name).strip()
            if not name:
                continue
            # high MINUS low, not high. A group whose old articles have expired
            # still reports a large high-water mark, and publishing that as the
            # article count overstates what a connecting peer would receive.
            groups.append({
                "name": name,
                "articles": max(0, high - low + 1) if high >= low else 0,
            })
    groups.sort(key=lambda item: item["name"])
    return groups


def catalog():
    """The cached catalogue, or an empty one. Never touches the network."""
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING, "") or "{}")
    except ValueError:
        return {"groups": [], "refreshed_at": None}
    if not isinstance(stored, dict):
        return {"groups": [], "refreshed_at": None}
    stored.setdefault("groups", [])
    stored.setdefault("refreshed_at", None)
    return stored


def is_stale(record=None, now=None):
    """Whether the catalogue is old enough that it should say so.

    A list somebody reads as live when it is a day old is worse than an
    admitted gap: they conclude a group exists, connect, and find nothing.
    """
    record = record if record is not None else catalog()
    stamp = (record or {}).get("refreshed_at")
    if not stamp:
        return True
    try:
        when = _datetime.datetime.fromisoformat(stamp.rstrip("Z"))
    except ValueError:
        return True
    now = now or _datetime.datetime.utcnow()
    return (now - when).total_seconds() > STALE_AFTER_SECONDS


def local_boards_by_group():
    """{newsgroup: [board name]} for the ENABLED mappings.

    What each group feeds locally — the part an operator deciding whether to
    peer with us actually wants, and the part the admin panel owns.
    """
    try:
        from model.Board import Board
        from model.NntpGroupMap import NntpGroupMap
        from shared import db

        rows = (db.session.query(NntpGroupMap.newsgroup, Board.name)
                .join(Board, Board.id == NntpGroupMap.board_id)
                .filter(NntpGroupMap.enabled.is_(True))
                .order_by(NntpGroupMap.newsgroup.asc(), Board.name.asc())
                .all())
    except Exception:
        app.logger.debug("nntp hub catalog: could not read group maps",
                         exc_info=True)
        return {}
    mapping = {}
    for newsgroup, board in rows:
        mapping.setdefault(newsgroup, []).append(board)
    return mapping


def published():
    """Everything the federation page needs, from cache and the database only."""
    record = catalog()
    boards = local_boards_by_group()
    groups = []
    for group in record.get("groups") or []:
        groups.append({**group, "boards": boards.get(group["name"], [])})
    # Mapped groups the hub does not carry are worth showing rather than
    # hiding: they are configured here and absent there, which is either a
    # mapping for a group we only pull from a peer, or a mistake. Silently
    # dropping them makes the second one invisible.
    #
    # But ONLY when there is a catalogue to compare against. With an empty one —
    # the hub never reached, or not asked yet — every mapped group would be
    # listed as "not carried", which is a claim about the hub made from having
    # no information about the hub. It reads as fact and is frequently the exact
    # opposite of the truth.
    carried = {group["name"] for group in groups}
    unlisted = sorted(name for name in boards
                      if name not in carried) if groups else []
    return {
        "connection": connection(),
        "groups": groups,
        "refreshed_at": record.get("refreshed_at"),
        "stale": is_stale(record),
        "mapped_elsewhere": [{"name": name, "boards": boards[name]}
                             for name in unlisted],
    }
