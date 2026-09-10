"""The status page, its feed, and the endpoints monitor nodes talk to.

WHO MEASURES WHAT
-----------------
This server renders; it does not grade itself. Monitor nodes fetch the target
list, probe it from wherever they are, and post signed results here. Checking
from several networks at once is the only way to tell "the site is down" apart
from "the site is unreachable from one place" — a distinction no amount of
instrumentation on a single host can make.

The page itself lives at /status on this server, so it does share a failure
domain with what it reports on. That is a deliberate trade for one URL and a nav
link rather than a subdomain nobody would remember.

THE FEED IS RSS, NOT EMAIL
--------------------------
Email would mean holding a list of addresses belonging to people whose only
stated interest is knowing when a site is broken, plus delivery, bounces and
unsubscribes. RSS needs none of that: nothing is stored, nothing is sent, and
nobody has to trust us with an address to find out we are down.
"""

import datetime
import xml.etree.ElementTree as ET

from flask import Blueprint, Response, jsonify, render_template, request

from shared import app, db

status_blueprint = Blueprint("status", __name__, template_folder="template")


def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def _client_country():
    """Country only, and only for spotting a regional pattern in reports."""
    try:
        from services.client_ip import get_client_ip
        from services.geoip import country_for_ip

        return country_for_ip(get_client_ip())
    except Exception:
        return None


# --- what a person sees -----------------------------------------------------

@status_blueprint.route("/status")
def status_page():
    from services.status_board import board

    try:
        data = board()
    except Exception:
        # A status page that 500s during an outage is the joke telling itself.
        # Render the shell with nothing in it and say so.
        app.logger.exception("status board could not be assembled")
        data = {"state": "unknown", "components": [], "incidents": [],
                "open_incidents": [], "regions": [], "history_days": 90,
                "network": {}, "generated_at": None, "unavailable": True}
    # NOT `board`: base.html uses that name for an imageboard, and a status
    # "board" arriving under it made `board is defined` true with an empty
    # name — rendering a stray // link to /boards/ in the nav.
    return render_template("status.html", status_board=data)


@status_blueprint.route("/status.json")
def status_json():
    """The whole board as JSON.

    Public and CORS-open so anybody can render or archive it — including a
    monitor operator who wants to watch without loading the page.
    """
    from services.status_board import board

    try:
        data = board()
    except Exception:
        app.logger.exception("status board could not be assembled")
        return _no_store(jsonify({"state": "unknown", "unavailable": True})), 503
    response = jsonify(data)
    response.headers["Access-Control-Allow-Origin"] = "*"
    return _no_store(response)


@status_blueprint.route("/status.rss")
def status_rss():
    """Incidents and their updates, newest first.

    Each UPDATE is an item rather than each incident, because a subscriber wants
    to be told when something changed, and an incident that has been open for
    six hours has changed several times.
    """
    from services.status_board import board

    base = (app.config.get("BASE_URL") or request.url_root).rstrip("/")
    try:
        data = board()
    except Exception:
        app.logger.exception("status feed could not be assembled")
        data = {"incidents": []}

    rss = ET.Element("rss", {"version": "2.0"})
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = "%s status" % (
        app.config.get("INSTANCE_NAME") or "Syndichan")
    ET.SubElement(channel, "link").text = base + "/status"
    ET.SubElement(channel, "description").text = (
        "Incidents affecting the site and the network, as they are updated.")
    ET.SubElement(channel, "ttl").text = "5"

    items = []
    for incident in data.get("incidents", []):
        for update in incident.get("updates", []):
            items.append((update.get("at"), incident, update))
    # Newest first across every incident, not grouped by incident: a reader
    # wants the most recent thing that happened, whatever it was about.
    items.sort(key=lambda row: row[0] or "", reverse=True)

    for at, incident, update in items[:100]:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = "[%s] %s" % (
            (update.get("status") or "update").title(), incident.get("title", ""))
        link = "%s/status#incident-%s" % (base, incident.get("id"))
        ET.SubElement(item, "link").text = link
        # Per update, not per incident: a GUID that repeated across updates
        # would make every reader show only the first one.
        guid = ET.SubElement(item, "guid", {"isPermaLink": "false"})
        guid.text = "%s-incident-%s-%s" % (base, incident.get("id"), at)
        ET.SubElement(item, "description").text = update.get("body") or ""
        pub = _rfc822(at)
        if pub:
            ET.SubElement(item, "pubDate").text = pub

    body = ET.tostring(rss, encoding="utf-8", xml_declaration=True)
    return _no_store(Response(body, mimetype="application/rss+xml"))


def _rfc822(iso):
    """RSS insists on RFC-822 dates; readers that reject them show nothing."""
    if not iso:
        return None
    try:
        stamp = datetime.datetime.strptime(iso.replace("Z", ""), "%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        try:
            stamp = datetime.datetime.strptime(iso.replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            return None
    return stamp.strftime("%a, %d %b %Y %H:%M:%S +0000")


@status_blueprint.route("/status/report", methods=["POST"])
def submit_report():
    """A visitor saying it looks broken from where they are.

    No login. The person best placed to notice an outage is somebody it is
    happening to, and asking them to sign in to report that they cannot use the
    site is a joke at their expense.
    """
    from model.Status import StatusReport

    body = (request.form.get("body") or
            (request.get_json(silent=True) or {}).get("body") or "").strip()
    component = (request.form.get("component") or
                 (request.get_json(silent=True) or {}).get("component") or "").strip()
    if not body:
        return _no_store(jsonify({"error": "Say what is happening."})), 400
    if len(body) > 1000:
        body = body[:1000]

    try:
        db.session.add(StatusReport(
            component_key=component[:48] or None,
            body=body,
            country_code=_client_country(),
        ))
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("status report could not be stored")
        return _no_store(jsonify({"error": "Could not record that — try again."})), 503
    return _no_store(jsonify({"ok": True}))


# --- what a monitor node talks to -------------------------------------------

@status_blueprint.route("/api/v1/status/targets")
def probe_targets():
    """What to check, how long to wait, and where to send the answer.

    Served rather than compiled into the client so the check list can change
    without every volunteer updating a binary — which, for a monitoring fleet,
    would mean the checks can only ever be as current as the slowest operator.
    """
    from model.Status import StatusComponent

    base = (app.config.get("BASE_URL") or request.url_root).rstrip("/")
    try:
        rows = (
            db.session.query(StatusComponent)
            .filter(StatusComponent.enabled.is_(True))
            .order_by(StatusComponent.position.asc())
            .all()
        )
    except Exception:
        app.logger.exception("probe targets could not be listed")
        return _no_store(jsonify({"targets": []})), 503

    targets = []
    for row in rows:
        url = row.probe_url or ""
        if url.startswith("/"):
            url = base + url
        targets.append({
            "key": row.key,
            "name": row.name,
            "url": url,
            "timeout_ms": row.timeout_ms,
        })
    response = jsonify({
        "version": 1,
        "targets": targets,
        # A floor, not a schedule. Monitors jitter around it so a fleet does not
        # arrive in lockstep and turn monitoring into a load test.
        "interval_seconds": 60,
        "report_url": base + "/api/v1/status/report",
    })
    response.headers["Access-Control-Allow-Origin"] = "*"
    return _no_store(response)


@status_blueprint.route("/api/v1/status/report", methods=["POST"])
def ingest_probe():
    """Signed probe results from a monitor node.

    Same identity as the storage heartbeat — an Ed25519 signature over the exact
    body, from a registered node id. Unsigned reports are refused rather than
    stored-and-ignored: anybody who could post them could manufacture an outage
    on the public page, or hide one.
    """
    from services.status_coordination import validate_probe_report
    from services.status_board import record_probe

    raw = request.get_data(cache=False, as_text=False)
    try:
        payload = validate_probe_report(
            raw,
            request.headers.get("X-Syndichan-Node"),
            request.headers.get("X-Syndichan-Signature"),
        )
    except PermissionError as exc:
        return _no_store(jsonify({"error": str(exc)})), 403
    except ValueError as exc:
        return _no_store(jsonify({"error": str(exc)})), 400

    country = None
    try:
        from services.client_ip import get_client_ip
        from services.geoip import country_for_ip

        country = country_for_ip(get_client_ip())
    except Exception:
        country = None

    stored = 0
    try:
        # Sampled here rather than on a timer: monitors post roughly every
        # minute, so the series fills itself, and a sampler that only runs on a
        # schedule stops silently when the schedule does — leaving a gap that
        # looks exactly like a quiet network.
        try:
            from services.status_board import sample_traffic

            sample_traffic()
        except Exception:
            db.session.rollback()
            app.logger.debug("traffic sample skipped", exc_info=True)
        for result in payload["results"]:
            record_probe(
                component_key=result["key"],
                node_id=payload["node_id"],
                ok=result["ok"],
                latency_ms=result.get("latency_ms"),
                detail=result.get("detail", ""),
                country_code=country,
            )
            stored += 1
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("probe report could not be stored")
        return _no_store(jsonify({"error": "report could not be stored"})), 503

    return _no_store(jsonify({"ok": True, "stored": stored}))
