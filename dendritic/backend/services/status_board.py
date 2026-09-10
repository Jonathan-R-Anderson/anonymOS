"""Turning monitor probes into the thing a status page shows.

Three jobs: record a probe (and roll it into its day as it arrives), assemble
the board a page renders, and forget raw probes once they are summarised.

THE HONESTY RULES, WHICH ARE THE WHOLE POINT
--------------------------------------------
A status page is only worth serving if it is believed, and it is believed only
if it refuses to flatter itself. Three rules, each of which costs something:

  * A day nobody probed is grey, not green. Uptime is a measurement, and an
    unmeasured day has no measurement. Filling it in would make the headline
    number best exactly when monitoring is most broken.

  * Overall status is the WORST component, not the average. Averaging says
    "94% operational" while the thing somebody came to use is down.

  * Probe detail is never shown publicly. It is written by a volunteer's client
    and can quote an internal hostname or a stack error, so the public sees
    up/down/degraded and the operator sees why.
"""

import datetime as _datetime

# A component that is failing for some monitors and fine for others is not down
# — it is degraded, and saying "down" would be as wrong as saying "up". This is
# the fraction of recent probes that must fail before it stops being degraded
# and starts being an outage.
OUTAGE_FAILURE_RATIO = 0.5

# How far back "right now" reaches. Long enough that one slow probe cannot flip
# the banner, short enough that a fixed outage clears without waiting a day.
CURRENT_WINDOW_MINUTES = 15

OPERATIONAL = "operational"
DEGRADED = "degraded"
OUTAGE = "outage"
UNKNOWN = "unknown"

# Worst-first. The banner takes the maximum, so this order IS the policy.
SEVERITY = {UNKNOWN: 0, OPERATIONAL: 1, DEGRADED: 2, OUTAGE: 3}


def _utcnow():
    return _datetime.datetime.utcnow()


def record_probe(component_key, node_id, ok, latency_ms=None, detail="",
                 country_code=None, now=None):
    """Store one probe and fold it into its day. Caller commits.

    The rollup is updated here rather than by a nightly job because a nightly
    job means the page is wrong until it runs, and wrong in the flattering
    direction — an outage at 09:00 would not appear on the bar until midnight.
    """
    from model.Status import StatusDay, StatusProbe
    from shared import db

    now = now or _utcnow()
    latency = None
    if latency_ms is not None:
        try:
            latency = max(0, int(latency_ms))
        except (TypeError, ValueError):
            latency = None

    db.session.add(StatusProbe(
        component_key=component_key, node_id=node_id, ok=bool(ok),
        latency_ms=latency, detail=(detail or "")[:300],
        country_code=(country_code or None), at=now,
    ))

    day = now.date()
    row = (
        db.session.query(StatusDay)
        .filter(StatusDay.component_key == component_key, StatusDay.day == day)
        .one_or_none()
    )
    if row is None:
        row = StatusDay(component_key=component_key, day=day, probes=0, failures=0,
                        latency_sum_ms=0, latency_count=0, worst_latency_ms=0)
        db.session.add(row)
    row.probes = (row.probes or 0) + 1
    if not ok:
        row.failures = (row.failures or 0) + 1
    # Latency is recorded only for probes that SUCCEEDED. A timeout produces a
    # latency equal to the timeout, and averaging that in makes an outage look
    # like a slowdown — the two need to stay distinguishable.
    if ok and latency is not None:
        row.latency_sum_ms = (row.latency_sum_ms or 0) + latency
        row.latency_count = (row.latency_count or 0) + 1
        if latency > (row.worst_latency_ms or 0):
            row.worst_latency_ms = latency
    return row


def prune_probes(now=None):
    """Forget raw probes once their day is summarised. Returns rows removed."""
    from model.Status import RAW_RETENTION_DAYS, StatusProbe
    from shared import db

    cutoff = (now or _utcnow()) - _datetime.timedelta(days=RAW_RETENTION_DAYS)
    removed = (
        db.session.query(StatusProbe)
        .filter(StatusProbe.at < cutoff)
        .delete(synchronize_session=False)
    )
    if removed:
        db.session.commit()
    return removed


def _state_from(probes, failures):
    if not probes:
        return UNKNOWN
    if not failures:
        return OPERATIONAL
    return OUTAGE if (failures / float(probes)) >= OUTAGE_FAILURE_RATIO else DEGRADED


def current_states(components, now=None):
    """Each component's state right now, from the last few minutes of probes."""
    from model.Status import StatusProbe
    from shared import db

    now = now or _utcnow()
    since = now - _datetime.timedelta(minutes=CURRENT_WINDOW_MINUTES)
    rows = (
        db.session.query(StatusProbe.component_key, StatusProbe.ok)
        .filter(StatusProbe.at >= since)
        .all()
    )
    tally = {}
    for key, ok in rows:
        seen, failed = tally.get(key, (0, 0))
        tally[key] = (seen + 1, failed + (0 if ok else 1))

    out = {}
    for component in components:
        seen, failed = tally.get(component.key, (0, 0))
        out[component.key] = {
            "state": _state_from(seen, failed),
            "probes": seen,
            "failures": failed,
        }
    return out


def history(component_keys, days, now=None):
    """Per-component daily bars, oldest first, with gaps preserved as None.

    The gaps are the point. A missing day is rendered grey and excluded from the
    uptime average, so a week when nothing was monitored neither counts as
    perfect nor drags the number down.
    """
    from model.Status import StatusDay
    from shared import db

    now = now or _utcnow()
    today = now.date()
    first = today - _datetime.timedelta(days=days - 1)
    rows = (
        db.session.query(StatusDay)
        .filter(StatusDay.day >= first, StatusDay.component_key.in_(list(component_keys)))
        .all()
    )
    by_key = {}
    for row in rows:
        by_key.setdefault(row.component_key, {})[row.day] = row

    out = {}
    for key in component_keys:
        days_for_key = by_key.get(key, {})
        bars = []
        for offset in range(days):
            day = first + _datetime.timedelta(days=offset)
            row = days_for_key.get(day)
            if row is None or not row.probes:
                bars.append({"day": day.isoformat(), "uptime": None, "state": UNKNOWN,
                             "probes": 0, "failures": 0, "mean_latency_ms": None})
                continue
            bars.append({
                "day": day.isoformat(),
                "uptime": row.uptime,
                "state": _state_from(row.probes, row.failures),
                "probes": row.probes,
                "failures": row.failures,
                "mean_latency_ms": row.mean_latency_ms,
            })
        out[key] = bars
    return out


def uptime_over(bars):
    """Average uptime across measured days only, or None if none were."""
    measured = [b["uptime"] for b in bars if b["uptime"] is not None]
    if not measured:
        return None
    return sum(measured) / len(measured)


def regional_latency(now=None, minutes=60, limit=12):
    """Mean successful latency per country over the recent window.

    Successes only: a timeout contributes the timeout value and would render an
    unreachable region as merely a slow one.
    """
    from model.Status import StatusProbe
    from shared import db

    now = now or _utcnow()
    since = now - _datetime.timedelta(minutes=minutes)
    rows = (
        db.session.query(StatusProbe.country_code, StatusProbe.latency_ms, StatusProbe.ok)
        .filter(StatusProbe.at >= since)
        .all()
    )
    tally = {}
    for country, latency, ok in rows:
        code = (country or "??").upper()
        seen, failed, total, counted = tally.get(code, (0, 0, 0, 0))
        seen += 1
        if not ok:
            failed += 1
        elif latency is not None:
            total += latency
            counted += 1
        tally[code] = (seen, failed, total, counted)

    out = []
    for code, (seen, failed, total, counted) in tally.items():
        out.append({
            "country": code,
            "probes": seen,
            "failures": failed,
            "mean_latency_ms": int(total / counted) if counted else None,
        })
    # Slowest first: the interesting row is the region having a bad time, and
    # a region with no successful probe at all is the most interesting of all.
    out.sort(key=lambda r: (r["mean_latency_ms"] is not None, r["mean_latency_ms"] or 0),
             reverse=True)
    return out[:limit]


def overall_state(states):
    """The banner. The WORST component, never an average."""
    if not states:
        return UNKNOWN
    return max(states, key=lambda s: SEVERITY.get(s, 0))


def board(days=None, now=None, include_detail=False):
    """Everything the status page renders, in one call.

    include_detail carries the monitors' own error strings and is for the ADMIN
    view only: those are written by volunteer clients and can quote internal
    hostnames or stack traces.
    """
    from model.Status import (
        HISTORY_DAYS, StatusComponent, StatusIncident, StatusIncidentUpdate,
    )
    from shared import db

    now = now or _utcnow()
    days = days or HISTORY_DAYS

    components = (
        db.session.query(StatusComponent)
        .filter(StatusComponent.enabled.is_(True))
        .order_by(StatusComponent.position.asc(), StatusComponent.key.asc())
        .all()
    )
    keys = [c.key for c in components]
    states = current_states(components, now=now)
    bars = history(keys, days, now=now)

    rendered = []
    for component in components:
        component_bars = bars.get(component.key, [])
        rendered.append({
            "key": component.key,
            "name": component.name,
            "description": component.description,
            "state": states[component.key]["state"],
            "probes_recent": states[component.key]["probes"],
            "failures_recent": states[component.key]["failures"],
            "bars": component_bars,
            "uptime": uptime_over(component_bars),
        })

    # Open incidents first, then recently resolved ones — a status page is read
    # for "what is wrong now" and then for "what happened".
    incidents = (
        db.session.query(StatusIncident)
        .filter(StatusIncident.started_at >= now - _datetime.timedelta(days=days))
        .order_by(StatusIncident.started_at.desc())
        .limit(50)
        .all()
    )
    incident_ids = [i.id for i in incidents]
    updates = {}
    if incident_ids:
        for update in (
            db.session.query(StatusIncidentUpdate)
            .filter(StatusIncidentUpdate.incident_id.in_(incident_ids))
            .order_by(StatusIncidentUpdate.at.desc())
            .all()
        ):
            updates.setdefault(update.incident_id, []).append({
                "status": update.status,
                "body": update.body,
                "at": update.at.isoformat() + "Z",
            })

    rendered_incidents = [{
        "id": i.id,
        "title": i.title,
        "component_key": i.component_key,
        "impact": i.impact,
        "status": i.status,
        "open": i.is_open,
        "started_at": i.started_at.isoformat() + "Z",
        "resolved_at": (i.resolved_at.isoformat() + "Z") if i.resolved_at else None,
        "updates": updates.get(i.id, []),
    } for i in incidents]

    open_incidents = [i for i in rendered_incidents if i["open"]]

    # An open incident overrides a green banner. Probes can look fine while
    # something the monitors do not check is broken, and the operator saying so
    # outranks the absence of a failing probe.
    state = overall_state([c["state"] for c in rendered])
    if open_incidents and state == OPERATIONAL:
        state = DEGRADED

    out = {
        "generated_at": now.isoformat() + "Z",
        "state": state,
        "components": rendered,
        "incidents": rendered_incidents,
        "open_incidents": open_incidents,
        "regions": regional_latency(now=now),
        "history_days": days,
        "network": _network_metrics(),
        "traffic_history": traffic_history(now=now),
    }
    if include_detail:
        out["recent_failures"] = recent_failures(now=now)
    return out


def sample_traffic(now=None):
    """Record one throughput reading, at most once per interval.

    Called from both the probe ingest and the page render. Guarded rather than
    scheduled because this project runs no reliable cron: a sampler that only
    fires on a timer stops silently when the timer does, and a gap in the graph
    is indistinguishable from a quiet network.

    The guard is the reason it is safe to call from everywhere. Several monitors
    posting within the same minute produce one sample, not one each.
    """
    from model.Status import (
        NetworkTrafficSample, TRAFFIC_RETENTION_DAYS, TRAFFIC_SAMPLE_SECONDS,
    )
    from shared import db

    now = now or _utcnow()
    latest = (
        db.session.query(NetworkTrafficSample.at)
        .order_by(NetworkTrafficSample.at.desc())
        .first()
    )
    if latest is not None:
        age = (now - latest[0]).total_seconds()
        # Negative age means a clock moved backwards. Skipping is right: writing
        # a sample "before" the newest one puts a point out of order in a series
        # whose whole meaning is its order.
        if age < TRAFFIC_SAMPLE_SECONDS:
            return None

    metrics = _network_metrics()
    if metrics.get("bytes_per_second") is None:
        return None

    sample = NetworkTrafficSample(
        at=now,
        bytes_per_second=int(metrics.get("bytes_per_second") or 0),
        requests_per_second=float(metrics.get("requests_per_second") or 0.0),
        reporting_nodes=int(metrics.get("traffic_reporting_nodes") or 0),
        active_nodes=int(metrics.get("nodes") or 0),
    )
    db.session.add(sample)
    cutoff = now - _datetime.timedelta(days=TRAFFIC_RETENTION_DAYS)
    db.session.query(NetworkTrafficSample).filter(
        NetworkTrafficSample.at < cutoff
    ).delete(synchronize_session=False)
    db.session.commit()
    return sample


def traffic_history(hours=24, now=None, limit=600):
    """Recent throughput samples, oldest first, for the chart.

    reporting_nodes rides along on every point so the page can grey a stretch
    where nobody was reporting. A flat line at zero because the network was idle
    and a flat line at zero because nothing was measuring are the same picture
    and completely different facts.
    """
    from model.Status import NetworkTrafficSample
    from shared import db

    now = now or _utcnow()
    since = now - _datetime.timedelta(hours=hours)
    rows = (
        db.session.query(NetworkTrafficSample)
        .filter(NetworkTrafficSample.at >= since)
        .order_by(NetworkTrafficSample.at.asc())
        .limit(limit)
        .all()
    )
    return [{
        "at": row.at.isoformat() + "Z",
        "bytes_per_second": int(row.bytes_per_second or 0),
        "requests_per_second": float(row.requests_per_second or 0.0),
        "reporting_nodes": int(row.reporting_nodes or 0),
        "measured": bool(row.reporting_nodes),
    } for row in rows]


def recent_failures(now=None, minutes=180, limit=40):
    """Failing probes with the monitor's own reason. ADMIN ONLY."""
    from model.Status import StatusProbe
    from shared import db

    now = now or _utcnow()
    since = now - _datetime.timedelta(minutes=minutes)
    rows = (
        db.session.query(StatusProbe)
        .filter(StatusProbe.at >= since, StatusProbe.ok.is_(False))
        .order_by(StatusProbe.at.desc())
        .limit(limit)
        .all()
    )
    return [{
        "component_key": r.component_key,
        "node_id": (r.node_id or "")[:16],
        "country": r.country_code,
        "detail": r.detail,
        "at": r.at.isoformat() + "Z",
    } for r in rows]


def _network_metrics():
    """Storage capacity and node counts, from the existing heartbeat records.

    Read through the same summary the rest of the site uses rather than
    recomputed here: two numbers for "how big is the network" that can disagree
    is a bug waiting to be reported as an outage.
    """
    try:
        from model.StorageNode import network_summary

        summary = network_summary()
        return {
            "nodes": summary.get("nodes"),
            "capacity_bytes": summary.get("capacity_bytes"),
            "capacity_human": summary.get("capacity_human"),
            "active_window_seconds": summary.get("active_window_seconds"),
            # Summed from what nodes report about themselves. This server never
            # sees peer-to-peer shard traffic, so a figure derived from its own
            # logs would describe the website and call it the network.
            "traffic_human": summary.get("traffic_human"),
            "bytes_per_second": summary.get("bytes_per_second"),
            "requests_per_second": summary.get("requests_per_second"),
            "traffic_reporting_nodes": summary.get("traffic_reporting_nodes"),
        }
    except Exception:
        # The status page must render when the database is unhappy — that is
        # the moment somebody is looking at it.
        return {"nodes": None, "capacity_bytes": None,
                "capacity_human": None, "active_window_seconds": None,
                "traffic_human": None, "bytes_per_second": None,
                "requests_per_second": None, "traffic_reporting_nodes": None}


# The probe URLs are checked against the running app, not guessed. The first
# seeding used /healthy and /api/v1/boards; neither existed — one 404s and the
# other 308s to a trailing slash — so the monitor correctly reported the site as
# down when it was fine. A default that reports a false outage is worse than no
# default, because it teaches the operator to disbelieve the page.
DEFAULT_COMPONENTS = (
    ("website", "Website", "Pages, posting and media.", "/health", 8000, 10),
    ("api", "API", "The public JSON API.", "/api/v1/boards/", 8000, 20),
    ("dht", "Distributed storage", "The peer-to-peer store that holds media.",
     "/api/v1/storage/nodes/status", 10000, 30),
    ("chain", "Settlement", "Epoch settlement on Ethereum Mainnet.", "/epochs.json", 12000, 40),
    ("federation", "Federation", "NNTP and aggregated boards.", "/federation", 10000, 50),
)


def ensure_default_components():
    """Create the starting component list once, if none exists.

    Only when the table is EMPTY. Re-adding a component the operator disabled
    would be the code arguing with the person running it.
    """
    from model.Status import StatusComponent
    from shared import db

    if db.session.query(StatusComponent.key).first() is not None:
        return 0
    for key, name, description, url, timeout, position in DEFAULT_COMPONENTS:
        db.session.add(StatusComponent(
            key=key, name=name, description=description,
            probe_url=url, timeout_ms=timeout, position=position, enabled=True))
    db.session.commit()
    return len(DEFAULT_COMPONENTS)
