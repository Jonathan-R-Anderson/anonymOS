"""The status page's data: what is monitored, what probed it, and what broke.

WHY THE PROBES COME FROM NODES AND NOT FROM HERE
------------------------------------------------
A status page served by the thing it monitors reports "all systems operational"
right up until it stops answering at all, and then it reports nothing. The
outage and the page's ability to describe the outage fail together, which is the
one moment the page exists for.

So the checks are made by MONITOR nodes — volunteers running the client with the
monitor role — from wherever they are, and posted here signed. This server
stores and renders them; it does not grade itself. When it is down, the monitors
still have the data, which is why the page is also served from them at
status.<domain> rather than only from here.

WHY A DAILY ROLLUP RATHER THAN COUNTING RAW PROBES
--------------------------------------------------
The 90-day bar is the whole point of the page, and computing it from raw probes
means scanning every check ever made on every page load. With a handful of
components and a handful of monitors that is already millions of rows a quarter.

So each probe increments a per-component, per-day counter as it arrives — O(1),
no scan — and the raw rows are kept only long enough to answer "what is the
latency from Europe right now", then pruned.

A DAY WITH NO PROBES IS NOT A DAY THAT WAS UP
---------------------------------------------
The single most important rule here. If nobody was monitoring, the honest answer
is "no data" and the bar is grey. Filling it green because nothing reported a
failure would mean the page's headline number is highest exactly when the
monitoring is most broken.
"""

import datetime as _datetime

from shared import db

# Raw probes answer "how does it look right now, from where". Anything older is
# already summarised in StatusDay, so keeping it is cost without information.
RAW_RETENTION_DAYS = 8

# What the bar chart covers, matching what people expect from a status page.
HISTORY_DAYS = 90

IMPACT_NONE = "none"
IMPACT_MINOR = "minor"
IMPACT_MAJOR = "major"
IMPACT_CRITICAL = "critical"
IMPACTS = (IMPACT_NONE, IMPACT_MINOR, IMPACT_MAJOR, IMPACT_CRITICAL)

# The lifecycle a status page walks an incident through. Kept in this order
# because the page renders the newest update first and colours by the latest.
INCIDENT_INVESTIGATING = "investigating"
INCIDENT_IDENTIFIED = "identified"
INCIDENT_MONITORING = "monitoring"
INCIDENT_RESOLVED = "resolved"
INCIDENT_STATUSES = (
    INCIDENT_INVESTIGATING, INCIDENT_IDENTIFIED,
    INCIDENT_MONITORING, INCIDENT_RESOLVED,
)


class StatusComponent(db.Model):
    """One thing that can be up or down, and how a monitor checks it."""

    __tablename__ = "status_component"

    key = db.Column(db.String(48), primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    description = db.Column(db.String(300), nullable=False, default="")
    # What a monitor node requests. Kept here rather than in the client so the
    # set of checks can change without every volunteer updating a binary.
    probe_url = db.Column(db.String(300), nullable=False, default="")
    # A probe is a failure unless it answers within this. Per-component because
    # a DHT lookup and a static page have nothing to do with each other.
    timeout_ms = db.Column(db.Integer, nullable=False, default=8000)
    position = db.Column(db.Integer, nullable=False, default=0)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


class StatusProbe(db.Model):
    """One check, by one monitor, at one moment. Pruned after RAW_RETENTION_DAYS."""

    __tablename__ = "status_probe"

    id = db.Column(db.BigInteger, primary_key=True)
    component_key = db.Column(db.String(48), nullable=False, index=True)
    # The reporting monitor. Not a foreign key: a monitor that stops running
    # should not take its history with it.
    node_id = db.Column(db.String(128), nullable=False, index=True)
    # Country-level only, from the same geoip the node map uses. Enough to say
    # "slow from South America", nowhere near enough to locate a volunteer.
    country_code = db.Column(db.String(2), nullable=True, index=True)
    ok = db.Column(db.Boolean, nullable=False)
    latency_ms = db.Column(db.Integer, nullable=True)
    # Why it failed, in the monitor's words. Shown to the operator, never to the
    # public: it can carry an internal hostname or an error from our own stack.
    detail = db.Column(db.String(300), nullable=False, default="")
    at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)


class StatusDay(db.Model):
    """One component's day, rolled up as probes arrive.

    `probes` being zero is the "no data" case and must stay distinguishable from
    `failures` being zero. They are different facts and the bar colours differ.
    """

    __tablename__ = "status_day"

    component_key = db.Column(db.String(48), primary_key=True)
    day = db.Column(db.Date, primary_key=True)
    probes = db.Column(db.Integer, nullable=False, default=0)
    failures = db.Column(db.Integer, nullable=False, default=0)
    # Sum and count rather than a stored average: an average cannot be merged
    # with another average without weighting, and this is updated incrementally
    # from many monitors at once.
    latency_sum_ms = db.Column(db.BigInteger, nullable=False, default=0)
    latency_count = db.Column(db.Integer, nullable=False, default=0)
    worst_latency_ms = db.Column(db.Integer, nullable=False, default=0)

    @property
    def uptime(self):
        """Fraction up, or None when nothing measured this day."""
        if not self.probes:
            return None
        return (self.probes - self.failures) / float(self.probes)

    @property
    def mean_latency_ms(self):
        if not self.latency_count:
            return None
        return int(self.latency_sum_ms / self.latency_count)


class StatusIncident(db.Model):
    """A human-written account of something being wrong.

    Deliberately not opened automatically. A probe failing tells you something
    changed; it does not tell you what, who it affects, or whether you already
    know. Auto-filed incidents train people to ignore the page, and a status
    page nobody believes is worse than none.
    """

    __tablename__ = "status_incident"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    # Null means "the whole site", which is a real and common case.
    component_key = db.Column(db.String(48), nullable=True, index=True)
    impact = db.Column(db.String(16), nullable=False, default=IMPACT_MINOR)
    status = db.Column(db.String(16), nullable=False, default=INCIDENT_INVESTIGATING, index=True)
    started_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    @property
    def is_open(self):
        return self.status != INCIDENT_RESOLVED


class StatusIncidentUpdate(db.Model):
    """One posting on an incident. The narrative, in order."""

    __tablename__ = "status_incident_update"

    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey("status_incident.id"),
                            nullable=False, index=True)
    status = db.Column(db.String(16), nullable=False, default=INCIDENT_INVESTIGATING)
    body = db.Column(db.Text, nullable=False, default="")
    at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)


class StatusReport(db.Model):
    """A visitor saying the site looks broken to them.

    Accepted from anybody, with no login, because the person best placed to
    notice an outage is somebody it is happening to — and requiring them to sign
    in to report that they cannot use the site is a joke the site is telling at
    their expense.
    """

    __tablename__ = "status_report"

    id = db.Column(db.Integer, primary_key=True)
    component_key = db.Column(db.String(48), nullable=True)
    body = db.Column(db.String(1000), nullable=False, default="")
    # Country only, and only to spot a regional outage in the reports
    # themselves. No IP is stored: somebody reporting a fault is not a suspect.
    country_code = db.Column(db.String(2), nullable=True)
    at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow, index=True)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False, index=True)


class NetworkTrafficSample(db.Model):
    """One reading of network-wide throughput, kept so it can be drawn over time.

    The live figure is a sum of what nodes report right now, which answers "how
    busy is it" and nothing else. A graph needs history, and history has to be
    written down as it happens — it cannot be recovered later from a number that
    was only ever instantaneous.

    Sampled on a schedule rather than on every heartbeat: nodes report on their
    own clocks, so recording per-heartbeat would produce a series whose point
    spacing depends on how many nodes happen to be running. Even spacing is what
    makes a line chart mean anything.
    """

    __tablename__ = "network_traffic_sample"

    id = db.Column(db.BigInteger, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, index=True,
                   default=_datetime.datetime.utcnow)
    bytes_per_second = db.Column(db.BigInteger, nullable=False, default=0)
    requests_per_second = db.Column(db.Float, nullable=False, default=0.0)
    # How many nodes the reading covers. Without it a dip is unreadable: a
    # quiet network and a network that stopped reporting look identical.
    reporting_nodes = db.Column(db.Integer, nullable=False, default=0)
    active_nodes = db.Column(db.Integer, nullable=False, default=0)


# Five minutes: frequent enough that a busy hour has shape, sparse enough that a
# week of history is a few thousand rows rather than a table nobody prunes.
TRAFFIC_SAMPLE_SECONDS = 300

# What the graph can draw. Longer than the window anybody looks at, so the chart
# never runs out of data at its left edge mid-incident.
TRAFFIC_RETENTION_DAYS = 14
