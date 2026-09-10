"""The catalog of lab challenge images — the site's image registry.

The syndichan worker nodes DO NOT decide which images exist. This catalog does.
An admin uploads a challenge (a Dockerfile plus supporting files); the site
packs it into a content-addressed build context, records it here, and it becomes
available on the /lab page. Deleting it here removes it from the catalog so no
new deploys reference it. A worker only ever runs the build context a deploy
hands it, verified by digest — it never chooses from a list of its own.

The packed build context is stored on the DHT as shards by a bridged node; the
authoritative copy and its digest live here so the catalog is self-contained and
the admin can manage it without a node attached.
"""
import datetime as _datetime

from shared import db


class LabChallenge(db.Model):
    __tablename__ = "lab_challenge"

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)

    # The machine's handle: an adjective-and-animal name in the style Docker
    # gives containers. `name` stays as it was — "activemq CVE-2023-46604" — but
    # it is a catalogue entry, not something two people comparing notes can say
    # out loud, and a CVE number is precisely the thing nobody remembers.
    # Assigned once from the slug and then stored, because a name that shifts
    # when the wordlist is edited is not a name. Editable by an admin.
    codename = db.Column(db.String(48), nullable=True, unique=True, index=True)
    description = db.Column(db.Text, nullable=False, default="")

    # How the worker turns the build context into a running service:
    #   "dockerfile" — the context has a Dockerfile at its root; the worker
    #                  `docker build`s it and runs the one container (the
    #                  original single-image challenge path).
    #   "compose"    — the context is a docker-compose project (vulhub-style);
    #                  the worker `docker compose up`s it, pulling the images
    #                  from the registry, and exposes the primary service. The
    #                  compose FILES live on the DHT; the IMAGES come from the
    #                  registry, which is exactly the split vulhub is built on.
    kind = db.Column(db.String(16), nullable=False, default="dockerfile")

    # The container's primary service port — where a portless inbound I2P stream
    # is routed on the worker. For compose, this is the port of the primary
    # (internet-facing) service.
    primary_port = db.Column(db.Integer, nullable=False, default=80)

    # EVERY container port the project exposes, comma-separated, primary first.
    #
    # The importer already worked all of these out — parse_ports() returns the
    # whole list — and then kept one, so a box exposing a web app, a database
    # and a debugger advertised a single open port. The destination always
    # carried all of them (one .b32.i2p, every port), so this was the page
    # describing the box wrongly rather than the box being wrong; somebody
    # port-scanning it would find services the page said were not there.
    #
    # Empty means "not recorded", not "none exposed": rows imported before this
    # existed have an encrypted build context the site cannot re-read, so they
    # fall back to showing the primary alone rather than claiming a box has no
    # other ports.
    exposed_ports = db.Column(db.String(200), nullable=False, default="", server_default="")

    # The content-addressed build context: "sha256:<hex>" and the packed
    # tar.gz blob (Dockerfile + supporting files). The digest is what a deploy
    # references; the blob is what a bridged node publishes to the DHT.
    build_digest = db.Column(db.String(80), nullable=False, index=True)
    build_context = db.deferred(db.Column(db.LargeBinary, nullable=False))
    context_size = db.Column(db.Integer, nullable=False, default=0)

    # Deliberately-vulnerable? A lab challenge deploys with lab containment
    # (private address, no egress, stricter TTL); a non-lab one is an ordinary
    # service.
    is_lab = db.Column(db.Boolean, nullable=False, default=True)

    # Presentation metadata for the machines UI (Hack-The-Box-style). Difficulty
    # is an admin label (Easy|Medium|Hard|Insane); os is the guest OS the box
    # runs. Both have sensible defaults so existing rows render without a backfill.
    difficulty = db.Column(db.String(12), nullable=False, default="Medium")
    os = db.Column(db.String(12), nullable=False, default="Linux")

    # Which skill-radar axes this box exercises, comma separated (see
    # services/codeplay.SKILL_AXIS_KEYS). Solving it moves those axes, weighted
    # by how cleanly it went. Empty means the box contributes to nobody's
    # chart — the honest default, because guessing from a Dockerfile would put
    # confident wrong labels on hundreds of imported challenges.
    skills = db.Column(db.String(200), nullable=False, default="", server_default="")

    # Inactive challenges are hidden from /lab and refused for new deploys, but
    # kept so an in-flight instance can still be reasoned about. "Delete" flips
    # this and clears the blob (see delete_challenge).
    active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    # Set when the packed context has been published to the DHT by a node.
    dht_published_at = db.Column(db.DateTime, nullable=True)

    created_by_slip_id = db.Column(db.Integer, db.ForeignKey("slip.id"), nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=_datetime.datetime.utcnow)

    # Ordered questions a researcher answers to earn points (model.LabQuestion).
    # cascade delete keeps the questions from outliving a deleted challenge.
    questions = db.relationship(
        "LabQuestion",
        backref="challenge",
        cascade="all, delete-orphan",
        order_by="LabQuestion.position",
        lazy="selectin",
    )

    def port_list(self):
        """Every exposed port, primary first, de-duplicated.

        Falls back to the primary alone when nothing was recorded, which is the
        honest answer for a row imported before the list was kept: the box may
        well expose more, and this says only what is known rather than implying
        the rest are closed.
        """
        out, seen = [], set()
        for chunk in (self.exposed_ports or "").split(","):
            chunk = chunk.strip()
            if not chunk.isdigit():
                continue
            port = int(chunk)
            if port not in seen:
                seen.add(port)
                out.append(port)
        primary = self.primary_port
        if primary:
            # Primary first, wherever the importer happened to find it: it is
            # where a portless inbound stream lands, so it is the one somebody
            # tries first.
            if primary in seen:
                out.remove(primary)
            out.insert(0, primary)
        return out

    @property
    def category(self):
        """The software family, from a vulhub slug 'vulhub-<category>-<cve>'."""
        parts = (self.slug or "").split("-")
        if len(parts) >= 2 and parts[0] == "vulhub":
            return parts[1]
        return parts[0] if parts and parts[0] else "lab"

    @property
    def display_name(self):
        """What to call this machine. Falls back to the catalogue name so a row
        without a codename still renders rather than showing a blank."""
        return (self.codename or "").strip() or self.name

    @property
    def os_kind(self):
        """Normalised to the three the icon set draws: linux, windows, other.

        Anything unrecognised is "other" rather than assumed to be Linux —
        showing a penguin next to a BSD box is a small lie the operator cannot
        correct without reading the source.
        """
        value = (self.os or "").strip().lower()
        if value.startswith("lin"):
            return "linux"
        if value.startswith("win"):
            return "windows"
        return "other"

    @property
    def reward(self):
        """A Hack-The-Box-style points reward derived from difficulty, purely
        for display."""
        return {"Easy": 20, "Medium": 30, "Hard": 40, "Insane": 50}.get(self.difficulty, 30)

    def to_public(self):
        """The fields the /lab page shows a user (no blob)."""
        return {
            "slug": self.slug,
            "name": self.name,
            "codename": self.codename,
            "display_name": self.display_name,
            "os_kind": self.os_kind,
            "description": self.description,
            "primary_port": self.primary_port,
            "exposed_ports": self.port_list(),
            "is_lab": self.is_lab,
            "build_digest": self.build_digest,
            "kind": self.kind,
            "difficulty": self.difficulty,
            "os": self.os,
            "skills": self.skills,
            "category": self.category,
        }

    def to_admin(self):
        return {
            **self.to_public(),
            "id": self.id,
            "active": self.active,
            "context_size": self.context_size,
            "dht_published": bool(self.dht_published_at),
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M") if self.created_at else "",
        }


def active_challenges():
    return (
        db.session.query(LabChallenge)
        .filter(LabChallenge.active.is_(True))
        .order_by(LabChallenge.name.asc())
        .all()
    )


def browse_challenges(page=1, per_page=25, query="", difficulty="", os_kind=""):
    """One page of the machine list, filtered in the database.

    Filtering used to happen in the browser over every row, which meant the
    catalogue was sent in full on every page load — 330 machines today and
    growing with each vulhub import. Doing it here keeps the page a fixed size
    however large the catalogue gets, and makes a filtered view a URL somebody
    can send to someone else.
    """
    q = db.session.query(LabChallenge).filter(LabChallenge.active.is_(True))

    text = (query or "").strip().lower()
    if text:
        # Codename, catalogue name and slug together: people search for the
        # handle they remember, and that is sometimes the CVE.
        like = "%" + text + "%"
        q = q.filter(db.or_(
            db.func.lower(LabChallenge.codename).like(like),
            db.func.lower(LabChallenge.name).like(like),
            db.func.lower(LabChallenge.slug).like(like),
        ))
    if difficulty:
        q = q.filter(LabChallenge.difficulty == difficulty)
    if os_kind:
        # Matched on the stored value's prefix so "Linux"/"linux"/"Linux 5.x"
        # all answer to the same filter, and anything else falls under "other".
        if os_kind == "other":
            q = q.filter(db.and_(
                db.not_(db.func.lower(LabChallenge.os).like("lin%")),
                db.not_(db.func.lower(LabChallenge.os).like("win%")),
            ))
        else:
            q = q.filter(db.func.lower(LabChallenge.os).like(os_kind[:3] + "%"))

    total = q.count()
    per_page = max(1, min(int(per_page or 25), 100))
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(int(page or 1), pages))
    rows = (
        q.order_by(LabChallenge.codename.asc(), LabChallenge.name.asc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {"rows": rows, "total": total, "page": page, "pages": pages,
            "per_page": per_page}


def assign_missing_codenames():
    """Give every machine a codename, once.

    Runs at startup and after an import. Deterministic from the slug, so a
    second deployment of the same catalogue produces the same names — but the
    result is STORED, because people refer to machines by these names and a name
    that moves is not one.
    """
    from services.lab_codenames import codename_for

    rows = (
        db.session.query(LabChallenge)
        .filter(LabChallenge.codename.is_(None))
        .order_by(LabChallenge.id.asc())
        .all()
    )
    if not rows:
        return 0
    taken = {
        (name or "").lower()
        for (name,) in db.session.query(LabChallenge.codename)
        .filter(LabChallenge.codename.isnot(None)).all()
    }
    for row in rows:
        name = codename_for(row.slug, taken)
        row.codename = name
        taken.add(name.lower())
    db.session.commit()
    return len(rows)


def all_challenges():
    return (
        db.session.query(LabChallenge)
        .order_by(LabChallenge.active.desc(), LabChallenge.name.asc())
        .all()
    )


def challenge_by_slug(slug, active_only=True):
    query = db.session.query(LabChallenge).filter(LabChallenge.slug == slug)
    if active_only:
        query = query.filter(LabChallenge.active.is_(True))
    return query.one_or_none()
