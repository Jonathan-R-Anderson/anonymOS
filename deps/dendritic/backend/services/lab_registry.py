"""The lab challenge registry: pack a Dockerfile + files into a content-addressed
build context, store it in the catalog, and manage the catalog.

The packed blob is a gzip'd tar with the Dockerfile at its root, matching what
the Go worker's UnpackBuildContext expects. It does NOT need to be byte-identical
to the Go packer: the digest is computed over THIS blob and stored with it, and
the worker verifies the blob it fetches against that digest, then re-packs the
validated files itself before building. So the only requirements here are: a
valid gzip tar, regular files only, safe relative paths, and a Dockerfile.
"""
import datetime as _datetime
import gzip
import hashlib
import io
import re
import tarfile

from shared import db
from model.LabChallenge import LabChallenge, challenge_by_slug
from model.LabQuestion import (
    LabQuestion, question_by_id, questions_for_challenge,
    ANSWER_KINDS, ANSWER_STATIC,
)

# A build context is a Dockerfile plus small supporting files, not a base image.
MAX_CONTEXT_BYTES = 8 * 1024 * 1024
# A compose project bundles a few more config files (and occasionally a small
# build context of its own), so it gets a roomier ceiling. Still tiny next to
# the images, which are pulled from the registry and never live here.
MAX_COMPOSE_CONTEXT_BYTES = 16 * 1024 * 1024
# A fixed mtime so the archive is reproducible; the digest is over this blob.
_FIXED_MTIME = 1_000_000_000
_SLUG_RE = re.compile(r"[^a-z0-9-]+")
# Compose file names the worker will look for, in preference order.
COMPOSE_FILENAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


class RegistryError(Exception):
    def __init__(self, message):
        super().__init__(message)
        self.message = message


def _safe_rel_path(path):
    """Reject anything that could write outside the build directory."""
    if not path or path.startswith("/") or "\\" in path:
        return False
    parts = path.split("/")
    return ".." not in parts and "" not in parts[:-1]


def pack_build_context(dockerfile, files):
    """Pack a Dockerfile (str) and supporting files ({path: bytes}) into a
    (blob, digest) build context. Raises RegistryError on unsafe input."""
    dockerfile = (dockerfile or "").strip()
    if not dockerfile:
        raise RegistryError("A Dockerfile is required.")

    entries = {"Dockerfile": dockerfile.encode("utf-8")}
    for path, data in (files or {}).items():
        path = path.replace("\\", "/").lstrip("./")
        if not _safe_rel_path(path):
            raise RegistryError("Unsafe file path in the build context: %r" % path)
        if path == "Dockerfile":
            continue  # the textarea Dockerfile wins
        entries[path] = data

    total = sum(len(v) for v in entries.values())
    if total > MAX_CONTEXT_BYTES:
        raise RegistryError("Build context is too large (max %d MiB)." % (MAX_CONTEXT_BYTES // (1024 * 1024)))

    return _pack_files(entries)


def _pack_files(entries):
    """Pack a {path: bytes} mapping into a reproducible tar.gz and return
    (blob, "sha256:<hex>"). Shared by the Dockerfile and compose packers so both
    produce a byte-identical archive for identical inputs and the same digest the
    worker verifies. Paths are validated by the caller."""
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for name in sorted(entries):
                data = entries[name]
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                info.mtime = _FIXED_MTIME
                info.mode = 0o644
                info.uid = info.gid = 0
                info.type = tarfile.REGTYPE
                tar.addfile(info, io.BytesIO(data))
    blob = raw.getvalue()
    return blob, "sha256:" + hashlib.sha256(blob).hexdigest()


def pack_compose_context(files):
    """Pack a docker-compose project ({path: bytes}) into a (blob, digest)
    context. Requires a compose file at the root; everything else it references
    (configs, mounted files, an occasional local build dir) rides along. The
    IMAGES are NOT here -- the worker pulls those from the registry at
    `compose up`; only the small text project lives on the DHT."""
    entries = {}
    has_compose = False
    for path, data in (files or {}).items():
        path = path.replace("\\", "/").lstrip("./")
        if not _safe_rel_path(path):
            raise RegistryError("Unsafe file path in the compose context: %r" % path)
        entries[path] = data
        if path in COMPOSE_FILENAMES:
            has_compose = True
    if not has_compose:
        raise RegistryError("A docker-compose file is required at the project root.")

    total = sum(len(v) for v in entries.values())
    if total > MAX_COMPOSE_CONTEXT_BYTES:
        raise RegistryError("Compose context is too large (max %d MiB)." % (MAX_COMPOSE_CONTEXT_BYTES // (1024 * 1024)))
    return _pack_files(entries)


def context_object_id(slug):
    """The stable content-encryption object id for a challenge's build context.

    Keyed by slug (not the ciphertext) so it is reproducible, and matched at
    deploy time when the server grants the worker the key."""
    return "lab/" + slug


def _finalize_context(object_id, blob):
    """Encrypt the packed build context for storage when a content master is
    configured, and return (stored_blob, "sha256:<digest-of-stored-blob>").

    The digest is computed over exactly the bytes the node stores and the worker
    fetches, so `_publish_one`'s digest check and the worker's verification both
    match. Volunteer nodes only ever hold this ciphertext; only the server (and a
    worker it grants) can decrypt it."""
    from services import content_keys

    if content_keys.enabled():
        blob = content_keys.encrypt(object_id, blob)
    return blob, "sha256:" + hashlib.sha256(blob).hexdigest()


def slugify(name):
    slug = _SLUG_RE.sub("-", (name or "").strip().lower()).strip("-")
    return slug[:100] or "challenge"


_DIFFICULTIES = ("Easy", "Medium", "Hard", "Insane")
_OSES = ("Linux", "Windows")


def _clean_difficulty(value):
    return value if value in _DIFFICULTIES else "Medium"


def _clean_os(value):
    return value if value in _OSES else "Linux"


def create_challenge(name, description, dockerfile, files, primary_port, is_lab,
                     created_by_slip_id=None, difficulty="Medium", os="Linux"):
    name = (name or "").strip()
    if not name:
        raise RegistryError("A challenge name is required.")
    slug = slugify(name)
    if challenge_by_slug(slug, active_only=False) is not None:
        raise RegistryError("A challenge with a similar name already exists.")
    try:
        port = int(primary_port)
    except (TypeError, ValueError):
        port = 80
    if port < 1 or port > 65535:
        raise RegistryError("Primary port must be between 1 and 65535.")

    blob, _plain_digest = pack_build_context(dockerfile, files)
    blob, digest = _finalize_context(context_object_id(slug), blob)

    challenge = LabChallenge(
        slug=slug, name=name, description=(description or "").strip(),
        primary_port=port, build_digest=digest, build_context=blob,
        context_size=len(blob), is_lab=bool(is_lab), active=True,
        kind="dockerfile", created_by_slip_id=created_by_slip_id,
        difficulty=_clean_difficulty(difficulty), os=_clean_os(os),
        codename=_fresh_codename(slug),
    )
    db.session.add(challenge)
    db.session.commit()
    return challenge


def _fresh_codename(slug):
    """A codename for a new challenge, avoiding the ones already handed out.

    Assigned at creation rather than left to the startup backfill so a machine
    has a name the moment it appears in the catalogue — an import that shows a
    page of unnamed rows until the next restart is a worse first impression than
    it needs to be.
    """
    from services.lab_codenames import codename_for

    taken = {
        (name or "").lower()
        for (name,) in db.session.query(LabChallenge.codename)
        .filter(LabChallenge.codename.isnot(None)).all()
    }
    return codename_for(slug, taken)


def _clean_ports(ports):
    """Comma-separated, de-duplicated, in range. Order preserved.

    Recorded at import because that is the only place the plaintext project is
    readable: the stored build context is encrypted, so the site cannot go back
    and work this out later.
    """
    out, seen = [], set()
    for value in (ports or []):
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 1 <= port <= 65535 and port not in seen:
            seen.add(port)
            out.append(str(port))
    # The column is 200 chars; a project with dozens of ports is pathological
    # and truncating beats failing the whole import over presentation data.
    return ",".join(out)[:200].rstrip(",")


def create_compose_challenge(slug, name, description, files, primary_port,
                             is_lab=True, created_by_slip_id=None, commit=True,
                             difficulty="Medium", os="Linux", ports=None):
    """Register a docker-compose challenge (vulhub-style). `files` is a
    {path: bytes} map of the whole project. `slug` is supplied by the caller
    (the importer derives a stable one from the upstream path) rather than
    slugified from the name, so re-imports are idempotent. Returns the challenge,
    or None if a challenge with this slug already exists."""
    slug = slugify(slug)
    if challenge_by_slug(slug, active_only=False) is not None:
        return None
    try:
        port = int(primary_port)
    except (TypeError, ValueError):
        port = 80
    if port < 1 or port > 65535:
        port = 80

    blob, _plain_digest = pack_compose_context(files)
    blob, digest = _finalize_context(context_object_id(slug), blob)

    challenge = LabChallenge(
        slug=slug, name=(name or slug).strip()[:120],
        description=(description or "").strip(),
        primary_port=port, build_digest=digest, build_context=blob,
        exposed_ports=_clean_ports(ports),
        context_size=len(blob), is_lab=bool(is_lab), active=True,
        kind="compose", created_by_slip_id=created_by_slip_id,
        difficulty=_clean_difficulty(difficulty), os=_clean_os(os),
        codename=_fresh_codename(slug),
    )
    db.session.add(challenge)
    if commit:
        db.session.commit()
    return challenge


def delete_challenge(challenge_id):
    """Retire a challenge: hide it from the catalog and drop its stored blob so
    it stops being deployable. The DHT copy is content-addressed and expires /
    garbage-collects when no instance references it; there is no way (and no
    need) to force-delete an immutable shard, so retiring the catalog entry is
    the authoritative 'delete'."""
    challenge = db.session.query(LabChallenge).filter(LabChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        raise RegistryError("No such challenge.")
    challenge.active = False
    challenge.build_context = b""
    challenge.context_size = 0
    db.session.commit()


# --- Lab questions (admin-editable Q&A that awards points) -------------------

MAX_QUESTION_PROMPT = 2000
MAX_QUESTION_ANSWER = 255


def _clean_answer_kind(value):
    return value if value in ANSWER_KINDS else ANSWER_STATIC


def _clean_points(value, default=10):
    try:
        points = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, min(points, 10000))


def _clean_tier(value):
    """A question's tier, or "" for an ordinary question.

    Unknown values become "" rather than raising: a tier is decoration on top of
    a valid question, and refusing to save the question over it would lose the
    admin's work.
    """
    from model.LabQuestion import TIERS
    tier = (value or "").strip().lower()
    return tier if tier in TIERS else ""


def add_question(challenge_id, prompt, example_answer="", expected_answer="",
                 answer_kind=ANSWER_STATIC, points=10, tier="", commit=True):
    """Append a question to a challenge. Raises RegistryError on a missing
    challenge, an empty prompt, or a fixed-answer question with no answer set."""
    challenge = db.session.query(LabChallenge).filter(LabChallenge.id == challenge_id).one_or_none()
    if challenge is None:
        raise RegistryError("No such challenge.")
    prompt = (prompt or "").strip()
    if not prompt:
        raise RegistryError("A question prompt is required.")
    kind = _clean_answer_kind(answer_kind)
    expected = (expected_answer or "").strip()
    if kind == ANSWER_STATIC and not expected:
        raise RegistryError(
            "A fixed-answer question needs an expected answer "
            "(or switch it to the per-boot secret kind)."
        )
    next_position = 1 + max(
        [q.position for q in questions_for_challenge(challenge_id, active_only=False)],
        default=-1,
    )
    question = LabQuestion(
        challenge_id=challenge_id,
        prompt=prompt[:MAX_QUESTION_PROMPT],
        example_answer=(example_answer or "").strip()[:MAX_QUESTION_ANSWER],
        expected_answer=expected[:MAX_QUESTION_ANSWER],
        answer_kind=kind,
        tier=_clean_tier(tier),
        points=_clean_points(points),
        position=next_position,
        active=True,
    )
    db.session.add(question)
    if commit:
        db.session.commit()
    return question


def update_question(question_id, **fields):
    """Patch a question in place. Accepts prompt, example_answer, expected_answer,
    answer_kind, points, active, position. Returns the challenge id it belongs to."""
    question = question_by_id(question_id)
    if question is None:
        raise RegistryError("No such question.")
    if "prompt" in fields:
        prompt = (fields["prompt"] or "").strip()
        if not prompt:
            raise RegistryError("A question prompt is required.")
        question.prompt = prompt[:MAX_QUESTION_PROMPT]
    if "example_answer" in fields:
        question.example_answer = (fields["example_answer"] or "").strip()[:MAX_QUESTION_ANSWER]
    if "expected_answer" in fields:
        question.expected_answer = (fields["expected_answer"] or "").strip()[:MAX_QUESTION_ANSWER]
    if "answer_kind" in fields:
        question.answer_kind = _clean_answer_kind(fields["answer_kind"])
    if "tier" in fields:
        question.tier = _clean_tier(fields["tier"])
    if "points" in fields:
        question.points = _clean_points(fields["points"], default=question.points)
    if "active" in fields:
        question.active = bool(fields["active"])
    if "position" in fields:
        try:
            question.position = int(fields["position"])
        except (TypeError, ValueError):
            pass
    if question.answer_kind == ANSWER_STATIC and not question.expected_answer:
        raise RegistryError("A fixed-answer question needs an expected answer.")
    db.session.commit()
    return question.challenge_id


def delete_question(question_id):
    """Delete a question and any solve rows that reference it. Returns the
    challenge id it belonged to, or None. The solves must go first: the
    lab_solve.question_id FK has no ON DELETE CASCADE, so deleting a question that
    has been answered would otherwise raise a ForeignKeyViolation. Deleting the
    solves also drops the points they awarded, which is correct -- the question no
    longer exists (to hide a question without losing points, deactivate it)."""
    from model.LabSolve import LabSolve
    question = question_by_id(question_id)
    if question is None:
        return None
    challenge_id = question.challenge_id
    db.session.query(LabSolve).filter(LabSolve.question_id == question_id).delete(synchronize_session=False)
    db.session.delete(question)
    db.session.commit()
    return challenge_id
    return challenge


def unpublished_contexts(limit=20):
    """Active challenges whose build context has not yet been announced to the
    DHT. A bridged node reads these, stores the blob in the shard store, and
    marks them published. Until a node is bridged, they remain here and the
    catalog still works (the site holds the authoritative blob)."""
    return (
        db.session.query(LabChallenge)
        .filter(LabChallenge.active.is_(True), LabChallenge.dht_published_at.is_(None))
        .limit(limit)
        .all()
    )


def mark_published(challenge_id):
    challenge = db.session.query(LabChallenge).filter(LabChallenge.id == challenge_id).one_or_none()
    if challenge is not None:
        challenge.dht_published_at = _datetime.datetime.utcnow()
        db.session.commit()
