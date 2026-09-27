"""Import the vulhub (github.com/vulhub/vulhub) collection into the lab challenge
catalog.

Vulhub is ~330 deliberately-vulnerable environments, each a small docker-compose
project that pulls PREBUILT images from a registry. That is exactly the split the
lab system wants: the compose FILES are small and content-addressed onto the DHT;
the IMAGES are pulled from the registry at `compose up`. So each vulhub
environment becomes one `kind="compose"` LabChallenge whose build context is the
project's text files (compose + configs + any local build files), minus the
screenshots and READMEs that only matter to a human reading the repo.

Run it against a checkout:

    python -m services.vulhub_import /path/to/vulhub

or from the admin registry page ("Import vulhub"). Idempotent: an environment
whose slug already exists is skipped, so re-running only adds what is new.
"""
import os
import re
import sys

# Files that are documentation or screenshots, not part of the runnable project.
_SKIP_SUFFIXES = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico")
_SKIP_NAME_RE = re.compile(r"^readme(\.[a-z-]+)?\.md$", re.I)

_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")

# Ports that are never the primary internet-facing service of a challenge:
# language debuggers, SSH, and the usual backing stores that sit BEHIND the app.
_AVOID_PORTS = {5005, 22, 2222, 3306, 5432, 1433, 6379, 27017, 11211,
                5672, 25, 465, 587, 2181, 9092, 1099}
# When several candidate ports remain, prefer the ones that are usually the web
# entry point, in this order.
_PREFER_PORTS = [80, 8080, 8000, 8888, 3000, 8081, 8090, 8443, 443, 9000, 9200,
                 7001, 8983, 5000, 4000, 8161, 15672, 8161]


def iter_envs(root):
    """Yield (rel_path, abs_dir) for every environment (a dir with a compose
    file) under root, sorted for a stable import order."""
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        if any(name in filenames for name in _COMPOSE_NAMES):
            rel = os.path.relpath(dirpath, root)
            out.append((rel.replace(os.sep, "/"), dirpath))
    out.sort(key=lambda t: t[0])
    return out


def _compose_path(env_dir):
    for name in _COMPOSE_NAMES:
        p = os.path.join(env_dir, name)
        if os.path.isfile(p):
            return p, name
    return None, None


def parse_ports(compose_text):
    """Return the list of CONTAINER ports published by a compose file, in file
    order. Handles the common forms: "H:C", "IP:H:C", "C", and long-form
    `target:`/`published:` maps. Uses PyYAML when available, else a regex."""
    ports = []
    try:
        import yaml
        doc = yaml.safe_load(compose_text) or {}
        services = doc.get("services") or {}
        for svc in services.values():
            for entry in (svc or {}).get("ports", []) or []:
                if isinstance(entry, dict):
                    tgt = entry.get("target")
                    if tgt is not None:
                        ports.append(int(tgt))
                    continue
                s = str(entry).strip().strip('"').strip("'")
                nums = re.findall(r"\d+", s.split("/")[0])
                if not nums:
                    continue
                # last number is the container port for H:C / IP:H:C; a lone
                # number is itself the container port.
                ports.append(int(nums[-1]))
        return ports
    except Exception:
        pass
    # Regex path (no PyYAML). NOT A FALLBACK IN PRACTICE: PyYAML is declared in
    # neither requirements.txt, the Pipfile nor the Dockerfile, so unless it
    # arrives as somebody else's transitive dependency this IS the code that
    # runs. It therefore has to agree with the YAML branch above rather than be
    # approximately right, and it did not -- tests/test_lab_ports.py was
    # reporting the difference and the failure was miscounted as an orphan of a
    # deleted feature (item 4.13).
    #
    # TWO DIVERGENCES, both fixed here:
    #
    #   1. LONG FORM WAS INVISIBLE. `- target: 5005` starts with a word, not a
    #      digit, so the old pattern skipped it and the port vanished. A
    #      challenge whose compose file uses the long form got the wrong
    #      primary port, or none.
    #   2. `expose:` WAS COUNTED. The old pattern matched any `- "8443"` list
    #      item anywhere in the file, including under `expose:`, which the YAML
    #      branch never reads. An exposed-but-unpublished port could be chosen
    #      as the one an inbound stream lands on.
    #
    # The protocol suffix sits INSIDE the quotes in the common "53:53/udp"
    # form, so it is matched before the optional closing quote, not after.
    in_ports = False
    ports_indent = 0
    for line in compose_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        key = re.match(r"([\w.-]+):\s*$", stripped)
        if key:
            # Any mapping key at or above the ports block's indent ends it --
            # `expose:`, the next service, anything.
            in_ports = key.group(1) == "ports"
            ports_indent = indent
            continue
        if not in_ports:
            continue
        if indent <= ports_indent:
            in_ports = False
            continue
        long_form = re.match(r"""-\s*target:\s*["']?(\d+)""", stripped)
        if long_form:
            ports.append(int(long_form.group(1)))
            continue
        short = re.match(r"""-\s*["']?(\d[\d.:]*)(?:/\w+)?["']?\s*$""", stripped)
        if short:
            nums = re.findall(r"\d+", short.group(1))
            if nums:
                # last number is the container port for H:C / IP:H:C; a lone
                # number is itself the container port.
                ports.append(int(nums[-1]))
    return ports


def choose_primary_port(compose_text):
    """Pick the port an inbound I2P stream should land on: the app's web port,
    not a debugger, SSH, or a backing database."""
    ports = parse_ports(compose_text)
    candidates = [p for p in ports if p not in _AVOID_PORTS]
    if not candidates:
        candidates = ports  # everything looked like a backing port; take what we have
    for pref in _PREFER_PORTS:
        if pref in candidates:
            return pref
    return candidates[0] if candidates else 80


def collect_files(env_dir):
    """Return {rel_path: bytes} of the runnable project files under env_dir,
    excluding screenshots and READMEs. Skips anything that is not a regular file
    or is unreadable."""
    files = {}
    for dirpath, dirnames, filenames in os.walk(env_dir):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for fn in filenames:
            low = fn.lower()
            if low.endswith(_SKIP_SUFFIXES) or _SKIP_NAME_RE.match(fn):
                continue
            abs_p = os.path.join(dirpath, fn)
            try:
                if not os.path.isfile(abs_p) or os.path.islink(abs_p):
                    continue
                with open(abs_p, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            rel = os.path.relpath(abs_p, env_dir).replace(os.sep, "/")
            files[rel] = data
    return files


def derive_name(rel):
    parts = [p for p in rel.split("/") if p]
    if not parts:
        return "vulhub challenge"
    category = parts[0]
    rest = " ".join(parts[1:])
    name = ("%s %s" % (category, rest)).strip()
    return name[:120]


def derive_description(env_dir, rel):
    """A short description from README.md: the first heading and the first
    paragraph of prose, stripped of markdown noise."""
    readme = os.path.join(env_dir, "README.md")
    text = ""
    try:
        with open(readme, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        text = ""
    lines = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            if lines:
                break  # end of the first paragraph after we have something
            continue
        if s.startswith("!["):  # an image line
            continue
        s = re.sub(r"^#+\s*", "", s)          # heading marks
        s = re.sub(r"[*_`>]", "", s)           # inline emphasis / quote marks
        s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)  # links -> text
        lines.append(s)
        if sum(len(x) for x in lines) > 320:
            break
    desc = " ".join(lines).strip()
    if not desc:
        desc = "Vulhub environment %s." % rel
    return desc[:480]


def make_slug(rel):
    base = "vulhub-" + rel.lower()
    base = base.replace("/", "-").replace("_", "-").replace(".", "-")
    base = re.sub(r"[^a-z0-9-]+", "-", base).strip("-")
    return base[:100] or "vulhub-challenge"


def plan_env(root, rel, env_dir):
    """Compute what would be imported for one env, WITHOUT touching the DB.
    Returns a dict with slug/name/port/size/file_count or an 'error'."""
    cpath, _ = _compose_path(env_dir)
    try:
        with open(cpath, "r", encoding="utf-8", errors="replace") as fh:
            compose_text = fh.read()
    except OSError as exc:
        return {"rel": rel, "error": "cannot read compose: %s" % exc}
    files = collect_files(env_dir)
    size = sum(len(v) for v in files.values())
    return {
        "rel": rel,
        "slug": make_slug(rel),
        "name": derive_name(rel),
        "port": choose_primary_port(compose_text),
        # Every container port, not just the one an inbound stream lands on.
        # parse_ports already worked these out; keeping only the primary was
        # what made a box exposing a web app, a database and a debugger
        # advertise a single open port.
        "ports": parse_ports(compose_text),
        "files": files,
        "file_count": len(files),
        "size": size,
        "description": derive_description(env_dir, rel),
    }


def plan_vulhub(root):
    """Dry run: plan every environment, no DB. For validation and previews."""
    plans = []
    for rel, env_dir in iter_envs(root):
        plans.append(plan_env(root, rel, env_dir))
    return plans


def import_vulhub(root, limit=None, created_by_slip_id=None, commit_every=25,
                  logger=None):
    """Create a compose LabChallenge for every vulhub environment under root.
    Idempotent (existing slugs are skipped). Returns a stats dict."""
    from shared import db
    from services import lab_registry

    def log(msg):
        if logger:
            logger(msg)

    stats = {"total": 0, "created": 0, "skipped": 0, "errors": 0, "error_list": []}
    envs = iter_envs(root)
    if limit:
        envs = envs[:limit]
    stats["total"] = len(envs)

    pending = 0
    for rel, env_dir in envs:
        plan = plan_env(root, rel, env_dir)
        if plan.get("error"):
            stats["errors"] += 1
            stats["error_list"].append("%s: %s" % (rel, plan["error"]))
            continue
        try:
            challenge = lab_registry.create_compose_challenge(
                slug=plan["slug"], name=plan["name"],
                description=plan["description"], files=plan["files"],
                primary_port=plan["port"], ports=plan.get("ports"), is_lab=True,
                created_by_slip_id=created_by_slip_id, commit=False,
            )
        except lab_registry.RegistryError as exc:
            stats["errors"] += 1
            stats["error_list"].append("%s: %s" % (rel, exc))
            db.session.rollback()
            continue
        except Exception as exc:  # noqa: BLE001 - one bad env must not abort the run
            stats["errors"] += 1
            stats["error_list"].append("%s: %s" % (rel, exc))
            db.session.rollback()
            continue
        if challenge is None:
            stats["skipped"] += 1
            continue
        stats["created"] += 1
        pending += 1
        if pending >= commit_every:
            db.session.commit()
            pending = 0
            log("imported %d/%d (created=%d skipped=%d errors=%d)" % (
                stats["created"] + stats["skipped"] + stats["errors"],
                stats["total"], stats["created"], stats["skipped"], stats["errors"]))
    if pending:
        db.session.commit()
    log("done: created=%d skipped=%d errors=%d of %d" % (
        stats["created"], stats["skipped"], stats["errors"], stats["total"]))
    return stats


def _main(argv):
    if len(argv) < 2:
        sys.stderr.write("usage: python -m services.vulhub_import <vulhub-root> [--limit N] [--dry-run]\n")
        return 2
    root = argv[1]
    limit = None
    dry = "--dry-run" in argv
    if "--limit" in argv:
        limit = int(argv[argv.index("--limit") + 1])
    if not os.path.isdir(root):
        sys.stderr.write("no such directory: %s\n" % root)
        return 2

    if dry:
        plans = plan_vulhub(root)
        if limit:
            plans = plans[:limit]
        ok = [p for p in plans if not p.get("error")]
        bad = [p for p in plans if p.get("error")]
        sys.stdout.write("planned %d env(s), %d error(s)\n" % (len(ok), len(bad)))
        for p in ok[:20]:
            sys.stdout.write("  %-46s port=%-5s files=%-3d %6.1fKB  %s\n" % (
                p["slug"], p["port"], p["file_count"], p["size"] / 1024.0, p["name"]))
        for p in bad[:20]:
            sys.stdout.write("  ERROR %s: %s\n" % (p["rel"], p["error"]))
        return 0

    # Real import needs the Flask app context (DB session).
    from app import app
    with app.app_context():
        stats = import_vulhub(root, limit=limit, logger=lambda m: sys.stdout.write(m + "\n"))
    sys.stdout.write("created=%d skipped=%d errors=%d total=%d\n" % (
        stats["created"], stats["skipped"], stats["errors"], stats["total"]))
    for e in stats["error_list"][:30]:
        sys.stdout.write("  ! %s\n" % e)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv))
