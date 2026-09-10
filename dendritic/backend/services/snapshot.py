"""Build a frozen, signed, read-only copy of the public site.

This is the producer half of the emergency cache (see
``roadmap/emergency-cache.md``). It renders every eligible route, strips it down
to something safe to serve while nothing behind it works, addresses each result
by its hash, and signs one manifest covering the lot.

WHAT GOES IN, AND WHY THE ANSWER IS NOT A LIST
----------------------------------------------
``board_access.viewer_can_use_public_cache()`` already decides what may be
rendered once and shown to any anonymous stranger. It already excludes private
boards, geo boards, logged-in viewers, shadowbanned viewers and privileged
viewers, and the existing shared render cache already depends on it being right.

So eligibility here is *that function*, not a second list of things to leave
out. A second list would drift from the first, and the drift would not be a
rendering bug — it would be somebody's private board published to strangers.

CONSISTENCY, AND WHY THERE IS NO LONG TRANSACTION
-------------------------------------------------
The obvious way to get a consistent snapshot is one REPEATABLE READ transaction
around the whole build. That would hold a database snapshot open for as long as
it takes to render every page, block vacuum for that entire window, and sit
there as an idle-in-transaction session — which is the exact shape of an outage
this deployment has already had once.

It is also unnecessary. Every object records the content version it was rendered
at, and those versions are signed. A thread that changes mid-build produces an
object stamped with the version it actually had, so skew is VISIBLE in the
manifest rather than hidden behind a claim of atomicity. A snapshot that says
"these are the versions I saw" is more honest than one that says "this is an
instant" and is wrong by a few seconds.

A BROKEN ORIGIN MUST NOT OVERWRITE A GOOD SNAPSHOT
--------------------------------------------------
The build refuses to run when the site cannot render, because the failure mode
otherwise is catastrophic and quiet: the hour the origin starts failing is the
hour a snapshot of error pages replaces the last good copy, and the emergency
cache is then a cache of the emergency.
"""

import datetime
import hashlib
import json
import os

from shared import app, db

SCHEMA = 1

# Recommended defaults from the roadmap. Hours, deliberately: an operator
# reading a config wants "6 hours", not 21600.
REFRESH_AFTER_HOURS = 1
STALE_AFTER_HOURS = 6
EXPIRES_AFTER_HOURS = 24

# A snapshot that renders a fraction of the site is worse than none: gateways
# would serve a plausible-looking site with most of it missing, and readers
# would take the gaps for deletions.
MINIMUM_ROUTES = 3


def sha256_hex(data):
    return hashlib.sha256(data).hexdigest()


def _now():
    return datetime.datetime.utcnow()


def origin_is_healthy():
    """Whether the site is well enough for its output to be worth freezing."""
    try:
        from sqlalchemy import text

        db.session.execute(text("SELECT 1"))
    except Exception:
        app.logger.warning("snapshot: database unreachable; refusing to build")
        return False
    try:
        from model.SiteSetting import get_setting

        if str(get_setting("maintenance_mode", "") or "").lower() in ("1", "true", "on"):
            app.logger.warning("snapshot: maintenance mode active; refusing to build")
            return False
    except Exception:
        # A missing setting is not a reason to refuse; an unreadable database is,
        # and that was already checked above.
        pass
    return True


def eligible_routes():
    """Public routes worth freezing, in the order a reader would need them.

    Tier 1 from the roadmap: the pages a visitor lands on. Thread pages are
    included per board rather than site-wide so one enormous board cannot crowd
    out every other board's front page.
    """
    from board_access import viewer_can_use_public_cache, visible_boards
    from model.Board import Board

    # /network is here for the same reason the others are, and one more: it is
    # the page that explains what an outage looks like and how to run a node.
    # Losing it during an outage loses the explanation exactly when somebody is
    # looking at a degraded site and wondering what is going on.
    #
    # network.json is here for a different reason entirely. It is the signed
    # statement of where this network lives, and a gateway serving a snapshot is
    # serving it precisely when the origin cannot be reached — which is the
    # situation a directive exists for. Without this, the only way to learn the
    # network moved is to ask the thing that moved.
    #
    # A stale snapshot serving a stale directive is safe: the sequence rule
    # means a node holding a newer one refuses it, and the signature means a
    # gateway cannot alter it. Non-HTML routes skip the read-only rewrite, so
    # the JSON is published byte-for-byte as the origin signed it.
    routes = ["/", "/economy", "/faq", "/formatting", "/network",
              "/.well-known/syndichan/network.json"]
    try:
        boards = visible_boards(Board.query.all())
    except Exception:
        app.logger.exception("snapshot: could not enumerate boards")
        return routes

    for board in boards:
        # The same gate the live render cache uses. A board that cannot be
        # shared with an anonymous stranger cannot be in a public snapshot.
        try:
            if not viewer_can_use_public_cache(board=board, slip=None):
                continue
        except Exception:
            continue
        # Boards are addressed by NAME, not id — blueprints/boards.py registers
        # /<string:board_name>. An id here renders a 404 into the snapshot, which
        # would read to a visitor as "this board was deleted".
        name = (getattr(board, "name", "") or "").strip()
        if name:
            routes.append("/boards/%s" % name)
    return routes


def _render_route(client, path):
    """Fetch one route through the app itself.

    Through the WSGI app rather than by calling view functions directly: the
    bytes that must be frozen are the bytes a reader would receive, including
    every after_request hook. A view function's return value is not that, and
    the difference is exactly where a signature stops matching.
    """
    try:
        response = client.get(path, headers={"X-Syndichan-Snapshot-Build": "1"})
    except Exception:
        app.logger.exception("snapshot: %s failed to render", path)
        return None
    if response.status_code != 200:
        return None
    content_type = (response.headers.get("Content-Type") or "").split(";")[0].strip()
    if content_type not in ("text/html", "application/json", "text/plain"):
        return None
    return {
        "body": response.get_data(),
        "content_type": response.headers.get("Content-Type") or content_type,
        # The live signed version, carried into the snapshot so skew is legible.
        "version": int(response.headers.get("X-Syndichan-Version") or 0),
    }


def build(sequence=None, now=None):
    """Produce one snapshot. Returns the manifest dict, or None if refused."""
    if not origin_is_healthy():
        return None

    from services.snapshot_rewrite import looks_interactive, rewrite_html

    started = now or _now()
    label = started.strftime("%d %B %Y at %H:%M UTC")
    objects = {}
    routes = {}
    searchable = {}

    client = app.test_client()
    for path in eligible_routes():
        rendered = _render_route(client, path)
        if rendered is None:
            continue
        body = rendered["body"]
        # Non-HTML loses nothing by definition; HTML sets this below.
        lost_something = False
        if rendered["content_type"].startswith("text/html"):
            rewritten, took_away = rewrite_html(body.decode("utf-8", "replace"), label)
            if rewritten is None or looks_interactive(rewritten):
                # A page that survived rewriting with a live form is a bug in
                # the rewriter. Dropping the route loses a page; publishing it
                # puts a working-looking post box in front of somebody during an
                # outage.
                app.logger.warning("snapshot: %s dropped, not safely read-only", path)
                continue
            body = rewritten.encode("utf-8")
            lost_something = took_away

        if rendered["content_type"].startswith("text/html"):
            # Indexed from the PRE-rewrite page. The rewritten one carries the
            # emergency banner, which names the build time — indexing that would
            # make the index differ on every build and, since a changed index is
            # a changed route, would defeat the reissue for the whole snapshot.
            # The banner adds no words a reader would search for.
            searchable[path] = rendered["body"].decode("utf-8", "replace")

        # The hash of what the SITE produced, before the emergency banner is
        # stamped on. That banner names the build time, so a rewritten page
        # differs on every build even when nothing about the site changed —
        # which would defeat the delta entirely and make every rebuild a full
        # re-upload. This is the hash that answers "did the content change".
        source_digest = sha256_hex(rendered["body"])

        # TWO variants for an HTML route, and the reason is that they are served
        # in opposite conditions:
        #
        #   emergency  forms replaced, banner added — the origin cannot answer,
        #              so a live-looking post box would swallow what somebody
        #              typed.
        #   offload    the origin's OWN bytes, untouched — the origin is fine,
        #              so disabling its search box would remove a capability the
        #              reader still has, and a banner would claim an outage that
        #              is not happening.
        #
        # Storing only the emergency variant is what made the offload set empty:
        # this site's shared layout carries a search form and buttons, so every
        # page loses something to the rewrite, and none could ever be served
        # while the origin was up.
        offload_digest = None
        if rendered["content_type"].startswith("text/html"):
            offload_digest = source_digest
            objects[source_digest] = rendered["body"]

        digest = sha256_hex(body)
        # Content addressing gives deduplication for free: two routes that
        # render identically, and every unchanged page in the next hourly
        # build, resolve to bytes already stored.
        objects[digest] = body
        routes[path] = {
            "object": digest,
            "content_type": rendered["content_type"],
            "status": 200,
            "size": len(body),
            "live_version": rendered["version"],
            "source_hash": source_digest,
            # Did the read-only rewrite take anything away? A page that lost a
            # form must never be served while the origin is up: doing so would
            # silently remove somebody's ability to post or log in.
            "lost_interactivity": bool(lost_something),
            # What to serve while the origin is HEALTHY: the untouched render.
            "offload_object": offload_digest,
        }

    # Static assets. This is where the offloadable bytes actually are: a page is
    # a few tens of kilobytes and its CSS, JavaScript and images are most of
    # what a reader downloads. Serving HTML from cache while every asset still
    # hits the origin offloads almost nothing.
    #
    # They need no rewriting — there is no form in a stylesheet — so the object
    # and the offload variant are the same bytes, which is also exactly what the
    # origin serves.
    _add_static_assets(objects, routes)

    # The search index is just another object: content-addressed, covered by the
    # manifest root, and therefore signed and verifiable with no special case.
    if searchable:
        index_body = _search_index_body(searchable)
        if index_body is not None:
            digest = sha256_hex(index_body)
            objects[digest] = index_body
            routes["/snapshot/search-index.json"] = {
                "object": digest,
                "content_type": "application/json",
                "status": 200,
                "size": len(index_body),
                "live_version": 0,
                # Its own hash: the index derives deterministically from pages
                # that are themselves unchanged, so this is stable exactly when
                # the content is. Omitting it would leave one route with no
                # source hash, and "missing counts as changed" would then defeat
                # the reissue for the entire snapshot.
                "source_hash": digest,
            }

    if len(routes) < MINIMUM_ROUTES:
        app.logger.error("snapshot: only %d route(s) rendered; refusing to publish "
                         "a snapshot that would look like a mostly-deleted site",
                         len(routes))
        return None

    return _manifest_for(routes, objects, started, sequence)


def _manifest_for(routes, objects, started, sequence):
    from services.content_signing import merkle_root
    from services.snapshot_key import public_key_b64, sign_manifest

    # Leaves are ordered by route so the root is reproducible: a challenger
    # rebuilding this must get the same root, and map iteration order would
    # make that a coin flip.
    leaves = [sha256_hex(("%s\n%s" % (path, entry["object"])).encode("utf-8"))
              for path, entry in sorted(routes.items())]
    root = merkle_root(leaves)

    created_at = int(started.timestamp())
    expires_at = int((started + datetime.timedelta(hours=EXPIRES_AFTER_HOURS)).timestamp())
    if sequence is None:
        sequence = next_sequence()
    snapshot_id = sha256_hex(
        ("%s|%s|%s" % (root, sequence, created_at)).encode("utf-8"))

    manifest = {
        "schema": SCHEMA,
        "site": app.config.get("SITE_HOSTNAME") or "syndichan.org",
        "snapshot_id": snapshot_id,
        "sequence": int(sequence),
        "created_at": created_at,
        "refresh_after": int((started + datetime.timedelta(
            hours=REFRESH_AFTER_HOURS)).timestamp()),
        "stale_after": int((started + datetime.timedelta(
            hours=STALE_AFTER_HOURS)).timestamp()),
        "expires_at": expires_at,
        "entrypoint": "/",
        "routes": dict(sorted(routes.items())),
        "fallback_routes": {
            # Anything not frozen resolves to a page that says so, rather than a
            # 404 that reads as "this was deleted".
            "/thread/*": "/",
            "/user/*": "/",
            "/admin/*": "/",
        },
        "object_count": len(routes),
        "root_hash": root,
        # The REPRODUCIBLE commitment: a root over (path, source_hash), which is
        # what the site produced rather than what was stamped and stored. Served
        # objects carry a build-time banner and legitimately differ between
        # publishers, so they cannot be what independent parties attest to.
        "source_root": None,
        "publisher_key": public_key_b64(),
        "hash": "sha256",
        "signature": None,
    }
    from services.snapshot_quorum import source_root as _source_root

    manifest["source_root"] = _source_root(manifest)
    manifest["signature"] = sign_manifest(
        snapshot_id, sequence, root, created_at, expires_at, len(routes))
    if manifest["signature"] is None:
        app.logger.error(
            "snapshot %s built UNSIGNED: SNAPSHOT_SIGNING_KEY is not configured, "
            "so no client will serve it", snapshot_id[:12])
    return manifest, objects


def build_and_publish():
    """Build one snapshot and activate it. Returns a small result dict.

    MUST RUN IN THE SERVING PROCESS, not as a separate command that imports the
    app. Importing `app` re-runs the startup DDL — the `ALTER TABLE ... ADD
    COLUMN IF NOT EXISTS` block — against a database the live process is already
    using. Those take AccessExclusiveLock, and the first attempt at running the
    builder as its own process deadlocked against the running server and took
    the pod down with it.

    So this is the entry point, and anything outside the process asks the app to
    call it rather than importing its way in.
    """
    from services.snapshot_store import current_manifest, publish, publish_to_dht

    built = build()
    if built is None:
        return {"ok": False, "reason": "origin unhealthy, or too few routes rendered"}
    manifest, objects = built

    # DELTA PUBLISHING (roadmap item 22)
    # ----------------------------------
    # Content addressing already makes an unchanged page resolve to bytes that
    # are ALREADY stored, so the expensive half of a rebuild — uploading and
    # reading back every object — is avoidable whenever nothing changed.
    #
    # This matters far beyond bandwidth. It is what makes publishing cheap
    # enough to do OFTEN, and publishing often is the only way a snapshot-first
    # architecture (phase 6) can serve content readers would call current. A
    # rebuild that costs a full re-upload can run hourly; one that costs a
    # signature can run every few minutes.
    previous = current_manifest() or {}

    _log_changes(previous, manifest)
    if _content_is_unchanged(previous, manifest):
        # Nothing on the site changed, so the PREVIOUS snapshot is still an
        # accurate frozen copy — including its banner, which correctly names
        # when that copy was taken. Reusing it wholesale means an idle site
        # costs one signature per build instead of a full re-upload, and the
        # objects gateways already hold stay valid.
        manifest = _reissue(previous, manifest)
        objects = {}
        changed, unchanged = set(), {entry["object"] for entry
                                     in manifest["routes"].values()}
    else:
        # Per-route reuse. Only pages whose SOURCE changed are re-rewritten;
        # the rest keep the object they already had.
        #
        # Without this, one busy board forces a full re-upload: the banner names
        # the build time, so re-rewriting an unchanged page yields different
        # bytes and therefore a different object. Two changed boards were
        # producing six new objects.
        manifest, objects = _reuse_unchanged(previous, manifest, objects)
        changed, unchanged = _delta(previous, manifest)

    # AFTER the route set is final. _reuse_unchanged replaces an unchanged
    # route's entry with the previous one wholesale, so marking before it would
    # be overwritten by the very entry being carried forward — the counter would
    # sit at whatever it was first set to and never advance, and no route would
    # ever become offloadable.
    _mark_offloadable(previous, manifest)
    manifest = _reroot(manifest)
    fresh = {digest: body for digest, body in objects.items() if digest in changed}

    # The DHT first, because it is the store. publish() then caches locally,
    # reads every object back through the same path a reader takes, and only
    # activates if that succeeds — so a snapshot that reached nowhere durable
    # never becomes current.
    #
    # Only the objects that are actually new are sent. The rest are already
    # there, by definition: their name IS their hash.
    dht = publish_to_dht(manifest, fresh)
    dht["unchanged_objects"] = len(unchanged)

    # NOTE: publish() gets EVERY object, not just the new ones. Transfer is the
    # delta; verification is not. An unchanged object that has since vanished
    # from the store would otherwise sail through — it was not in this build's
    # delta, so nothing would have checked it — and the gap would only surface
    # when a reader asked for that page during an outage.
    if not publish(manifest, objects):
        return {"ok": False, "reason": "objects did not store or did not read back",
                "sequence": manifest.get("sequence"), "dht": dht}

    return {
        "ok": True,
        "snapshot_id": manifest["snapshot_id"],
        "sequence": manifest["sequence"],
        "routes": manifest["object_count"],
        "bytes": sum(len(b) for b in objects.values()),
        "signed": bool(manifest["signature"]),
        "expires_at": manifest["expires_at"],
        "changed_objects": len(changed),
        "unchanged_objects": len(unchanged),
        # True when the site produced byte-identical output. The snapshot is
        # still republished — a new sequence with a fresh expiry window — but no
        # object moves, so an idle site costs one signature per build instead of
        # a full re-upload.
        "content_unchanged": not changed,
        "dht": dht,
    }


# One asset larger than this is skipped. A snapshot is fetched in full by every
# gateway, so a single enormous file would be paid for by all of them.
#
# Set above the site logo deliberately. The first cap excluded it at 2.25 MB,
# which every page loads — a snapshot missing the logo renders as a broken page
# during exactly the outage it exists to smooth over, and "the emergency copy
# looks wrong" undermines the thing more than the bytes cost.
MAX_ASSET_BYTES = 4 * 1024 * 1024
# And the whole asset set is bounded, for the same reason.
MAX_ASSET_TOTAL_BYTES = 24 * 1024 * 1024


def _add_static_assets(objects, routes):
    """Add every static file to the snapshot as an offloadable route.

    Assets are the bulk of what a reader downloads and the easiest thing to
    serve from a gateway: no rewriting, no interactivity to remove, and the
    stored bytes are byte-identical to the origin's.

    They still go through the ordinary stability rule rather than being trusted
    on sight. A deploy changes them, and a gateway serving last release's
    JavaScript beside this release's HTML is a broken page — the stability
    counter makes that window explicit instead of assuming assets never change.
    """
    from services.static_manifest import _hash_file, _static_root, _walk

    try:
        root = _static_root()
        walked = list(_walk(root))
    except Exception:
        app.logger.exception("snapshot: could not enumerate static assets")
        return

    total = 0
    for relative, absolute in sorted(walked):
        try:
            size = os.path.getsize(absolute)
        except OSError:
            continue
        if size > MAX_ASSET_BYTES:
            app.logger.info("snapshot: skipping %s (%d bytes over the per-asset cap)",
                            relative, size)
            continue
        if total + size > MAX_ASSET_TOTAL_BYTES:
            app.logger.warning("snapshot: static asset budget reached; %s and "
                               "later files are not included", relative)
            break
        try:
            with open(absolute, "rb") as handle:
                body = handle.read()
        except OSError:
            continue
        digest = _hash_file(absolute)
        if digest is None or sha256_hex(body) != digest:
            continue
        total += size
        objects[digest] = body
        routes["/static/%s" % relative] = {
            "object": digest,
            "content_type": _asset_content_type(relative),
            "status": 200,
            "size": size,
            "live_version": 0,
            "source_hash": digest,
            "lost_interactivity": False,
            # Same bytes: an asset has nothing to strip, so what is served
            # during an outage and what is served normally are identical.
            "offload_object": digest,
        }


_ASSET_TYPES = {
    ".css": "text/css; charset=utf-8",
    ".js": "application/javascript; charset=utf-8",
    ".json": "application/json",
    ".svg": "image/svg+xml",
    ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp", ".ico": "image/x-icon",
    ".woff": "font/woff", ".woff2": "font/woff2", ".ttf": "font/ttf",
    ".txt": "text/plain; charset=utf-8",
}


def _asset_content_type(relative):
    """Content type from the extension.

    Explicit rather than guessed by mimetypes: the guess depends on system
    files that differ between the build host and the container, and an asset
    served as the wrong type is a stylesheet a browser refuses to apply.
    """
    _, _, extension = relative.rpartition(".")
    return _ASSET_TYPES.get("." + extension.lower(), "application/octet-stream")


def _search_index_body(pages):
    """The snapshot's search index, as bytes. None if it could not be built."""
    import json as _json

    try:
        from services.snapshot_search import build_index, title_of

        titles = {route: title_of(html) for route, html in pages.items()}
        index = build_index(pages, titles)
        # Sorted and compact so identical corpora produce identical bytes —
        # otherwise the index would look "changed" on every build and defeat
        # the delta it lives alongside.
        return _json.dumps(index, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except Exception:
        app.logger.exception("snapshot: could not build the search index")
        return None


# A route must render identically this many builds running before a gateway may
# serve it while the origin is UP. One quiet build is not evidence of anything;
# it is what a busy board looks like between two posts.
OFFLOAD_STABLE_BUILDS = 3


def _mark_offloadable(previous, manifest):
    """Decide which routes a gateway may serve during ordinary operation.

    TWO conditions, and both are necessary.

    STABLE: the source has rendered identically for several consecutive builds.
    Serving a volatile page from an hour-old copy would show readers a board
    missing the last hour of posts, which is worse than a slow page.

    LOST NOTHING: the read-only rewrite removed no form, token or handler, so
    the stored bytes ARE the origin's bytes. A page that lost its post box must
    never be served while the origin is up — that would silently take away
    somebody's ability to post, and they would have no way to tell why.

    Together these pick out exactly the pages where a cached copy is
    indistinguishable from the live one. Anything else keeps going to the origin.
    """
    old_routes = (previous or {}).get("routes") or {}
    for path, entry in manifest["routes"].items():
        old_entry = old_routes.get(path) or {}
        if old_entry.get("source_hash") == entry.get("source_hash"):
            stable = int(old_entry.get("stable_builds") or 0) + 1
        else:
            # Any change resets the count. A page that just changed is exactly
            # the page a reader most wants live.
            stable = 0
        entry["stable_builds"] = stable
        # Stability alone. The offload variant IS the origin's bytes, so serving
        # it removes no capability and misleads nobody — the only question left
        # is whether the page is old enough to have gone out of date, which is
        # what stability answers.
        entry["offload"] = bool(stable >= OFFLOAD_STABLE_BUILDS
                                and entry.get("offload_object"))


def _log_changes(previous, manifest):
    """Name the routes whose source changed, so a rebuild is explicable."""
    old_routes = (previous or {}).get("routes") or {}
    if not old_routes:
        return
    changed = [path for path, entry in manifest["routes"].items()
               if old_routes.get(path, {}).get("source_hash") != entry.get("source_hash")]
    if changed:
        app.logger.info("snapshot: %d route(s) changed since the last build: %s",
                        len(changed), ", ".join(sorted(changed)[:6]))


def _content_is_unchanged(previous, manifest):
    """Whether the SITE produced identical output to the last snapshot.

    Compared on source_hash — the render before the banner — because the banner
    names the build time and would otherwise report every page as changed. An
    older snapshot missing source_hash counts as changed, which is the safe
    direction: it costs one rebuild rather than pinning a stale snapshot.
    """
    old_routes = (previous or {}).get("routes") or {}
    new_routes = manifest["routes"]
    if set(old_routes) != set(new_routes):
        return False
    for path, entry in new_routes.items():
        previous_hash = old_routes[path].get("source_hash")
        if not previous_hash or previous_hash != entry.get("source_hash"):
            return False
    return True


def _reissue(previous, rebuilt):
    """The previous snapshot, re-signed with a new sequence and a fresh window.

    The ROUTES and OBJECTS are the previous snapshot's — that is the point, and
    it is why gateways keep serving bytes they already hold. Only the identity
    and the validity window move forward.
    """
    manifest = dict(previous)
    for field in ("sequence", "created_at", "refresh_after", "stale_after",
                  "expires_at", "snapshot_id", "signature", "publisher_key"):
        manifest[field] = rebuilt[field]
    manifest["reissued"] = True
    # Re-signed over the PREVIOUS root, because the content is the previous
    # content. Signing the rebuilt root would commit to objects nobody stored.
    from services.snapshot_key import sign_manifest

    manifest["signature"] = sign_manifest(
        manifest["snapshot_id"], manifest["sequence"], manifest["root_hash"],
        manifest["created_at"], manifest["expires_at"], manifest["object_count"])
    return manifest


def _reuse_unchanged(previous, manifest, objects):
    """Keep the previous object for every route whose source did not change.

    The rewritten body carries a banner naming the build time, so a page that
    nobody edited still produces new bytes on every build. Comparing SOURCE
    hashes tells us that page did not really change, and the honest thing to
    serve is the copy already stored — which is also accurate, because its
    banner names when that copy was actually taken.
    """
    old_routes = (previous or {}).get("routes") or {}
    if not old_routes:
        return manifest, objects

    routes = dict(manifest["routes"])
    for path, entry in routes.items():
        old_entry = old_routes.get(path)
        if not old_entry or not old_entry.get("source_hash"):
            continue
        if old_entry.get("source_hash") != entry.get("source_hash"):
            continue
        # Unchanged at source: drop the freshly rewritten body and point at the
        # object already in the store.
        objects.pop(entry["object"], None)
        routes[path] = dict(old_entry)

    manifest = dict(manifest)
    manifest["routes"] = routes
    # The root commits to the routes, so it must be recomputed and re-signed
    # over what is actually being published rather than over what was built.
    manifest = _reroot(manifest)
    return manifest, objects


def _reroot(manifest):
    """Recompute the Merkle root and signature for edited routes."""
    from services.content_signing import merkle_root
    from services.snapshot_key import sign_manifest

    leaves = [sha256_hex(("%s\n%s" % (path, entry["object"])).encode("utf-8"))
              for path, entry in sorted(manifest["routes"].items())]
    manifest["root_hash"] = merkle_root(leaves)
    manifest["object_count"] = len(manifest["routes"])
    from services.snapshot_quorum import source_root as _source_root

    manifest["source_root"] = _source_root(manifest)
    manifest["signature"] = sign_manifest(
        manifest["snapshot_id"], manifest["sequence"], manifest["root_hash"],
        manifest["created_at"], manifest["expires_at"], manifest["object_count"])
    return manifest


def _delta(previous, manifest):
    """Objects this snapshot introduces, and those it reuses.

    Compared by OBJECT HASH rather than by route, because that is what decides
    whether anything must move. A page that moved from one path to another is
    the same bytes and needs no transfer; a page that changed at the same path
    is new bytes and does.
    """
    def objects_of(routes):
        found = set()
        for entry in (routes or {}).values():
            for field in ("object", "offload_object"):
                if entry.get(field):
                    found.add(entry[field])
        return found

    held = objects_of(previous.get("routes"))
    current = objects_of(manifest["routes"])
    return current - held, current & held


def next_sequence():
    """One higher than the highest snapshot ever published here.

    Monotonic and never reused: the sequence is the only thing stopping an old
    but validly signed snapshot from being replayed over a newer one, so a
    counter that restarts is a rollback attack that needs no attacker.
    """
    from model.SiteSetting import get_setting, set_setting

    try:
        current = int(get_setting("snapshot_sequence", 0) or 0)
    except (TypeError, ValueError):
        current = 0
    nxt = current + 1
    set_setting("snapshot_sequence", str(nxt))
    # COMMITTED HERE, explicitly. set_setting writes to the session, and in a
    # request that is flushed at teardown — but the builder runs in a background
    # thread that owns its own transaction, so without this every increment was
    # rolled back and every snapshot published as sequence 1.
    #
    # That is not a cosmetic bug. The sequence is the ONLY thing standing
    # between a reader and a replayed older snapshot, and gateways refuse a
    # sequence that does not advance — so a stuck counter silently means both
    # "rollback protection is void" and "no gateway will ever take a new
    # snapshot", while the logs report a successful publish every hour.
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("snapshot: could not persist the sequence counter")
        raise
    return nxt


def canonical_manifest_json(manifest):
    """The exact bytes a client hashes and checks. Sorted, compact, stable."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
