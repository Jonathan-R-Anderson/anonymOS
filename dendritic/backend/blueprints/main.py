import time

from flask import Blueprint, render_template, make_response, request, session, abort, redirect, url_for, flash, jsonify, current_app
from markdown import markdown
from werkzeug.http import parse_etags

from board_access import viewer_can_use_public_cache, visible_boards
import renderer
import cache
from model.Board import Board
from model.SiteSetting import get_setting
from shared import app, db
from services.recommendations.engine import recommendation_enabled


FRONT_PAGE_SETTING_KEY = "front_page_html"
DEFAULT_GREETING_PATH = "deploy-configs/index-greeting.html"

main_blueprint = Blueprint('main', __name__, template_folder='template')


# The anonymous front page is an expensive React SSR round-trip (~2.4s measured;
# the DB side is <5ms with the candidate pool cached). It used to re-render on
# EVERY hit because recommendation ranking disabled the shared cache
# (`not recommendation_enabled()`). But anonymous viewers have no personalization
# profile (services.recommendations.engine._viewer_state returns allowed=False
# without consent + a profile), and viewer_can_use_public_cache() already
# excludes everyone who must get a fresh render (logged-in, moderator,
# shadowbanned, private/geo boards). So we micro-cache the rendered page for
# public viewers with a short TTL: ranking exploration and newly-published
# content still refresh within the window, and the front page live-updates via
# the API regardless. The app cache has no native expiry, so a companion
# timestamp key bounds staleness (see _front_page_cache_is_fresh).
FRONT_PAGE_RENDER_TTL_SECONDS = 20


@main_blueprint.route("/")
def index():
    _sync_boards_if_available(visible_boards(Board.query.all()))
    cache_connection = cache.Cache()
    from blueprints.theme import resolve_current_theme
    current_theme = resolve_current_theme()
    use_cache = viewer_can_use_public_cache()
    # Bucket by ranking mode so a `?ranking=chronological` request (which turns
    # off the recommender) can never be served a recommendation-ranked render.
    rank_mode = "rec" if recommendation_enabled() else "chrono"
    response_cache_key = "firehose-v4-%s-%s-render" % (current_theme, rank_mode)
    etag_cache_key = "%s-etag" % response_cache_key
    ts_cache_key = "%s-ts" % response_cache_key
    etag_value = "%s-%f"  % (response_cache_key, time.time())
    if use_cache and _front_page_cache_is_fresh(cache_connection, ts_cache_key):
        cached_response_body = cache_connection.get(response_cache_key)
        if cached_response_body:
            etag_header = request.headers.get("If-None-Match")
            current_etag = cache_connection.get(etag_cache_key)
            if etag_header and current_etag:
                parsed_etag = parse_etags(etag_header)
                if parsed_etag.contains_weak(current_etag):
                    return make_response("", 304)
            cached_response = make_response(cached_response_body)
            cached_response.set_etag(current_etag, weak=True)
            cached_response.headers["Cache-Control"] = "public,must-revalidate"
            return cached_response
    greeting = get_setting(FRONT_PAGE_SETTING_KEY, _default_greeting())
    # The recent-posts firehose and the news desk were removed from the front
    # page, so neither is computed here anymore. The page is the hero, the
    # editable greeting, the video marquee and the warrant canary. Admin
    # "updates" moved to a signed-in slip pop-up (see /updates.json).
    from model.WarrantCanary import warrant_canary_config
    template = renderer.render_firehose(
        {"threads": [], "tag_styles": {}}, greeting,
        warrant_canary=warrant_canary_config(),
    )
    if use_cache is False:
        return make_response(template)
    uncached_response = make_response(template)
    uncached_response.set_etag(etag_value, weak=True)
    uncached_response.headers["Cache-Control"] = "public,must-revalidate"
    cache_connection.set(response_cache_key, template)
    cache_connection.set(etag_cache_key, etag_value)
    cache_connection.set(ts_cache_key, str(time.time()))
    return uncached_response


def _front_page_cache_is_fresh(cache_connection, ts_cache_key):
    """True while the cached front-page render is within the micro-cache TTL.

    The app cache (cache.Cache) has no native key expiry, so the render path
    stores a companion timestamp and we check its age here. This bounds how long
    a shared anonymous render can freeze ranking exploration or delay newly
    published content to FRONT_PAGE_RENDER_TTL_SECONDS."""
    stored = cache_connection.get(ts_cache_key)
    if not stored:
        return False
    try:
        return (time.time() - float(stored)) < FRONT_PAGE_RENDER_TTL_SECONDS
    except (TypeError, ValueError):
        return False


@main_blueprint.route("/economy")
def economy():
    # Merged into /network as an anchored section. Kept as a redirect so
    # existing links, bookmarks and the node software's references do not
    # 404; the content itself now lives in templates/network.html.
    return redirect(url_for("main.network_topology") + "#economy", code=301)


@main_blueprint.route("/network")
def network_topology():
    """How the network is actually put together, and how to join it.

    Linked from the graph on the front page, which until now was decoration.
    Someone who is considering running infrastructure needs to see what the
    parts are, what each one would ask of their machine, and what they get —
    before they are asked to download anything.
    """
    from services.node_release import PLATFORMS, ROLES, detect_platform, index

    # The former /reputation page is now a section of this template, so its
    # context has to be supplied here too. It is fetched defensively: a
    # reputation backend that is unavailable must degrade that one section,
    # not 500 the page that explains how to join the network.
    try:
        from services.reputation import WEIGHTS, network_summary, node_reputations
        rep_nodes, rep_summary, rep_weights = node_reputations(), network_summary(), WEIGHTS
    except Exception:
        app.logger.warning("reputation section unavailable on /network", exc_info=True)
        rep_nodes, rep_summary, rep_weights = [], None, {}

    return render_template(
        "network.html",
        roles=ROLES,
        platforms=PLATFORMS,
        releases=index(),
        detected=detect_platform(request.headers.get("User-Agent")),
        nodes=rep_nodes,
        summary=rep_summary,
        weights=rep_weights,
    )


@main_blueprint.route("/api/v1/node/releases")
def node_releases():
    """Published binaries and their hashes.

    Public and separate from the download so the expected hash can be read from
    somewhere other than the thing being verified — checking a file against a
    value that arrived in the same response proves only that they agree.
    """
    import json

    from services.node_release import PLATFORMS, index, index_serial

    published = index()
    platforms = [{
        "os": platform["os"], "arch": platform["arch"],
        "label": platform["label"],
        "binary": "syndichan-node-%s-%s%s" % (platform["os"], platform["arch"],
                                              platform["suffix"]),
        **published.get("%s-%s" % (platform["os"], platform["arch"]), {}),
    } for platform in PLATFORMS]

    # SIGNED, because separating the hash from the download only helps against
    # an adversary who does not control the origin, and §18.14 names the update
    # channel as the strongest adversary there is. Unsigned, this endpoint tells
    # a client the hash of the binary the SERVER wants it to trust, and every
    # check the client then performs succeeds.
    #
    # The signed bytes are the canonical JSON of `index` alone, so a client
    # rebuilds them exactly:
    #
    #     json.dumps(payload["index"], sort_keys=True, separators=(",", ":"))
    #
    # and checks it against ORIGIN_PUBLIC_KEY obtained out of band from
    # /.well-known/syndichan/origin-key.json. Signing the whole response instead
    # would mean signing the signature, and signing only the hashes would let
    # the platform-to-hash mapping be rearranged under a valid signature.
    #
    # `serial` is INSIDE the signed object, via sign_object's version field.
    # Without it a signature stops forgery and not replay: an adversary answering
    # for the origin serves an older, genuinely signed index naming a binary
    # whose flaw is now public. A client that records the highest serial it has
    # seen refuses that.
    body = {"platforms": platforms, "serial": index_serial()}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"))

    from services.content_signing import sign_object
    signed = sign_object("api/v1/node/releases", index_serial(),
                         canonical.encode("utf-8"))

    payload = {
        "index": body,
        "note": "sha256 is of the BINARY, which is identical for everyone on a "
                "platform. The download is a per-person archive and its hash is "
                "deliberately not published, because a hash nobody else can "
                "reproduce cannot be checked.",
        "verify": "signature covers json.dumps(index, sort_keys=True, "
                  "separators=(',',':')) — check it against ORIGIN_PUBLIC_KEY "
                  "from /.well-known/syndichan/origin-key.json, and refuse any "
                  "index whose serial is below the highest you have seen.",
    }
    # ABSENT rather than null when signing is not configured. A `"signature":
    # null` field reads as "this one is unsigned, carry on"; a missing field
    # makes a client that requires signatures fail closed.
    if signed:
        payload["signature"] = signed

    response = jsonify(payload)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@main_blueprint.route("/download/node")
def download_node():
    """A binary plus the configuration built from the page's selections."""
    from services.node_release import (PLATFORMS, binary_name, build_config,
                                       bundle, fetch, index)

    wanted_os = (request.args.get("os") or "").lower()
    wanted_arch = (request.args.get("arch") or "").lower()
    platform = next((p for p in PLATFORMS
                     if p["os"] == wanted_os and p["arch"] == wanted_arch), None)
    if platform is None:
        return jsonify({"error": "Unknown platform."}), 400

    entry = index().get("%s-%s" % (wanted_os, wanted_arch))
    if not entry or not entry.get("sha256"):
        return jsonify({
            "error": "No binary has been published for %s/%s yet." % (wanted_os, wanted_arch),
        }), 404
    body = fetch(entry["sha256"])
    if body is None:
        return jsonify({"error": "That binary is not retrievable right now."}), 503

    choices = {
        "roles": request.args.getlist("role"),
        "storage_gb": request.args.get("storage_gb"),
        "payout": request.args.get("payout"),
        "email": request.args.get("email"),
    }
    archive = bundle(platform, body, build_config(choices), entry["sha256"],
                     toolchain=entry.get("toolchain") or "")

    response = make_response(archive)
    response.headers["Content-Type"] = "application/zip"
    response.headers["Content-Disposition"] = (
        'attachment; filename="%s.zip"' % binary_name(platform))
    # The expected binary hash travels with the download as well as being
    # published, so a reader who checks only one of them still checks something.
    response.headers["X-Syndichan-Binary-SHA256"] = entry["sha256"]
    response.headers["Cache-Control"] = "no-store"
    return response


@main_blueprint.route("/dl/<name>")
def download_node_binary(name):
    """One published binary, or its SHA-256, at an address a script can hardcode.

    /download/node builds a per-person zip, which is right for somebody standing
    on the page making choices and useless to `curl … | sh`: an installer needs
    the raw file, and a checksum it can compare BEFORE it runs anything, both at
    a URL that a script written months ago still resolves. Hence /dl/<binary>
    and /dl/<binary>.sha256 — no query string, no per-visitor content, cacheable.

    The checksum is served from the same origin as the binary, so on its own it
    proves transport integrity: a truncated download, a corrupted object, a
    mirror that lost bytes. It is not a claim about who built the file. That is
    what /api/v1/node/releases and a -trimpath rebuild are for, and install.sh
    points at both rather than pretending this check is stronger than it is.
    """
    from services.node_release import PLATFORMS, binary_name, fetch, index

    wanted = name[:-len(".sha256")] if name.endswith(".sha256") else name
    platform = next((p for p in PLATFORMS if binary_name(p) == wanted), None)
    if platform is None:
        # Catalogue images live here too, in the same shape and for the same
        # reason. A node that lacks a compute image needs the raw file and a
        # checksum it can compare BEFORE it hands anything to a root daemon, at
        # a URL a build from months ago still resolves — which is the argument
        # that produced /dl/ in the first place. A second distribution mechanism
        # would be a second thing to keep working and to discover is broken.
        served = _download_catalogue_image(name, wanted)
        if served is not None:
            return served
        return jsonify({"error": "There is no binary called %r." % name}), 404

    entry = index().get("%s-%s" % (platform["os"], platform["arch"]))
    if not entry or not entry.get("sha256"):
        return jsonify({"error": "No %s has been published yet." % wanted}), 404

    if name.endswith(".sha256"):
        # sha256sum's own `<hex>  <name>` format, so an operator can run
        # `sha256sum -c` on the file exactly as served instead of eyeballing it.
        response = make_response("%s  %s\n" % (entry["sha256"], wanted))
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
    else:
        body = fetch(entry["sha256"])
        if body is None:
            return jsonify({"error": "That binary is not retrievable right now."}), 503
        response = make_response(body)
        response.headers["Content-Type"] = "application/octet-stream"
        response.headers["Content-Disposition"] = 'attachment; filename="%s"' % wanted
        response.headers["X-Syndichan-Binary-SHA256"] = entry["sha256"]
    # Short. The bytes for a given release never change, but publishing a new
    # one must reach an installer run minutes later — and the checksum and the
    # binary have to roll over together, so they share one TTL.
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


def _download_catalogue_image(name, wanted):
    """One published catalogue image, or its SHA-256. None if not one of ours.

    None rather than a 404 so the caller keeps ownership of "there is no such
    download" — this is a second table consulted by the same route, not a second
    route, and two places answering 404 differently is how one of them ends up
    saying something the other does not.

    STREAMED, where a binary is not. `docker save` of the embedding image is
    194,401,280 bytes (measured); reading that into memory to build a response
    would cost most of a gigabyte per concurrent download in a gevent worker. The
    hash still travels — in the sidecar, in the header, and, the one that
    matters, compiled into the node's own binary, which is what it actually
    checks against before loading anything.
    """
    from services import compute_catalogue
    from services.compute_image_release import index, stream

    workload = compute_catalogue.artifact_workload(wanted)
    if workload is None:
        return None
    entry = index().get(workload)
    if not entry or not entry.get("sha256"):
        return jsonify({
            "error": "No %s has been published yet. Build it with "
                     "compute-images/build.sh and publish it with "
                     "scripts/publish-compute-images.sh." % wanted,
        }), 404

    if name.endswith(".sha256"):
        # sha256sum's own format, so `sha256sum -c` works on the file as served.
        response = make_response("%s  %s\n" % (entry["sha256"], wanted))
        response.headers["Content-Type"] = "text/plain; charset=utf-8"
        response.headers["Cache-Control"] = "public, max-age=300"
        return response

    chunks = stream(entry["sha256"])
    if chunks is None:
        return jsonify({"error": "That image is not retrievable right now."}), 503
    response = app.response_class(chunks, mimetype="application/octet-stream")
    response.headers["Content-Disposition"] = 'attachment; filename="%s"' % wanted
    response.headers["X-Syndichan-Image-SHA256"] = entry["sha256"]
    if entry.get("size"):
        # A length means a node can tell a truncated transfer from a short file
        # before it spends a hash on it, and lets a progress bar exist at all.
        response.headers["Content-Length"] = str(entry["size"])
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@main_blueprint.route("/.well-known/syndichan/network.json")
def network_directive_document():
    """Where this network says it lives, signed by the operator's wallet.

    DNS is what breaks in every scenario this exists for, so DNS is not the
    authority — this document is. A node holds the last one it verified and
    prefers it over anything a name resolves to.

    Served here AND published to the DHT AND carried in every gateway snapshot.
    Three paths because the ones that depend on the current domain are exactly
    the ones that fail in the case this is for; a node that can only learn about
    the move by asking the thing that moved has learnt nothing.

    Verify the signature against a wallet address pinned in your OWN
    configuration. The `wallet` field here is served by the same host that
    served the directive, so it can confirm what you already know and cannot
    establish who is allowed to sign.
    """
    from services.network_directive import public_document

    response = jsonify(public_document())
    # Short: this is the document that says the site has moved, so a stale copy
    # is the failure. Cheap to re-fetch and consulted rarely.
    response.headers["Cache-Control"] = "public, max-age=60"
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response


@main_blueprint.route("/.well-known/syndichan/origin-key.json")
def origin_key():
    """The public key that signs this site's content.

    Published so a client can verify what a gateway hands it. A gateway is
    untrusted transport: it never holds the private half, and a reader who has
    this key can detect a modified byte without trusting anyone.

    Fetching the key through a gateway is trust-on-first-use, which is the same
    bootstrap every pinned-key system has. It is worth having anyway: an
    attacker must now serve a consistent lie to a reader for their whole
    session, and be the only gateway that reader ever uses, rather than flipping
    one byte in one response.
    """
    from services.content_signing import public_key_b64

    public = public_key_b64()
    response = jsonify({
        "algorithm": "ed25519",
        "public_key": public,
        "signing": bool(public),
        "object_prefix": "syndichan-object:v1",
        "manifest_prefix": "syndichan-manifest:v1",
        "note": "Content signatures cover \"prefix\\nkey\\nversion\\nsha256(body)\". "
                "Refuse a version lower than the highest you have seen for a key: "
                "a stale copy is authentic, which is exactly why the version is signed.",
    })
    # Cached, because a key that changes is a key rotation and that is a
    # deliberate event, not something to poll for.
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@main_blueprint.route("/.well-known/syndichan/manifest.json")
def static_manifest_route():
    """Every static asset, hashed, under one signed Merkle root.

    nginx serves /static/ directly and never reaches this application, so those
    files cannot be signed on their way out the way a page is. They are signed
    here instead: one signature over the root, and any single file proves
    membership with a short path of hashes.
    """
    from services.static_manifest import manifest

    response = jsonify(manifest())
    # Short: the manifest describes files in THIS image, and a new build is a
    # new image. Long enough that a page load does not refetch it.
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@main_blueprint.route("/.well-known/syndichan/proof/<path:asset>")
def static_proof_route(asset):
    """The Merkle path for one asset, for a client that does not want the whole
    manifest to check a single file."""
    from services.static_manifest import proof_for

    found = proof_for(asset)
    if found is None:
        return jsonify({"error": "That asset is not in the signed manifest."}), 404
    response = jsonify(found)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@main_blueprint.route("/api/v1/gateway/audit", methods=["POST"])
def gateway_audit_intake():
    """Record one observation of a gateway serving content.

    Open, because the observers worth having are ordinary readers: a client that
    verified a page is the only party who can report on the gateway that served
    it, and requiring an account would leave the network with only the observers
    who volunteered to be identified.

    That openness is exactly why nothing here is a verdict. A report is stored as
    what it is — one observer's claim — and a single claim never becomes
    reputation. Anyone can say anything; corroboration is what will make it mean
    something, and corroboration needs independent validators (phase 4).

    Deduplicated on (gateway, object, version, observer) so a report is worth one
    observation no matter how many times it is sent. Without that, standing is
    farmable by repetition in both directions: inflate yourself, or bury a rival.
    """
    from model.GatewayAudit import RESULTS, record
    from services import ml_runner  # its rate limiter, not its engine

    allowed, retry_after = ml_runner.rate_limit("audit:" + _audit_caller())
    if not allowed:
        response = jsonify({"error": "Too many audit reports. Try again in %ds."
                                     % retry_after})
        response.headers["Retry-After"] = str(retry_after)
        return response, 429

    payload = request.get_json(silent=True) or {}

    def field(name, limit=255):
        return str(payload.get(name) or "").strip()[:limit]

    from services.gateway_identity import is_identity, normalize

    # NOT lower-cased. A gateway identity is base58, which is case-sensitive, so
    # folding it turns a real peer ID into a string that decodes to nothing.
    gateway = normalize(field("gateway", 64))
    object_key = field("object_key")
    result = field("result", 16).lower()
    if not gateway or not object_key:
        return jsonify({"error": "gateway and object_key are required"}), 400
    if result not in RESULTS:
        return jsonify({"error": "result must be one of %s" % (RESULTS,)}), 400
    # An identity that is not a key is not an observation about anything. The
    # intake is open by design, but open to reports about REAL gateways: without
    # this, anyone could fill the record with names nobody ever ran, and every
    # later attempt at corroboration would have to wade through them.
    if not is_identity(gateway):
        return jsonify({"error": "gateway must be a libp2p Ed25519 peer ID"}), 400
    try:
        version = int(payload.get("version") or 0)
        latency = int(payload.get("latency_ms") or 0) or None
    except (TypeError, ValueError):
        return jsonify({"error": "version and latency_ms must be numbers"}), 400

    object_hash = field("object_hash", 64).lower()
    # The other half of a cross-gateway comparison: the gateway the reader
    # actually arrived through. Recorded so "these two disagreed" is expressible
    # rather than only "this one did not match".
    peer = normalize(field("peer_gateway", 64))
    if peer and not is_identity(peer):
        peer = ""

    from services.audit_receipts import classify, receipt_message

    # A signature proves a report was not filed in someone else's name. It does
    # NOT prove the report is true, and for a browser it does not even prove the
    # sender is a distinct person — keys are free. What it buys is that an
    # observer's record cannot be poisoned by anyone but themselves, and that
    # "distinct observers" counts something real.
    signature = field("signature", 128) or None
    kind, signed_observer, verified = classify(
        field("observer_kind", 16) or "client",
        field("observer_key", 128), signature,
        receipt_message(gateway, object_key, version, object_hash, result),
        _registered_node_keys(),
    )
    # A signed report is identified BY ITS KEY, never by a self-declared name:
    # otherwise one key could file under many names and inflate the only number
    # that resists a single loud source. Unsigned reports fall back to the
    # salted address hash, which groups without identifying.
    observer = signed_observer or field("observer", 64) or _audit_observer_id()

    row, created = record(
        gateway=gateway, object_key=object_key, version=version,
        object_hash=object_hash, result=result,
        observer=observer, observer_kind=kind,
        latency_ms=latency, observer_signature=signature if verified else None,
        gateway_registered=_gateway_is_registered(gateway),
        peer_gateway=peer or None,
    )
    if created and result != "pass":
        app.logger.warning("gateway audit: %s reported %s for %s v%s by %s",
                           gateway[:16], result, object_key, version, observer[:16])
    return jsonify({"ok": True, "recorded": bool(created),
                    "id": row.id if row is not None else None})


def _registered_node_keys():
    """Hex Ed25519 keys of nodes the network has registered.

    The gate on validator standing. A signature proves who sent a report; this
    decides whose word carries the weight a validator's does, and the answer is
    "a node that registered, staked an identity and can be found again" — not
    anyone who can generate a keypair.

    Deliberately SUBMITTED only, never pending. A pending registration is
    self-declared: it costs an Ed25519 keypair and a wallet address, both free
    and unlimited, so honouring it would let one person mint as many
    quorum-eligible validators as they liked and turn corroboration back into
    counting. `submitted` means the registration reached the chain, which is
    what makes an identity cost something.

    The consequence is worth stating plainly: while on-chain registration is not
    completing, no node qualifies as a validator and quorum cannot be reached.
    That is the correct failure — no verdicts rather than cheap ones.
    """
    try:
        from services.reputation import registered_keys

        return {key for key in registered_keys() if key}
    except Exception:
        # Empty means nobody qualifies as a validator, which fails toward
        # treating reports as ordinary client observations. That is the safe
        # direction: it under-counts evidence rather than over-trusting it.
        return set()


def _gateway_is_registered(gateway):
    """Whether the controller currently publishes this identity as a gateway.

    Recorded with the observation rather than resolved when the record is read,
    so that unregistering cannot retroactively turn a report about a real
    gateway into a report about nobody.

    The origin is not a gateway and does not register anywhere; it is treated as
    known because it is the one identity this server can vouch for directly. A
    controller outage yields False, which reads as "not confirmed" rather than
    "confirmed absent" — the weaker claim, which is the true one.
    """
    from services.gateway_identity import ORIGIN

    if gateway == ORIGIN:
        return True
    try:
        from services.gateway_registry import registered_identities

        identities, current = registered_identities()
        return current and gateway in identities
    except Exception:
        return False


def _audit_caller():
    forwarded = request.headers.get("X-Forwarded-For") or ""
    return (forwarded.split(",")[0].strip() if forwarded
            else (request.remote_addr or "unknown"))


def _audit_observer_id():
    """A stable, non-identifying grouping key for an anonymous observer.

    The address is HASHED with the origin key rather than stored: the point is to
    tell one observer from another, not to know who they are, and an audit log
    full of reader IP addresses would be a worse privacy problem than the
    tampering it exists to detect.
    """
    import hashlib

    from services.content_signing import public_key_b64

    salt = (public_key_b64() or "syndichan")[:32]
    return hashlib.sha256((salt + "|" + _audit_caller()).encode("utf-8")).hexdigest()[:32]


@main_blueprint.route("/api/v1/gateway/audits")
def gateway_audit_list():
    """What has been observed, per gateway. Counts, never a score."""
    from model.GatewayAudit import gateways_seen, summary_for
    from services.gateway_identity import normalize

    # Case preserved for the same reason the intake preserves it: a lower-cased
    # peer ID matches nothing, so folding here would make every real gateway
    # look like one with no history.
    which = normalize(request.args.get("gateway") or "")
    if which:
        return jsonify(summary_for(which))
    response = jsonify({
        "gateways": gateways_seen(),
        "note": "Counts of observations, not a verdict. A single observer — "
                "including a gateway reporting on itself — proves nothing; "
                "corroboration by independent validators is what will.",
    })
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


def _canary_view():
    """Serve a canary. Signed by the ordinary response hook, like any page."""
    from services.canaries import canary_body

    response = make_response(canary_body(request.path))
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    # Not indexed and not cached by intermediaries: a canary that a CDN answers
    # from cache is one the gateway never had to serve, and the audit would be
    # measuring the cache.
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    response.headers["Cache-Control"] = "no-store"
    return response


def _register_canaries():
    """Register canary paths as ordinary routes at import time.

    Static rules rather than a before_request hook: the check would otherwise
    run on every request to the site to catch a handful of paths, and a hook
    that inspects every request is a cost paid forever for a rare event.
    """
    try:
        from services.canaries import canary_paths

        for index, path in enumerate(canary_paths()):
            main_blueprint.add_url_rule(
                path, "canary_%d" % index, _canary_view, methods=["GET"])
    except Exception:
        # A deployment without a signing key has nothing to protect with
        # canaries anyway; failing to register them must not stop the site.
        app.logger.warning("canary routes not registered", exc_info=True)


_register_canaries()


@main_blueprint.route("/.well-known/syndichan/snapshot-key.json")
def snapshot_key():
    """The key that signs emergency snapshots.

    Published separately from the origin key, and deliberately a different key:
    the snapshot publisher crawls the whole site unattended, so if it held the
    origin key, reaching the least-guarded component would yield the ability to
    sign live responses. See services/snapshot_key.py.
    """
    from services.snapshot_key import SNAPSHOT_PREFIX, public_key_b64

    public = public_key_b64()
    response = jsonify({
        "algorithm": "ed25519",
        "public_key": public,
        "signing": bool(public),
        "manifest_prefix": SNAPSHOT_PREFIX.decode("ascii"),
        "hash": "sha256",
        "note": "Snapshot manifests are signed over "
                "\"prefix\\nsnapshot_id\\nsequence\\nroot\\ncreated_at\\n"
                "expires_at\\ncount\". Refuse a sequence lower than the highest "
                "you have seen: an old snapshot is authentic, which is exactly "
                "why the sequence is signed.",
    })
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@main_blueprint.route("/.well-known/syndichan/snapshot.json")
def snapshot_manifest():
    """The current emergency snapshot manifest, signed.

    Served from the origin in phase 1 so the verification path can be built and
    tested before the distribution machinery exists. Phase 2 moves the authority
    for this to the DHT; the manifest itself does not change, because a signed
    manifest is exactly as checkable however it arrived.
    """
    from services.snapshot_store import current_manifest

    manifest = current_manifest()
    if manifest is None:
        return jsonify({"error": "No snapshot has been published yet."}), 404
    response = jsonify(manifest)
    # Short: a snapshot is superseded hourly, and a client holding a stale
    # manifest would refuse the newer objects a gateway is serving.
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@main_blueprint.route("/.well-known/syndichan/keys.json")
def snapshot_keyring_route():
    """Which publisher keys the offline root key currently delegates.

    Published so a gateway can pin the ROOT rather than the publisher key. That
    is what makes rotation an announcement instead of a coordination problem:
    without it, changing the publisher key means every operator hand-editing a
    config, so in practice it never changes, and a key that cannot rotate is one
    that stays compromised.

    This server can serve a registry and cannot make one — there is no signing
    path here, because a root key kept beside the thing it protects is just a
    second copy of the publisher key.
    """
    from services.snapshot_keyring import current_keyring, root_public_key

    record = current_keyring()
    if record is None:
        return jsonify({
            "root_public_key": root_public_key(),
            "publisher_keys": [],
            "installed": False,
            "note": "No signed key registry is installed. Gateways fall back to "
                    "the publisher key pinned in their configuration.",
        }), 404
    response = jsonify(record)
    response.headers["Cache-Control"] = "public, max-age=300"
    return response


@main_blueprint.route("/api/v1/snapshot/quorum")
def snapshot_quorum_status():
    """How many independent publishers have attested to the current snapshot.

    Published because the answer is currently "one", and that is worth being
    able to read rather than assume. A snapshot signed by a single key is one
    stolen key away from a forgery; the number here is how far past that the
    network has got.
    """
    from services.snapshot_quorum import attestations_for, verify_quorum
    from services.snapshot_store import current_manifest

    manifest = current_manifest()
    if manifest is None:
        return jsonify({"error": "No snapshot has been published yet."}), 404
    checked = dict(manifest)
    checked["signatures"] = attestations_for(manifest.get("sequence") or 0)
    verdict = verify_quorum(checked)
    verdict["sequence"] = manifest.get("sequence")
    verdict["source_root"] = manifest.get("source_root")
    response = jsonify(verdict)
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@main_blueprint.route("/.well-known/syndichan/revocations.json")
def snapshot_revocations():
    """Snapshots that must not be served, signed and cumulative.

    Cumulative on purpose: a gateway holds ONE record, so a list containing only
    the newest revocation would let a gateway that missed a publication go on
    serving something everybody else had stopped serving, with nothing to tell
    it otherwise.

    The sequence is what stops an old, validly signed, empty list being replayed
    to un-revoke everything.
    """
    from services.snapshot_control import current_revocations

    response = jsonify(current_revocations())
    # Short, and shorter than the snapshot poll: a revocation that takes an hour
    # to reach gateways is an hour of serving content somebody decided was
    # dangerous enough to revoke.
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


@main_blueprint.route("/.well-known/syndichan/defensive-mode.json")
def snapshot_defensive_mode():
    """Whether gateways should stop forwarding to the origin.

    Returns 404 when not in force, and an expired record counts as not in force.
    A gateway should never have to remember to check an expiry, because the one
    that forgets stays offline after everybody else has come back.
    """
    from services.snapshot_control import current_defensive_mode

    record = current_defensive_mode()
    if record is None:
        return jsonify({"mode": "NORMAL"}), 404
    response = jsonify(record)
    response.headers["Cache-Control"] = "public, max-age=15"
    return response


@main_blueprint.route("/snapshot/object/<digest>")
def snapshot_object(digest):
    """One content-addressed snapshot object.

    Immutable by construction — the name IS the hash — so this is cacheable
    forever by anything between here and the reader, and a cache that returns
    the wrong bytes is caught by the reader rather than trusted.
    """
    from services.snapshot_store import get_object

    cleaned = "".join(c for c in str(digest or "") if c in "0123456789abcdef")
    if len(cleaned) != 64:
        return jsonify({"error": "Not an object hash."}), 400
    body = get_object(cleaned)
    if body is None:
        return jsonify({"error": "No such object in the current snapshot."}), 404

    from services.snapshot_store import current_manifest

    manifest = current_manifest() or {}
    content_type = "application/octet-stream"
    for entry in (manifest.get("routes") or {}).values():
        if entry.get("object") == cleaned:
            content_type = entry.get("content_type") or content_type
            break

    response = make_response(body)
    response.headers["Content-Type"] = content_type
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    # Names this as emergency content so the client verifier checks it against
    # the snapshot manifest rather than against a live object signature it
    # cannot have. The header only SELECTS the path — the manifest signature is
    # what decides whether the bytes are genuine.
    response.headers["X-Syndichan-Source"] = "snapshot"
    response.headers["X-Syndichan-Snapshot"] = str(manifest.get("sequence") or 0)
    return response


@main_blueprint.route("/api/v1/pof/settlement-readiness")
def pof_settlement_readiness():
    """Why epochs with receipts have not settled.

    Published because the alternative is what this network had for months: a
    growing pile of receipts, zero settlements, and no way to learn the reason
    without compiling the Go aggregator and running it by hand. "0 settlements"
    reads as a broken pipeline; it is in fact a correct refusal, and the
    difference matters to anyone deciding whether to run a node.
    """
    from services.settlement_readiness import epoch_readiness

    response = jsonify(epoch_readiness())
    response.headers["Cache-Control"] = "public, max-age=120"
    return response


@main_blueprint.route("/api/v1/gateway/verdict")
def gateway_verdict():
    """What independent validators agree about a gateway — or why they cannot.

    Returns `insufficient_independence` rather than a score whenever the
    agreeing validators do not represent enough distinct operators and networks.
    That is the expected answer on a network run by one person, and it is the
    point: a verdict drawn from machines one party owns would look exactly like
    corroboration while being none.
    """
    from services.gateway_identity import is_identity, normalize
    from services.gateway_quorum import evaluate_gateway

    which = normalize(request.args.get("gateway") or "")
    if not which or not is_identity(which):
        return jsonify({"error": "gateway must be a libp2p Ed25519 peer ID"}), 400
    response = jsonify(evaluate_gateway(which))
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


@main_blueprint.route("/api/v1/gateway/spot-checks")
def gateway_spot_checks():
    """Objects real readers were served, for a validator to re-request.

    Closes the gap that canaries alone leave open. A gateway could serve honest
    bytes for everything a validator is known to ask for and altered bytes to
    everyone else; re-requesting what ACTUAL READERS received means being honest
    during audits is not enough, because the audit set is drawn from real
    traffic after the fact.

    Only object keys and versions — never who read them. The point is which
    objects to re-check, and a feed of what individual people read would be a
    far worse thing to publish than the tampering it helps detect.
    """
    from sqlalchemy import func

    from model.GatewayAudit import GatewayAudit

    from services.canaries import canary_paths

    rows = (
        db.session.query(GatewayAudit.object_key, func.max(GatewayAudit.version))
        .filter(GatewayAudit.observer_kind == "client")
        .group_by(GatewayAudit.object_key)
        .order_by(func.max(GatewayAudit.id).desc())
        .limit(50)
        .all()
    )
    objects = [{"object_key": key, "version": int(version or 0)}
               for key, version in rows]
    # Canaries are mixed in unlabelled and in the same shape as everything else.
    # Marking them would hand a gateway the one thing it needs: a way to tell an
    # audit from a reader, which is precisely what they exist to deny it.
    objects.extend({"object_key": path, "version": 0} for path in canary_paths())

    response = jsonify({
        "objects": objects,
        "note": "Objects readers were recently served. Re-request them to check "
                "that a gateway is not honest only when it thinks it is being "
                "watched.",
    })
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@main_blueprint.route("/api/v1/pof/genesis-seed")
def pof_genesis_seed():
    """The genesis epoch seed, for nodes bootstrapping their first challenges.

    Public and read-only. Publishing it is the design, not a leak: epoch
    randomness is a public on-chain value, and every witness set must be
    re-derivable by anyone auditing a receipt. What matters is that no
    participant chose it — see services/pof_genesis.py.

    Never mints. Until an operator arms genesis from the admin page this returns
    404, so a node cannot fix the seed by polling.
    """
    from services.pof_genesis import get_genesis

    record = get_genesis(create=False)
    if record is None:
        return jsonify({
            "error": "Genesis has not been armed yet.",
            "armed": False,
        }), 404
    # The epoch ANCHOR. Nodes and the aggregator must agree on which epoch
    # number "now" is, and they cannot each derive it from the clock alone:
    # EpochManager counts from the genesis epoch, while unix/3600 is a number in
    # the hundreds of thousands. Two numbering schemes that never meet means
    # every node asks for randomness of an epoch the chain has never heard of.
    # So the anchor is published once, here, and both sides count from it.
    from services.pof_genesis import (
        EPOCH_SECONDS, current_epoch_number, genesis_anchor_unix,
    )

    anchor = genesis_anchor_unix(record)
    response = jsonify({
        "armed": True,
        "seed": record["seed"],
        "epoch": record.get("epoch", 0),
        "created_at": record.get("created_at"),
        "submitted_tx": record.get("submitted_tx"),
        "submitted_at": record.get("submitted_at"),
        "chain_id": 324,
        "epoch_seconds": EPOCH_SECONDS,
        "epoch_anchor": anchor,
        "current_epoch": current_epoch_number(record),
        "note": "Seed for witness selection in the first epoch. Verify against "
                "EpochManager.randomnessOf(epoch) once genesis is on-chain. "
                "Epoch numbers count from `epoch` at `epoch_anchor`, one every "
                "`epoch_seconds`.",
    })
    response.headers["Cache-Control"] = "no-store"
    return response


@main_blueprint.route("/api/v1/pof/register", methods=["POST"])
def pof_register():
    """Queue a node for on-chain registration. Self-service — no per-node approval.

    The ed25519 proof is mandatory and is the point of this endpoint. A node's
    p2p public key IS its libp2p peer id, so it is public knowledge, and
    NodeRegistry registers whoever asks first. Without proof that the p2p key
    consented, anyone could bind a stranger's node to their own wallet and
    collect its earnings.

    The secp256k1 signature is not verified here (this runtime cannot ecrecover)
    — the contract does that when the batch is submitted, so a forged one costs
    gas but changes nothing.
    """
    from model.PofRegistration import (
        PofRegistration, STATUS_PENDING, registration_for_key, verify_p2p_proof,
    )

    payload = request.get_json(silent=True) or {}

    def field(name, default=""):
        return str(payload.get(name) or default).strip()

    def strip0x(value):
        # The image runs Python 3.8; str.removeprefix is 3.9+.
        return value[2:] if value.startswith("0x") else value

    p2p_key = strip0x(field("p2p_public_key").lower())
    wallet = field("wallet").lower()
    proof = strip0x(field("p2p_proof"))
    endpoint_commitment = field("endpoint_commitment").lower()
    try:
        capabilities = int(payload.get("capabilities") or 0)
        nonce = int(payload.get("nonce") or 0)
        sig_v = int(payload.get("v") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "capabilities, nonce and v must be integers"}), 400
    sig_r = field("r").lower()
    sig_s = field("s").lower()

    if len(p2p_key) != 64:
        return jsonify({"error": "p2p_public_key must be a 32-byte hex ed25519 key"}), 400
    if len(wallet) != 42 or not wallet.startswith("0x"):
        return jsonify({"error": "wallet must be a 0x address"}), 400
    if capabilities <= 0:
        return jsonify({"error": "capabilities must name at least one service"}), 400
    if not proof:
        return jsonify({"error": "p2p_proof is required — see /how-it-works"}), 400
    if not verify_p2p_proof(p2p_key, proof, wallet, capabilities, endpoint_commitment, nonce):
        # Either the key does not own this binding, or the payload was altered
        # after signing. Both mean the same thing here: not registerable.
        return jsonify({
            "error": "p2p_proof does not verify for this key and payload.",
        }), 403

    existing = registration_for_key(p2p_key)
    if existing is not None:
        # Idempotent for the same wallet: a node that retries after a restart
        # must not be told it is a duplicate.
        if existing.wallet == wallet:
            return jsonify({
                "ok": True, "status": existing.status,
                "tx_hash": existing.tx_hash, "already_registered": True,
            })
        return jsonify({
            "error": "This p2p key is already queued for a different wallet.",
        }), 409

    db.session.add(PofRegistration(
        p2p_public_key=p2p_key, wallet=wallet, capabilities=capabilities,
        endpoint_commitment=endpoint_commitment, nonce=nonce,
        sig_v=sig_v, sig_r=sig_r, sig_s=sig_s, p2p_proof=proof,
        status=STATUS_PENDING,
    ))
    db.session.commit()
    return jsonify({
        "ok": True, "status": STATUS_PENDING,
        "note": "Queued. It reaches the chain when the next batch is submitted.",
    })


@main_blueprint.route("/api/v1/pof/payout", methods=["POST"])
def pof_payout():
    """Record where a node's earnings should be sent.

    Accepted from anywhere because it carries its own proof: the declaration is
    signed by the node's ed25519 identity key, so only that node can say where
    its rewards go. Without the signature this endpoint would let anyone
    redirect a stranger's earnings by naming their key.

    The address is inside the signed bytes, and a sequence number decides which
    of two declarations wins — otherwise the outcome would depend on arrival
    order, which is not something a node can control.
    """
    from model.PofRegistration import (
        PofPayout, payout_for_key, verify_payout_declaration,
    )

    payload = request.get_json(silent=True) or {}
    key = str(payload.get("p2p_public_key") or "").strip().lower()
    if key.startswith("0x"):
        key = key[2:]
    payout = str(payload.get("payout") or "").strip().lower()
    signature = str(payload.get("signature") or "").strip()
    if signature.startswith("0x"):
        signature = signature[2:]
    try:
        sequence = int(payload.get("sequence") or 0)
    except (TypeError, ValueError):
        return jsonify({"error": "sequence must be an integer"}), 400

    if len(key) != 64:
        return jsonify({"error": "p2p_public_key must be a 32-byte hex ed25519 key"}), 400
    if len(payout) != 42 or not payout.startswith("0x"):
        return jsonify({"error": "payout must be a 0x address"}), 400
    if payout == "0x" + "0" * 40:
        return jsonify({"error": "payout cannot be the zero address"}), 400
    if not verify_payout_declaration(key, payout, sequence, signature):
        return jsonify({"error": "signature does not verify for this key"}), 403

    existing = payout_for_key(key)
    if existing is not None:
        if sequence < existing.sequence:
            # Older than what we hold: almost certainly a replay of a
            # superseded declaration, so the newer choice stands.
            return jsonify({
                "ok": True, "payout": existing.payout, "sequence": existing.sequence,
                "note": "A newer declaration is already on record.",
            })
        existing.payout = payout
        existing.sequence = sequence
        existing.signature = signature
    else:
        db.session.add(PofPayout(
            p2p_public_key=key, payout=payout, sequence=sequence, signature=signature))
    db.session.commit()
    return jsonify({"ok": True, "payout": payout, "sequence": sequence})


@main_blueprint.route("/api/v1/pof/claim/<int:epoch>/<node_id>")
def pof_claim(epoch, node_id):
    """A node's reward and Merkle proof for an epoch.

    Public: the reward tree is committed on-chain and every leaf is derivable by
    anyone with the receipts, so a proof is not a secret — it is arithmetic. It
    is served because the alternative is making operators run an aggregator to
    learn their own proof, which would restrict claiming to people who can
    compile Go.
    """
    from model.PofSettlement import claim_for_node

    record, row = claim_for_node(epoch, node_id)
    if record is None:
        return jsonify({"error": "Epoch %d has not been settled." % epoch, "settled": False}), 404
    if row is None:
        return jsonify({
            "settled": True, "earned": False, "epoch": epoch,
            "reward_root": record.reward_root,
            "note": "This node has no reward in that epoch.",
        }), 404
    return jsonify({
        "settled": True,
        "earned": True,
        "epoch": epoch,
        "reward_root": record.reward_root,
        "submitted_tx": record.submitted_tx,
        "claim": row,
        "how": "Call RewardDistributor.claim(epoch, node_id, recipient, amount, "
               "service_breakdown_hash, proof) once the epoch is finalized.",
    })


@main_blueprint.route("/api/v1/pof/settlement/<int:epoch>")
def pof_settlement_public(epoch):
    """Public summary of a settled epoch, so its roots can be checked."""
    import json as _json

    from model.PofSettlement import settlement_for_epoch

    record = settlement_for_epoch(epoch)
    if record is None:
        return jsonify({"error": "Epoch %d has not been settled." % epoch}), 404
    return jsonify({
        "epoch": record.epoch,
        "receipt_root": record.receipt_root,
        "reward_root": record.reward_root,
        "randomness": record.randomness,
        "total_rewards": record.total_rewards,
        "accepted": record.accepted,
        "rejected": record.rejected,
        # Published rather than hidden: an operator whose work was not paid is
        # owed the reason.
        "rejections": _json.loads(record.rejections or "[]"),
        "claim_count": len(record.claim_rows()),
        "submitted_tx": record.submitted_tx,
        "verify": "Re-run pof-settle for this epoch; the roots must match.",
    })


@main_blueprint.route("/api/v1/pof/receipts", methods=["POST"])
def pof_receipts_upload():
    """Spool signed receipts for the aggregator.

    Deliberately unverified here: a receipt's identity is keccak256 over its
    canonical encoding and this runtime has no keccak, so signature checking
    belongs to the aggregator, which recomputes every hash and rejects anything
    that fails. A forged receipt is worthless — settlement requires attestations
    from the witness set the chain randomness selected — so the caps below
    protect disk, not correctness.
    """
    import json as _json

    from model.PofRelay import (
        MAX_RECEIPTS_PER_NODE_PER_EPOCH, MAX_RECEIPT_BYTES, PofReceipt,
        receipt_count_for, receipt_exists,
    )

    payload = request.get_json(silent=True) or {}
    items = payload.get("receipts")
    if not isinstance(items, list) or not items:
        return jsonify({"error": "receipts must be a non-empty array"}), 400
    if len(items) > 1000:
        return jsonify({"error": "send at most 1000 receipts per request"}), 413

    stored, skipped = 0, 0
    for item in items:
        if not isinstance(item, dict):
            skipped += 1
            continue
        receipt_hash = str(item.get("hash") or "").strip().lower()
        provider_key = str(item.get("provider_key") or "").strip().lower()
        try:
            epoch = int(item.get("epoch"))
        except (TypeError, ValueError):
            skipped += 1
            continue
        body = item.get("body")
        if len(receipt_hash) != 64 or len(provider_key) != 64 or not isinstance(body, dict):
            skipped += 1
            continue
        encoded = _json.dumps(body, separators=(",", ":"))
        if len(encoded) > MAX_RECEIPT_BYTES:
            skipped += 1
            continue
        if receipt_exists(receipt_hash):
            skipped += 1  # already spooled; re-uploading is normal after a restart
            continue
        if receipt_count_for(provider_key, epoch) >= MAX_RECEIPTS_PER_NODE_PER_EPOCH:
            skipped += 1
            continue
        db.session.add(PofReceipt(
            epoch=epoch, receipt_hash=receipt_hash,
            provider_key=provider_key, body=encoded))
        stored += 1
    db.session.commit()
    return jsonify({"ok": True, "stored": stored, "skipped": skipped})


@main_blueprint.route("/api/v1/pof/receipts/<int:epoch>")
def pof_receipts_for_epoch(epoch):
    """Every spooled receipt for an epoch, for the aggregator to settle."""
    import json as _json

    from model.PofRelay import receipts_for_epoch

    rows = []
    for record in receipts_for_epoch(epoch):
        try:
            rows.append(_json.loads(record.body))
        except ValueError:
            continue
    response = jsonify({"epoch": epoch, "receipts": rows, "count": len(rows)})
    response.headers["Cache-Control"] = "no-store"
    return response


@main_blueprint.route("/api/v1/pof/assignments", methods=["POST"])
def pof_assignments_publish():
    """A node advertises what it is holding, so challengers know what to test.

    Unsigned on purpose. The claim is only ever a liability: advertising a shard
    you do not hold earns nothing (the proof fails on unpredictable chunks), and
    omitting one you do hold earns nothing either. There is no gain to forge, so
    a signature would add ceremony without adding safety — unlike the payout
    address, where a forgery pays the forger.
    """
    import json as _json

    from model.PofRelay import (
        MAX_ASSIGNMENT_BYTES, MAX_ASSIGNMENTS_PER_NODE, PofAssignment,
    )

    payload = request.get_json(silent=True) or {}
    key = str(payload.get("p2p_public_key") or "").strip().lower()
    if key.startswith("0x"):
        key = key[2:]
    items = payload.get("assignments")
    if len(key) != 64:
        return jsonify({"error": "p2p_public_key must be a 32-byte hex ed25519 key"}), 400
    if not isinstance(items, list):
        return jsonify({"error": "assignments must be an array"}), 400
    # Refusals say what the limit IS. A node told only "too large" can do
    # nothing but keep sending the same thing forever, which is exactly what
    # happened: a node holding 4185 shards retried every pass, advertised
    # nothing, and had no way to learn what would have been accepted.
    if len(items) > MAX_ASSIGNMENTS_PER_NODE:
        return jsonify({
            "error": "too many assignments: %d sent, %d accepted per node"
                     % (len(items), MAX_ASSIGNMENTS_PER_NODE),
            "max_assignments": MAX_ASSIGNMENTS_PER_NODE,
            "max_bytes": MAX_ASSIGNMENT_BYTES,
        }), 413
    encoded = _json.dumps(items, separators=(",", ":"))
    if len(encoded) > MAX_ASSIGNMENT_BYTES:
        return jsonify({
            "error": "assignment list is too large: %d bytes, %d accepted"
                     % (len(encoded), MAX_ASSIGNMENT_BYTES),
            "max_assignments": MAX_ASSIGNMENTS_PER_NODE,
            "max_bytes": MAX_ASSIGNMENT_BYTES,
        }), 413

    record = (
        db.session.query(PofAssignment)
        .filter(PofAssignment.p2p_public_key == key)
        .one_or_none()
    )
    if record is None:
        db.session.add(PofAssignment(p2p_public_key=key, body=encoded, count=len(items)))
    else:
        record.body = encoded
        record.count = len(items)
    db.session.commit()
    return jsonify({"ok": True, "count": len(items)})


@main_blueprint.route("/api/v1/pof/assignments")
def pof_assignments_list():
    """The network's advertised assignments — what challengers draw from."""
    import json as _json

    from model.PofRelay import all_assignments

    out = []
    for record in all_assignments():
        try:
            items = _json.loads(record.body)
        except ValueError:
            continue
        out.append({"p2p_public_key": record.p2p_public_key, "assignments": items})
    response = jsonify({"nodes": out})
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


@main_blueprint.route("/api/v1/pof/candidates")
def pof_candidates():
    """The witness pool: every registered node, with the weights it is drawn on.

    THE point of this endpoint is that there is exactly one of it. Witness
    selection is computed independently three times — by the node deciding whom
    to ask for an attestation, by each witness deciding whether it was entitled
    to give one, and by settlement deciding whether the attestations it received
    were legitimate. Those three have to draw from an identical candidate list in
    an identical order, or they produce different sets and every honest receipt
    is rejected for "attestations from witnesses the protocol did not select" —
    a failure indistinguishable, from the outside, from fraud.

    The pool is REGISTERED nodes, not nodes that advertised shards. Witnessing
    needs no stored data: it is a signature over a Merkle proof somebody else
    produced. Restricting the pool to storage providers would mean the only
    people auditing storage are the people selling it.
    """
    from model.PofRegistration import PofRegistration, STATUS_SUBMITTED
    from services.keccak import keccak256
    from services.pof_chain import (
        BOOTSTRAP_STAKE_FLOOR_WEI, DEFAULT_REPUTATION_BPS, node_owner,
        pof_addresses, total_staked,
    )

    addresses = pof_addresses()
    registry = addresses.get("NodeRegistry")
    vault = addresses.get("StakeVault")

    rows = []
    records = (
        db.session.query(PofRegistration)
        .filter(PofRegistration.status == STATUS_SUBMITTED)
        .order_by(PofRegistration.p2p_public_key.asc())
        .limit(500)
        .all()
    )
    for record in records:
        key = (record.p2p_public_key or "").lower()
        if len(key) != 64:
            continue
        try:
            node_id = keccak256(bytes.fromhex(key)).hex()
        except ValueError:
            continue
        owner = node_owner(registry, node_id)
        if owner is None:
            # Queued here but not on-chain: not a candidate. Settlement reads
            # the registry directly and would drop it, so including it would put
            # this node in a pool the aggregator does not share.
            continue
        rows.append({
            "p2p_public_key": key,
            "node_id": "0x" + node_id,
            "owner": owner,
            "stake_wei": str(total_staked(vault, owner)),
            "reputation_bps": DEFAULT_REPUTATION_BPS,
        })

    response = jsonify({
        "candidates": rows,
        "bootstrap_stake_floor_wei": str(BOOTSTRAP_STAKE_FLOOR_WEI),
        "note": "Registered nodes eligible to witness. Stake and owner are read "
                "from NodeRegistry and StakeVault on Ethereum Mainnet; verify against "
                "the chain if you do not trust this server.",
    })
    # Short: stake changes on-chain and a stale pool is a different pool.
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


@main_blueprint.route("/api/v1/pof/payouts")
def pof_payouts():
    """Every declared payout address, for the aggregator building reward rows."""
    from model.PofRegistration import all_payouts

    rows = [{
        "p2p_public_key": p.p2p_public_key,
        "payout": p.payout,
        "sequence": p.sequence,
    } for p in all_payouts()]
    response = jsonify({"payouts": rows})
    response.headers["Cache-Control"] = "public, max-age=15"
    return response


@main_blueprint.route("/api/v1/pof/register/status/<p2p_public_key>")
def pof_register_status(p2p_public_key):
    """Where a queued registration has got to."""
    from model.PofRegistration import registration_for_key

    key = p2p_public_key.lower()
    record = registration_for_key(key[2:] if key.startswith("0x") else key)
    if record is None:
        return jsonify({"registered": False, "status": "unknown"}), 404
    return jsonify({
        "registered": record.status == "submitted",
        "status": record.status,
        "wallet": record.wallet,
        "tx_hash": record.tx_hash,
        "error": record.error,
        "queued_at": record.created_at.isoformat() + "Z" if record.created_at else None,
    })


@main_blueprint.route("/api/v1/pof/randomness/<int:epoch>")
def pof_randomness(epoch):
    """Epoch randomness, read from EpochManager for nodes that do not run a
    chain client.

    Convenience, not authority: the response says where the value came from so a
    node that cares can check `randomnessOf(epoch)` itself. A lying server could
    skew which chunks a node is asked to prove, but cannot forge earnings —
    receipts still need signatures from independently selected witnesses, and
    each witness recomputes the same derivation.
    """
    from services.pof_chain import ChainError, epoch_at, pof_addresses
    from services.pof_genesis import epoch_randomness

    epoch_manager = pof_addresses().get("EpochManager")
    row = None
    if epoch_manager:
        try:
            row = epoch_at(epoch_manager, epoch)
        except ChainError:
            # An unreachable chain must not stop a live epoch: the derived value
            # below needs no RPC, and a node that cannot audit because our node
            # provider is down is an outage we inflicted on it.
            row = None
    if row is not None:
        response = jsonify({
            "epoch": epoch,
            "randomness": row["randomness"],
            "exists": True,
            "settled": True,
            "source": "EpochManager.epochs(%d) at %s on Ethereum Mainnet (chain 1)"
                      % (epoch, epoch_manager),
            "submitted_at": row["submitted_at"],
            "challenge_deadline": row["challenge_deadline"],
            "finalized": row["finalized"],
        })
        response.headers["Cache-Control"] = "public, max-age=30"
        return response

    # Not on-chain yet — which is the normal state of the epoch being worked in.
    derived, source = epoch_randomness(epoch)

    if derived is None:
        return jsonify({"epoch": epoch, "exists": False, "error": source}), 404
    response = jsonify({
        "epoch": epoch,
        "randomness": derived,
        "exists": True,
        "settled": False,
        "source": source,
        "note": "This epoch is not settled. The same value is submitted with it, "
                "so it can be checked against EpochManager.randomnessOf(epoch) "
                "afterwards.",
    })
    response.headers["Cache-Control"] = "public, max-age=30"
    return response


@main_blueprint.route("/reputation")
def reputation():
    # Merged into /network as an anchored section. Kept as a redirect so
    # existing links, bookmarks and the node software's references do not
    # 404; the content itself now lives in templates/network.html.
    return redirect(url_for("main.network_topology") + "#reputation", code=301)


@main_blueprint.route("/claim")
def claim():
    """Kept only to redirect. The claim panel lives on the AXONCoins page now.

    Earning and spending were on separate URLs, which made claiming read as a
    different system from buying — somebody running a node had to know a second
    page existed in order to get paid. It is the same balance either way.

    Rewards remain PULL, not push: nothing arrives because an epoch settled,
    RewardDistributor.claim has to be called with a Merkle proof. Moving the
    button does not change that, it puts it where people already are.

    A redirect rather than a deletion, because /epochs, the onramp page and
    anybody's bookmarks already point here. 301 so it is remembered.
    """
    return redirect(url_for("credits.index") + "#claim", code=301)


@main_blueprint.route("/epochs")
def epochs():
    """The epoch chain on Ethereum Mainnet, drawn as a linked list.

    Read straight from the chain rather than from our database: the point of
    settling on-chain is that the record does not depend on this server telling
    the truth, and a page served from local state would quietly undo that.
    """
    from services.pof_chain import (
        ChainError, CHAIN_EXPLORER, epoch_chain, explorer_address_url, pof_addresses,
    )

    addresses = pof_addresses()
    epoch_manager = addresses.get("EpochManager")
    rows, error = [], None
    if not epoch_manager:
        error = "No EpochManager address is saved yet — deploy the contracts first."
    else:
        try:
            rows = epoch_chain(epoch_manager)
        except ChainError as exc:
            error = str(exc)

    # Unix timestamps are precise and unreadable. An operator looking at this
    # page wants to know whether the wait is minutes or a day, and computing
    # that from an epoch second in their head is a task nobody should be set.
    now = int(time.time())

    def _relative(when):
        if not when:
            return "unknown"
        delta = int(when) - now
        past = delta < 0
        delta = abs(delta)
        if delta < 90:
            unit = "%d seconds" % delta
        elif delta < 5400:
            unit = "%d minutes" % (delta // 60)
        elif delta < 172800:
            unit = "%d hours" % (delta // 3600)
        else:
            unit = "%d days" % (delta // 86400)
        return ("%s ago" % unit) if past else ("in %s" % unit)

    for row in rows:
        row["submitted_when"] = _relative(row.get("submitted_at"))
        row["deadline_when"] = _relative(row.get("challenge_deadline"))
        # Finalizable, not finalized: the window has closed and nobody disputed,
        # so the call would now succeed. finalize() is permissionless, and this
        # is how anyone knows it is worth making.
        row["finalizable"] = (
            not row.get("finalized")
            and not row.get("open_disputes")
            and int(row.get("challenge_deadline") or 0) <= now
        )

    from services.pof_genesis import get_genesis

    return render_template(
        "epochs.html",
        epochs=rows,
        error=error,
        addresses=addresses,
        epoch_manager=epoch_manager,
        explorer=CHAIN_EXPLORER,
        explorer_address_url=explorer_address_url,
        genesis=get_genesis(create=False),
    )


@main_blueprint.route("/how-it-works")
def how_it_works():
    """Folded into the FAQ.

    Kept as a redirect rather than deleted: the URL is linked from the front
    page, the DAO, the MetaMask page and anywhere people have bookmarked it, and
    a 404 teaches a reader the site is broken rather than that a page moved.
    """
    # POINTED AT /economy BECAUSE main.faq NO LONGER EXISTS. The FAQ route and
    # its template were removed with the rest of the stripped features, and this
    # line kept redirecting to it -- so a URL kept precisely because "a 404
    # teaches a reader the site is broken" was returning a 500, which teaches
    # them the same thing louder. url_for on a missing endpoint raises
    # BuildError at render time, so the failure was total rather than cosmetic.
    #
    # /economy is the closest live successor to the #why-crypto anchor this
    # pointed at. Found by tests/test_url_endpoints.py, which exists to catch
    # exactly this and had never been able to run.
    return redirect(url_for("main.economy"), code=301)


@main_blueprint.route("/metamask")
def metamask_help():
    """Install MetaMask and connect it to Ethereum Mainnet.

    Public on purpose: someone who does not yet have a wallet cannot sign in, so
    the page that tells them how to get one must not require a login.
    """
    # Read rather than hardcoded: the address changes if the token is ever
    # redeployed, and a help page confidently naming the wrong contract is worse
    # than one naming none — somebody would add it and see a permanent zero.
    from services.pof_chain import token_address

    try:
        token = token_address()
    except Exception:
        token = ""
    return render_template("metamask-help.html", token_address=token)


@main_blueprint.route("/epochs.json")
def epochs_json():
    """Which epochs are waiting to be finalized.

    Public, because the chain is: anyone can read the same state from an RPC and
    anyone can make the call. Publishing it means a stuck settlement is visible
    to somebody other than whoever happens to open the admin console — which is
    the failure this exists for, an epoch sitting a day past its deadline
    because no one was looking.

    Served from a cache the chain refreshes rarely. Reading an external RPC per
    request would put a network round trip inside a page load, which has taken
    this site down before.
    """
    from services.pof_alerts import finalizable

    response = jsonify({"finalizable": finalizable()})
    response.headers["Cache-Control"] = "public, max-age=60"
    return response


@main_blueprint.route("/updates.json")
def updates_json():
    """Admin-authored updates for the signed-in slip pop-up.

    Returns [] for anonymous visitors, so the pop-up is a no-op for them. This
    replaced the old front-page "Updates" section: the same content, shown as a
    dismissible pop-up to signed-in slips instead of a block on the front page.
    """
    from model.Slip import get_slip
    from model.FrontPageUpdate import recent_front_page_updates

    if get_slip() is None:
        response = jsonify({"updates": []})
        response.headers["Cache-Control"] = "no-store"
        return response
    updates = [
        {
            "id": update.id,
            "title": update.title or "",
            "body": update.body or "",
            "created_at_display": update.created_at_display,
        }
        for update in recent_front_page_updates()
    ]
    response = jsonify({"updates": updates})
    response.headers["Cache-Control"] = "no-store"
    return response


@main_blueprint.route("/nntp-watermark/<sha256>")
def nntp_watermark(sha256):
    """Serve an embedded federated source watermark by content hash. Immutable
    (keyed by content), so cache hard."""
    import re
    from model.NntpSourceWatermark import get_watermark
    if not re.match(r"^[0-9a-f]{64}$", sha256 or ""):
        abort(404)
    row = get_watermark(sha256)
    if row is None:
        abort(404)
    response = make_response(bytes(row.data))
    response.headers["Content-Type"] = row.mime or "image/png"
    response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
    return response


@main_blueprint.route("/banned")
def banned():
    """The ban page shown to permanently-banned visitors — renders whatever
    annoying content, theme, custom CSS/HTML/JS and opt-in annoyance features the
    sysop configured on the admin dashboard. Rendered unconditionally so the
    sysop can preview it (see the admin dashboard's "Preview ban page" link)."""
    from model.BanPageAsset import (
        ban_page_assets_by_kind,
        ban_page_customization,
        enabled_ban_page_features,
    )
    custom = ban_page_customization()
    return render_template(
        "banned.html",
        assets=ban_page_assets_by_kind(enabled_only=True),
        ban_theme=custom["theme"],
        ban_custom_css=custom["custom_css"],
        ban_custom_html=custom["custom_html"],
        ban_custom_js=custom["custom_js"],
        ban_features=sorted(enabled_ban_page_features()),
    )


@main_blueprint.route("/session/keepalive", methods=["POST", "GET"])
def session_keepalive():
    """Marks the session as active for the per-account idle-timeout. The
    before_request refreshes the activity timestamp for this path; the client
    (base.html) pings it only on genuine user interaction, throttled."""
    return ("", 204)


@main_blueprint.route("/live-typing/push", methods=["POST"])
def live_typing_push():
    """Receives a poster's in-progress post/reply draft (throttled by the client)
    for the admin live-monitor panel. Records the draft against the visitor's IP
    in Redis with a short TTL. Best-effort — always returns 204, never errors."""
    try:
        from services.live_typing import record_draft
        from post import get_ip_address
        payload = request.get_json(silent=True) or {}
        if isinstance(payload, dict):
            record_draft(
                comp_id=str(payload.get("comp_id") or ""),
                ip=get_ip_address(),
                text=str(payload.get("text") or ""),
                path=str(payload.get("path") or ""),
                board=str(payload.get("board") or ""),
                name=str(payload.get("name") or ""),
            )
    except Exception:
        pass
    return ("", 204)


@main_blueprint.route("/presence/ping", methods=["POST", "GET"])
def presence_ping():
    """Public heartbeat (base.html): records the visitor's IP as 'present now' so
    the admin live world map can place a dot where each current visitor is.
    Best-effort — always returns 204, never errors."""
    try:
        from services.presence import record_presence
        from post import get_ip_address
        page = request.args.get("p") or request.form.get("p") or ""
        record_presence(get_ip_address(), page=page)
    except Exception:
        pass
    return ("", 204)


@main_blueprint.route("/federation/request", methods=["POST"])
def federation_request():
    from model.Federation import record_chan_request
    # Honeypot: real users never fill this hidden field; bots do.
    if (request.form.get("website") or "").strip():
        return redirect(url_for("main.network_topology"))
    created = record_chan_request(
        request.form.get("action"),
        request.form.get("url"),
        name=request.form.get("name"),
        message=request.form.get("message"),
    )
    if created is None:
        flash("Please choose add or remove and include the chan's URL.")
    else:
        flash("Thanks — your request was submitted and will be reviewed.")
    # POINTED AT /network BECAUSE main.federation NO LONGER EXISTS. The
    # federation PAGE was removed and this POST handler survived, so both of its
    # redirects raised BuildError -- a 500 on every submission, AFTER
    # record_chan_request() had already written the row. Accepting the data and
    # then erroring is the worst of the available outcomes.
    #
    # Found by tests/test_hub_catalog.py, which failed with "substring not
    # found" looking for `def federation()`; the endpoint reference is in
    # PYTHON, so tests/test_url_endpoints.py -- which scans templates -- could
    # not have caught it.
    #
    # NOTE FOR WHOEVER OWNS THIS: requests are still recorded and there is no
    # longer a page that displays them. Keeping the endpoint alive is the
    # conservative choice; retiring it is a product decision, not a fix.
    return redirect(url_for("main.network_topology") + "#request")




def _sync_boards_if_available(boards):
    if app.config.get("AGGREGATOR_REQUEST_SYNC", False) is False:
        return False
    try:
        from aggregator_sync import sync_boards_if_due
        return sync_boards_if_due(boards)
    except Exception:
        db.session.rollback()
        app.logger.exception("Board aggregator sync failed during firehose render")
        return False


def _default_greeting():
    """The front-page landing block, rendered as a Jinja template.

    It used to be injected raw. It is rendered now so the block can `{% include %}`
    shared components -- specifically the live peer canvas, which the hero shows
    in place of the hand-drawn network motif that used to sit there. A picture of
    a network is a weaker argument than the network.

    TRUST: this executes the file as a template, so anyone who can WRITE to
    deploy-configs/ can execute code. That is the same authority templates/
    already carries, and anyone with write access to the deployment directory
    has that authority regardless. It is NOT user input and must never become
    user input.

    A template error falls back to the raw text rather than 500ing the front
    page: this is the page somebody loads to find out whether the network is up.
    """
    try:
        with open(DEFAULT_GREETING_PATH, encoding="utf-8") as greeting_file:
            source = greeting_file.read()
    except FileNotFoundError:
        return ""
    try:
        from flask import render_template_string

        return render_template_string(source)
    except Exception:
        current_app.logger.exception("Greeting template failed to render; serving it raw")
        return source
