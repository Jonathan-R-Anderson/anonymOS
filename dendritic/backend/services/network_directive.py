"""The signed statement of where this network lives.

DNS is what breaks in every scenario this exists for — a seized name, a
registrar dispute, a dead server. So DNS cannot be the authority. The authority
is a document signed by the operator's wallet, which nodes carry, verify
themselves, and prefer over anything a name resolves to.

WHY THE SEQUENCE MATTERS MORE THAN THE SIGNATURE
-----------------------------------------------
A signature proves who authorised a directive. It says nothing about WHEN, so a
directive captured today can be replayed in a year to drag the network back to
a domain the attacker has since acquired. The monotonic sequence is what makes
an old directive worthless: a node that has seen 7 refuses 6 forever, and the
refusal is recorded rather than silent.

THE UNCOMFORTABLE PART
----------------------
Whoever holds the wallet can point the whole network at a domain they control.
Signatures do not prevent that; they only establish that the key holder
authorised it. Three things narrow the window, and none of them close it:

  * `not_before` — an ordinary move takes effect after a delay, which is the
    time a legitimate operator has to notice and respond;
  * `freeze` — a directive that pins the network where it is and refuses further
    directives. Deliberately the CHEAPEST one to issue, because its failure mode
    is an outage and the alternative's failure mode is losing the project;
  * `emergency` — skips the delay, because immediate failover is the actual
    requirement. It buys that with visibility: loud logs, a permanent record,
    and a banner. Speed is paid for by being impossible to do quietly.

The real answer is a second independent signer, and that needs a second
operator to exist. See roadmap/domain-and-origin-succession.md.
"""

import json
import re

from shared import app

SETTING_CURRENT = "network_directive"
SETTING_HISTORY = "network_directive_history"

# What a directive can do.
KIND_MOVE = "move"        # adopt a new domain / origin / signing key
KIND_FREEZE = "freeze"    # pin where we are; refuse further directives
KIND_RESUME = "resume"    # lift a freeze
KINDS = (KIND_MOVE, KIND_FREEZE, KIND_RESUME)

# How long an ordinary move waits before nodes act on it. Long enough for a
# person to notice a directive they did not issue, short enough to be usable.
DEFAULT_DELAY_SECONDS = 3600

# Fields covered by the signature, in this order. Anything not listed here is
# NOT signed and must not be trusted — which is why the verifier rebuilds the
# message from these alone rather than from whatever arrived.
SIGNED_FIELDS = (
    "kind", "sequence", "issued_at", "not_before", "emergency",
    "origin_domain", "origin_address", "origin_key", "note",
)

_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?"
                     r"(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_ADDRESS = re.compile(r"^[a-z0-9.:\[\]-]+:[0-9]{1,5}$")
_HEXKEY = re.compile(r"^[0-9a-f]{64}$")


class DirectiveError(ValueError):
    """Refused. The message is shown to an operator, so it says which rule."""


def canonical(directive):
    """The exact bytes that get signed.

    Byte-exact and independent of dict ordering, because a signature over "some
    JSON" is a signature over whatever that particular encoder emitted. Two
    implementations that serialise differently would disagree about a valid
    signature, and the one that disagrees during an incident is the Go one, on
    a machine nobody can reach.

    Line-based rather than JSON on purpose: it is trivially re-implementable in
    any language, and a person can read it in a wallet's signing prompt and see
    what they are agreeing to. A wallet dialog showing minified JSON is a wallet
    dialog nobody reads.
    """
    lines = ["syndichan network directive v1"]
    for field in SIGNED_FIELDS:
        value = directive.get(field)
        if value is None or value == "":
            value = "-"
        elif value is True:
            value = "yes"
        elif value is False:
            value = "no"
        lines.append("%s: %s" % (field, value))
    return "\n".join(lines)


def parse_canonical(text):
    """The inverse of `canonical`. Raises DirectiveError on anything unexpected.

    Exists so the format can be shown to round-trip, and because the Go verifier
    has to do exactly this. Splitting on the FIRST ": " is what makes the free
    text `note` safe: a note containing "origin_domain: evil.example" stays part
    of the note's value instead of becoming a field of its own.
    """
    lines = (text or "").split("\n")
    if not lines or not lines[0].startswith("syndichan network directive"):
        raise DirectiveError("Not a network directive.")
    if len(lines) != 1 + len(SIGNED_FIELDS):
        raise DirectiveError("Expected %d lines, got %d."
                             % (1 + len(SIGNED_FIELDS), len(lines)))

    directive = {}
    for field, line in zip(SIGNED_FIELDS, lines[1:]):
        prefix = "%s: " % field
        if not line.startswith(prefix):
            raise DirectiveError("Expected %r, got %r." % (field, line[:40]))
        value = line[len(prefix):]
        if value == "-":
            value = False if field == "emergency" else ""
        elif field == "emergency":
            value = value == "yes"
        elif field == "sequence":
            if not value.isdigit():
                raise DirectiveError("sequence must be digits.")
            value = int(value)
        elif field in ("issued_at", "not_before"):
            if not value.isdigit():
                raise DirectiveError("%s must be digits." % field)
            value = int(value)
        directive[field] = value
    return directive


def build(kind, sequence, now, origin_domain="", origin_address="",
          origin_key="", emergency=False, note="", delay_seconds=None):
    """Assemble a directive ready to be signed. Raises DirectiveError."""
    if kind not in KINDS:
        raise DirectiveError("Unknown directive kind %r." % (kind,))
    # int(1.5) is 1, so a plain int() would silently accept a float and sign a
    # different sequence than the one asked for. On the one action that can
    # relocate the network, quietly changing the number is not acceptable.
    if isinstance(sequence, bool) or isinstance(sequence, float):
        raise DirectiveError("sequence must be a whole number.")
    try:
        sequence = int(str(sequence).strip())
    except (TypeError, ValueError):
        raise DirectiveError("sequence must be a whole number.")
    if sequence < 1:
        raise DirectiveError("sequence starts at 1.")

    origin_domain = (origin_domain or "").strip().lower()
    origin_address = (origin_address or "").strip().lower()
    origin_key = (origin_key or "").strip().lower()

    if kind == KIND_MOVE:
        if not origin_domain:
            raise DirectiveError("A move must name the new domain.")
        if not _DOMAIN.match(origin_domain):
            raise DirectiveError("%r is not a domain name." % origin_domain)
        if origin_address and not _ADDRESS.match(origin_address):
            raise DirectiveError("origin_address must be host:port.")
        if origin_key and not _HEXKEY.match(origin_key):
            raise DirectiveError("origin_key must be 64 hex characters "
                                 "(a raw Ed25519 public key).")
    elif origin_domain or origin_address or origin_key:
        # A freeze that also carried a domain would be a move wearing the name
        # of the thing meant to STOP moves.
        raise DirectiveError("A %s directive cannot carry origin details." % kind)

    emergency = bool(emergency)
    if delay_seconds is None:
        delay_seconds = 0 if (emergency or kind != KIND_MOVE) else DEFAULT_DELAY_SECONDS

    return {
        "kind": kind,
        "sequence": sequence,
        "issued_at": int(now),
        "not_before": int(now) + int(delay_seconds),
        "emergency": emergency,
        "origin_domain": origin_domain,
        "origin_address": origin_address,
        "origin_key": origin_key,
        "note": (note or "").strip()[:200].replace("\n", " "),
    }


def current():
    """The directive in force, or None."""
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING_CURRENT, "") or "null")
    except ValueError:
        return None
    return stored if isinstance(stored, dict) else None


def history():
    from model.SiteSetting import get_setting

    try:
        stored = json.loads(get_setting(SETTING_HISTORY, "") or "[]")
    except ValueError:
        return []
    return stored if isinstance(stored, list) else []


def next_sequence():
    """One past whatever is in force. The number the admin page proposes."""
    existing = current()
    return int((existing or {}).get("sequence") or 0) + 1


def frozen():
    existing = current()
    return bool(existing and existing.get("kind") == KIND_FREEZE)


# "Not supplied" and "nothing is in force" are different answers, and None
# cannot mean both. A caller asking to check against nothing must not silently
# get a database read instead — on this check, the difference decides whether a
# stale directive is refused.
_LOOK_IT_UP = object()


def check_acceptable(directive, existing=_LOOK_IT_UP):
    """Whether this directive may replace what is in force.

    Separate from signature checking so the two failures stay distinguishable:
    "that is not your signature" and "that signature is valid but the directive
    is stale" want different responses from an operator.
    """
    if existing is _LOOK_IT_UP:
        existing = current()
    if not existing:
        return

    incoming_sequence = int(directive.get("sequence") or 0)
    held = int(existing.get("sequence") or 0)
    if incoming_sequence <= held:
        # The whole point of the sequence. A directive captured from the wire
        # today is worthless tomorrow because this refuses it.
        raise DirectiveError(
            "Sequence %d is not newer than the %d already in force. A directive "
            "may only move forward." % (incoming_sequence, held))

    if existing.get("kind") == KIND_FREEZE and directive.get("kind") != KIND_RESUME:
        raise DirectiveError(
            "The network is frozen at sequence %d. Issue a resume directive "
            "before anything else." % held)


def verify_signature(directive, signature):
    """The address that signed, or None. Raises RuntimeError if unverifiable.

    Goes through the renderer, which means this only works while the origin is
    healthy. That is fine HERE — this is the path that issues a directive, and
    issuing happens before the emergency. Nodes verify independently in Go,
    against a wallet pinned in their config, because the whole point is that
    they must not need anything of ours to be up.
    """
    from services.wallet_auth import recover_signer

    return recover_signer(canonical(directive), signature)


def admin_wallet():
    from model.Slip import configured_admin_wallet_address

    return (configured_admin_wallet_address() or "").strip().lower()


def accept(directive, signature, signer):
    """Record a verified directive as the one in force.

    Stores the signature with it. A directive without its signature is a claim
    this server is making, and every node that receives it has to be able to
    check it against the pinned wallet rather than take our word.
    """
    from model.SiteSetting import get_setting, set_setting
    from shared import db

    check_acceptable(directive)

    record = dict(directive)
    record["signature"] = signature
    record["signer"] = (signer or "").strip().lower()

    try:
        past = json.loads(get_setting(SETTING_HISTORY, "") or "[]")
        if not isinstance(past, list):
            past = []
    except ValueError:
        past = []
    existing = current()
    if existing:
        past.append(existing)
    # Kept in full, not summarised. This is the audit trail for the one action
    # that can move the entire network, and a summary of it is not evidence.
    set_setting(SETTING_HISTORY, json.dumps(past[-50:]))
    set_setting(SETTING_CURRENT, json.dumps(record))
    db.session.commit()

    if record.get("emergency"):
        # Loud on purpose. An emergency directive skips the waiting period, and
        # the only thing bought in exchange is that it cannot happen quietly.
        app.logger.error(
            "NETWORK DIRECTIVE (EMERGENCY): kind=%s sequence=%s domain=%s "
            "signed by %s — this took effect immediately, with no delay",
            record.get("kind"), record.get("sequence"),
            record.get("origin_domain") or "-", record.get("signer"))
    else:
        app.logger.warning(
            "network directive accepted: kind=%s sequence=%s domain=%s "
            "effective %s signed by %s",
            record.get("kind"), record.get("sequence"),
            record.get("origin_domain") or "-", record.get("not_before"),
            record.get("signer"))
    return record


# Paths the old domain must keep ANSWERING rather than redirecting.
#
# Each one is here because forwarding it breaks the very thing that makes the
# move survivable:
#
#   * network.json is HOW a node learns the domain changed. Redirecting it means
#     a node can only discover the move by successfully reaching the new domain
#     — so if the new domain is not up yet, or is blocked where that node is,
#     it learns nothing and keeps talking to a host that is going away.
#   * acme-challenge must be answered by whoever is being validated. Forwarding
#     it means the old name can never renew its certificate, so it stops serving
#     HTTPS and stops being able to redirect at all.
#   * health and readiness are asked by things that do not follow redirects, and
#     a 302 reads to them as "not healthy".
NEVER_REDIRECT = (
    "/.well-known/syndichan/network.json",
    "/.well-known/acme-challenge/",
    "/health",
    "/readyz",
    "/healthz",
)


def redirect_target(host, path, query="", scheme="https", now=None):
    """Where a request arriving on the OLD domain should be sent, or None.

    Returns a URL to forward to. The caller is expected to use a TEMPORARY
    redirect: a 301 is cached by browsers effectively forever and by some
    indefinitely, so moving back — the ordinary outcome of a registrar dispute
    being resolved — would leave readers stuck on a name the project no longer
    controls, with no way to reach them and tell them.
    """
    import time

    record = current()
    if not record or record.get("kind") != KIND_MOVE:
        return None
    domain = (record.get("origin_domain") or "").strip().lower()
    if not domain:
        return None
    if int(record.get("not_before") or 0) > int(now if now is not None else time.time()):
        # Verified but not yet effective. Redirecting now would move readers
        # ahead of the nodes, which are still waiting out the same delay.
        return None

    host = (host or "").strip().lower().split(":")[0]
    if not host or host == domain or host.endswith("." + domain):
        return None
    # Never forward to a host that is not the one that was signed for.
    path = path or "/"
    for prefix in NEVER_REDIRECT:
        if path == prefix or path.startswith(prefix):
            return None

    return "%s://%s%s%s" % (scheme, domain, path, ("?" + query) if query else "")


def rehearse(directive):
    """What issuing this directive would actually do, before it is signed.

    The first real use of this feature will be during an incident, by somebody
    under pressure who has never run it before. "Here is what will change" is
    the difference between an operator who can check the move and one who finds
    out afterwards.

    Deliberately reports consequences rather than restating the form. An
    operator can already see they typed a domain; what they cannot see is that
    nodes will wait an hour, or that nothing will happen at all because the
    network is frozen.
    """
    import time

    effects = []
    warnings = []
    now = int(time.time())
    kind = directive.get("kind")
    existing = current()

    if frozen() and kind != KIND_RESUME:
        warnings.append(
            "The network is FROZEN. Nodes will refuse this until a resume "
            "directive is issued, so nothing would change.")

    if kind == KIND_MOVE:
        domain = directive.get("origin_domain") or ""
        effects.append("Nodes adopt %s as the origin and restart against it."
                       % domain)
        effects.append("Requests arriving on any other domain are forwarded "
                       "here with a temporary redirect.")
        if directive.get("origin_key"):
            effects.append(
                "Readers re-pin to the new signing key. Content signed by the "
                "OLD key stops verifying, so anything not re-signed will be "
                "rejected by clients that have seen this directive.")
        if directive.get("origin_address"):
            effects.append("Gateways pin the origin to %s rather than resolving it."
                           % directive["origin_address"])
        if not _resolves(domain):
            warnings.append(
                "%s does not resolve from this server. That may be fine if DNS "
                "has not propagated yet — but if it is a typo, nodes will "
                "adopt it, restart, and be unable to reach anything." % domain)
    elif kind == KIND_FREEZE:
        effects.append("Nodes refuse every further directive until a resume is "
                       "issued at a higher sequence.")
        effects.append("Nothing about the current domain or origin changes.")
    elif kind == KIND_RESUME:
        effects.append("The freeze lifts. Nodes accept directives again.")

    delay = int(directive.get("not_before") or 0) - now
    if directive.get("emergency"):
        warnings.append(
            "EMERGENCY: this takes effect the moment a node sees it, with no "
            "delay. The delay is the window in which a directive you did not "
            "issue can be frozen — this gives that up in exchange for speed.")
    elif delay > 0:
        effects.append("Nodes will not act for another %d minutes (%s)."
                       % (delay // 60, "the window to freeze this if it is wrong"))

    if not existing:
        warnings.append(
            "No directive has been issued before, so nodes installed until now "
            "have nothing pinned. Only nodes whose config carries this wallet "
            "will follow it.")

    return {"effects": effects, "warnings": warnings,
            "sequence": directive.get("sequence"),
            "replaces": (existing or {}).get("sequence")}


def _resolves(domain):
    """Whether a name resolves from here. Best effort — False is not proof."""
    import socket

    if not domain:
        return False
    try:
        socket.getaddrinfo(domain, None)
        return True
    except Exception:
        return False


# Where the directive is written in the object store, under a FIXED name.
#
# Everything else the snapshot system stores is addressed by its hash, which is
# right for immutable content and useless here: a node looking for "the current
# directive" does not know its hash, and if it did it would already know the
# contents. So this one object has a stable name and mutable contents.
#
# That is only safe because the name is not the authority. Anything could write
# to this key; only a document signed by the pinned wallet verifies, and only
# one with a higher sequence is adopted. The bytes being mutable costs nothing
# when the signature is what is trusted.
DHT_BUCKET = "directives"
DHT_CURRENT_KEY = "current"


def publish_to_dht():
    """Put the directive where a node can read it without reaching the origin.

    A node with storage already talks to its own local S3 endpoint, which is
    backed by the DHT — so this is the one publication path that does not
    require the origin to be up, its domain to resolve, or its certificate to
    be valid. All three of those are things a directive may be announcing the
    loss of.

    Returns True on success. Never raises: publishing a directive to the
    well-known URL has already succeeded by the time this runs, and failing
    that write should not fail the whole issuance.
    """
    import json as _json

    record = current()
    if not record:
        return False
    try:
        from services.snapshot_dht import _client

        client = _client()
        prefix = app.config.get("S3_UUID_PREFIX") or ""
        bucket = "%s%s" % (prefix, DHT_BUCKET)
        try:
            client.head_bucket(Bucket=bucket)
        except Exception:
            client.create_bucket(Bucket=bucket)

        body = _json.dumps(public_document(), sort_keys=True).encode("utf-8")
        client.put_object(Bucket=bucket, Key=DHT_CURRENT_KEY, Body=body,
                          ContentType="application/json")
        # Read back before reporting success. A directive announced as
        # published but not retrievable sends nodes to look somewhere it is
        # not, during the outage it was meant to carry them through.
        fetched = client.get_object(Bucket=bucket,
                                    Key=DHT_CURRENT_KEY)["Body"].read()
        if fetched != body:
            app.logger.error("directive: the object store did not return what "
                             "was written to %s/%s", bucket, DHT_CURRENT_KEY)
            return False
        app.logger.warning("directive: sequence %s published to %s/%s",
                           record.get("sequence"), bucket, DHT_CURRENT_KEY)
        return True
    except Exception:
        app.logger.exception("directive: could not publish to the object store")
        return False


def public_document():
    """What is served at /.well-known/syndichan/network.json.

    Carries the canonical text alongside the fields. A verifier that rebuilds
    the message from the fields and one that signs the text it was given must
    agree — publishing both means a mismatch is detectable rather than a silent
    verification failure on somebody else's machine.
    """
    record = current()
    if not record:
        return {
            "directive": None,
            "wallet": admin_wallet(),
            "note": "No directive has been issued. The network is operating "
                    "under its configured domain.",
        }
    directive = {field: record.get(field) for field in SIGNED_FIELDS}
    directive["sequence"] = int(directive.get("sequence") or 0)
    return {
        "directive": directive,
        "canonical": canonical(directive),
        "signature": record.get("signature"),
        "signer": record.get("signer"),
        "wallet": admin_wallet(),
        "note": "Verify the signature over `canonical` against a wallet address "
                "pinned in your own configuration. Do NOT trust the `wallet` "
                "field here to tell you who is allowed to sign — it is served "
                "by the same host that served the directive.",
    }
