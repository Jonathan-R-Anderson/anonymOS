"""Canary objects: pages nothing links to, so selective honesty gets caught.

A gateway that alters content for readers but serves the truth to anything that
looks like an audit defeats every check built so far. Canaries close that by
removing the gateway's ability to tell the two apart.

WHAT MAKES A CANARY WORK
------------------------
Not secrecy — a gateway sees the URL either way. What matters is that a canary
is INDISTINGUISHABLE from ordinary content while being fetched almost exclusively
by auditors:

  * it is served by the same code path, signed by the same key, and carries the
    same headers as a real page, so nothing about the response marks it;
  * its path looks like an ordinary page rather than /canary/1, because a
    recognisable path is one a gateway can special-case;
  * no template links to it, so organic traffic is close to zero and altering
    it gains an attacker nothing.

The consequence: a gateway altering "everything except audits" must decide, per
request, which it is looking at. It cannot, so it either alters canaries too and
is caught, or alters nothing and is honest.

WHY THE PATHS ARE DERIVED, NOT STORED
-------------------------------------
They come from a keyed hash of the origin signing key, so the set is stable
across restarts and identical on every replica without a table to migrate or
keep in sync — and an operator who rotates the signing key gets a fresh set for
free, which is the right behaviour: after a compromise, the old canaries are
exactly the ones an attacker had time to learn.
"""

import hashlib

# Shapes that look like the rest of the site. A gateway scanning for "canary"
# or a numeric id finds nothing to key on.
_SHAPES = (
    "/thread/%s",
    "/boards/%s",
    "/media/%s",
)

CANARY_COUNT = 6


def _seed():
    """Keyed on the signing key, so canaries follow key rotation.

    Falls back to a fixed seed when no key is reachable. A deployment with no
    signing key publishes no signatures, so its canaries prove nothing anyway —
    the fallback keeps the paths well-formed rather than pretending they are
    secret.
    """
    try:
        from services.content_signing import public_key_b64

        key = public_key_b64()
    except Exception:
        key = None
    # Only a real string is accepted. Canary paths are computed at import time
    # to register routes, so anything unexpected here would raise during startup
    # — and "the site did not boot" is a steep price for a diagnostic feature.
    if not isinstance(key, str) or not key:
        key = "syndichan-unsigned"
    return key.encode("utf-8")


def canary_paths():
    """The current canary set. Stable while the signing key is."""
    seed = _seed()
    paths = []
    for index in range(CANARY_COUNT):
        digest = hashlib.sha256(seed + b"|canary|" + str(index).encode()).hexdigest()
        shape = _SHAPES[index % len(_SHAPES)]
        # Long enough not to collide with a real id, short enough to look like
        # one. A 40-character path would itself be a tell.
        paths.append(shape % digest[:12])
    return paths


def is_canary(path):
    return path in set(canary_paths())


def canary_body(path):
    """Deterministic content for a canary.

    Deterministic because a canary that changed on every fetch could never be
    shown to have been altered: two different responses would be indistinguish-
    able from tampering, and every audit would be inconclusive.
    """
    digest = hashlib.sha256(_seed() + b"|body|" + path.encode("utf-8")).hexdigest()
    return (
        "<!doctype html><html><head><title>syndichan</title></head><body>"
        "<p>This page exists so that a gateway which alters content for readers, "
        "but serves the truth to anything that looks like an audit, is eventually "
        "asked for something it cannot tell apart from a real page.</p>"
        "<p>If you reached it from a link, that link is a mistake, not a secret.</p>"
        "<!-- %s --></body></html>" % digest
    )
