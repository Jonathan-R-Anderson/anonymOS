"""The two hashes Treasury.releaseOrder wants, computed once, at purchase time.

    orderId    = keccak256(stripe session id)
    originHash = keccak256(pepper || client ip)

Both are written to the CreditPurchase row when the checkout is created, so
whoever later delivers the tokens on chain passes stored values rather than
recomputing them from data that may no longer be available.

WHY THE IP IS CAPTURED AT CHECKOUT AND NOT AT THE WEBHOOK
----------------------------------------------------------
This is the part that is easy to get wrong and invisible when you do.

The webhook is the obvious place — it is where the payment is confirmed. But a
webhook is an HTTP request from STRIPE's servers, so `request.remote_addr` there
is Stripe's address, not the buyer's. Recording it would fill the chain with a
handful of hashes of Stripe's egress IPs, look completely plausible, and be
worthless: every purchase would appear to originate from the same few places.

The buyer's own browser is present exactly once, when it POSTs to create the
checkout session. That is the only moment the address is knowable, so that is
where it is taken.

WHY A PEPPER, AND WHAT IT COSTS
--------------------------------
IPv4 is 2^32 addresses. An unsalted keccak of one is reversible by brute force
in an afternoon, so an unpeppered hash on a public chain is the address itself
with extra steps.

The pepper is a server-side secret. Two consequences, both deliberate:

  * Only this operator can compute a lookup. Nobody reading the chain can turn
    a topic back into an address, and nobody else can search by one either.
  * Rotating the pepper makes older purchases unsearchable by origin. Their
    hashes stay valid as identifiers, they just no longer match anything you
    can compute. Treat it like a signing key.

Unset, origins are simply not recorded. That is the correct default: a hash
under an empty pepper is an unsalted hash, which is the thing this exists to
avoid, and silently degrading to it would be worse than recording nothing.
"""

import os

from services.keccak import keccak256
from shared import app

# Matches the contract's own zero check: a zero hash means "not recorded", and
# Treasury.releaseOrder skips the origin event entirely when it sees one.
ZERO = "0x" + "00" * 32


def pepper():
    """The secret salt, read from the environment first.

    os.environ before app.config, deliberately. The value arrives in the .env
    file, which shared.py loads into os.environ at import — but app.config is
    populated from a SEPARATE config file that is mounted into the container
    from the cluster and is not the copy in this repo. Adding the key to
    deploy-configs/maniwani.cfg therefore did nothing: the container reads
    /maniwani/runtime-config.cfg, which has no such line, so app.config
    returned "" while the value sat in os.environ the whole time.

    That failure is silent in the worst way. An empty pepper means origins are
    recorded as zero, the site stays green, and nothing is written down that
    would ever be noticed — so the value is read from the place it actually
    lands, and app.config is kept only as a fallback for a deployment that
    prefers to set it there.
    """
    return ((os.environ.get("PURCHASE_ORIGIN_PEPPER") or "").strip()
            or (app.config.get("PURCHASE_ORIGIN_PEPPER") or "").strip())


def order_id(session_id):
    """keccak256 of the Stripe session id.

    Hashed rather than stored raw because the chain is public and permanent: a
    session id there would tie a wallet to a payment for anyone to read, forever.
    It filters exactly as well hashed — an indexed topic matches by equality
    either way — so nothing is lost.
    """
    session_id = (session_id or "").strip()
    if not session_id:
        return ZERO
    return "0x" + keccak256(session_id.encode("utf-8")).hex()


def origin_hash(ip):
    """keccak256(pepper || ip), or ZERO when there is no pepper or no address.

    Returning ZERO rather than an unpeppered hash is the whole point of the
    check: the contract treats zero as "not recorded" and emits no origin event,
    which is a truthful absence. A hash computed under an empty pepper would be
    a reversible one, published permanently, and indistinguishable from a real
    one after the fact.
    """
    ip = (ip or "").strip()
    secret = pepper()
    if not ip or not secret:
        return ZERO
    return "0x" + keccak256(secret.encode("utf-8") + ip.encode("utf-8")).hex()


def client_ip():
    """The buyer's address, from the first hop of X-Forwarded-For.

    Behind the site's proxy, remote_addr is the proxy. threat_watch already
    takes the first hop and is the one place that knows how this deployment is
    fronted, so it is reused rather than reimplemented — two answers to "who is
    this request from" is one more than a system can afford.
    """
    try:
        from services.threat_watch import _client_address

        return _client_address() or ""
    except Exception:
        return ""


def for_purchase(session_id, ip=None):
    """Both hashes for a purchase being created.

    Call at checkout, while the buyer's browser is the thing talking to us.
    """
    return {
        "order_id": order_id(session_id),
        "origin_hash": origin_hash(client_ip() if ip is None else ip),
    }
