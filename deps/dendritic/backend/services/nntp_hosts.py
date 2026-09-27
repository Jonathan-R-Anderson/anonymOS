"""What may be written in an NNTP peer's host field.

Kept free of the app so it can be tested on its own: this decides whether a peer
is reached anonymously or not, which is the single most consequential thing
about a peer row, and a validator you cannot exercise without a database is one
nobody exercises.
"""

import ipaddress
import re

from services.i2p_addresses import normalize_i2p_host

# A DNS hostname: labels of letters, digits and hyphens, not starting or ending
# with a hyphen. Deliberately strict — a peer host goes straight into a socket
# connect, and "reject what does not look like a hostname" is a cheaper habit
# than reasoning about what a resolver will do with something strange.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$"
)

TRANSPORT_I2P = "i2p"
TRANSPORT_CLEARNET = "clearnet"


def normalize_peer_host(host):
    """Accept an I2P destination or an ordinary host, and say which it is.

    I2P first, and unchanged: a .b32.i2p peer is reached through the SOCKS proxy
    and never reveals this server's address. Clearnet peers are allowed because
    the alternative was a federation feature that could not run at all — but
    they are a different bargain, and the caller is told which one it just made
    so the operator can be told too.
    """
    raw = str(host or "").strip().lower().rstrip(".")
    if not raw:
        raise ValueError("Enter a peer host.")
    if raw.endswith(".i2p"):
        # Anything ending .i2p is meant to be I2P, so a malformed one is a typo
        # to report rather than a hostname to resolve on the open internet.
        return normalize_i2p_host(raw), TRANSPORT_I2P
    try:
        ipaddress.ip_address(raw)
        return raw, TRANSPORT_CLEARNET
    except ValueError:
        pass
    if not _HOSTNAME_RE.match(raw):
        raise ValueError(
            "Peer host must be a .b32.i2p destination, a hostname, or an IP address.")
    return raw, TRANSPORT_CLEARNET


