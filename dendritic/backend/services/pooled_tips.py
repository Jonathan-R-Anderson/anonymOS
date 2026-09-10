"""Pooled tipping — roadmap P15, the web-facing half.

WHAT THIS SERVER DOES AND DOES NOT HOLD
---------------------------------------
Nothing. There is no pool balance here, no channel list, no per-tip row, no
contributor table and no key to sign with. The pool is a DERIVED VIEW that lives
in the recipient's own node (storage-client/internal/channel/pool.go), computed
from co-signed bilateral channel states. This module answers two questions:

    "may this author be shown a Tip button?"      availability()
    "what does the browser need to pay them?"     quote()

and stores the answer to neither.

That is the same shape P9's channel awards already use, and it is reused rather
than reinvented: the browser talks to the recipient's node, the node co-signs a
state, and the money moves between two parties who both signed for it. This
server is a directory, not a party.

FAIL CLOSED
-----------
Every condition below must hold before a Tip button appears. A button that
promises a payment path which does not exist is worse than no button: the visitor
clicks, nothing works, and the failure looks like the recipient's fault.

    profile exists and is public
    the owner switched pooling ON            (off by default)
    the owner has a wallet
    the owner published a channel endpoint   (https only)
    a deployment is configured
    the viewer has a wallet
    the viewer is not the author

WHAT IS DELIBERATELY NOT HERE
-----------------------------
No aggregate, no eligible-channel list, no "you have N AXON waiting". Those are
computed by Pool.View in the OWNER'S node from THEIR channels, and the owner's
browser asks their own node directly. Routing it through this server would make
the platform exactly the metadata chokepoint P15 forbids — it would learn every
recipient's balance and every channel they hold.
"""

import time

from services.channel_awards import deployment
from services.channel_state import normalize_address

# A ceiling on a single tip. Not a policy about wealth — a guard so a fat-fingered
# or scripted amount cannot be presented for authorisation as if it were normal.
MAX_TIP = 10 ** 6

# AXON has 18 decimals, and a user types WHOLE AXON.
#
# The same convention services/channel_awards.py already uses
# (`amount_wei = credits * (10 ** 18)`): the number a person enters is whole
# coins, and the server converts once, here, before anything signs it.
#
# It was missing on this path. A browser tip of "5" produced a state moving 5
# BASE UNITS — 0.000000000000000005 AXON — while the dialog said "Send 5 to
# Tips". Found by reading the frame a real browser had queued.
ANON_DECIMALS = 18

# FRACTIONS OF A COIN ARE ALLOWED; FLOATS ARE NOT.
#
# The conversion above used int(), which made 0.1 into 0 and refused it as "the
# amount must be greater than zero" — so the smallest tip anybody could send was
# one whole AXON. For a tip that is the wrong floor: the point of a payment
# channel is that sending a little costs nothing, and a minimum of one coin
# undoes that.
#
# Decimal, not float, all the way to base units. 0.1 has no exact binary
# representation, so float(0.1) * 10**18 is 100000000000000001 rather than
# 10**17 — an amount that is not the one displayed, inside a state somebody is
# about to sign. Decimal("0.1") scales exactly.
#
# The int() it replaces was the fix for the base-unit bug in the comment above,
# and that fix is kept: the number a person types is still WHOLE COINS, still
# converted once, still here.
MIN_TIP_BASE = 1  # one base unit: the smallest thing the token can express


def parse_tip_amount(value):
    """Whole AXON as typed → (Decimal for display, int base units for signing).

    Raises PooledTipError with a message written to be shown to the visitor.
    """
    from decimal import Decimal, InvalidOperation

    if value is None:
        raise PooledTipError("Choose an amount.")
    # str() first: a float that reached here would already have lost the value,
    # and Decimal(0.1) faithfully reproduces the float's error rather than the
    # number the user typed.
    try:
        amount = Decimal(str(value).strip())
    except (InvalidOperation, ValueError, TypeError, ArithmeticError):
        raise PooledTipError("That is not a valid amount.")
    if not amount.is_finite():
        raise PooledTipError("That is not a valid amount.")

    scaled = amount * (10 ** ANON_DECIMALS)
    if scaled != scaled.to_integral_value():
        raise PooledTipError(
            "That amount is smaller than the token can express.")
    base = int(scaled)
    if base < MIN_TIP_BASE:
        raise PooledTipError("The amount must be greater than zero.")
    if amount > MAX_TIP:
        raise PooledTipError("That amount is too large for a tip.")
    return amount, base


def format_tip_amount(amount):
    """A Decimal as a person reads it: no exponent, no trailing zeros."""
    text = format(amount.normalize(), "f")
    return text


class PooledTipError(Exception):
    """A tip could not be quoted. The message is safe to show a visitor."""


def _profile_of(slip):
    """The public profile of a slip, or None."""
    if slip is None:
        return None
    profile = getattr(slip, "profile", None)
    if profile is None:
        return None
    if not getattr(profile, "is_public", False):
        return None
    return profile


def _endpoint_of(profile):
    """The owner's node URL, or None.

    https only. A tip flow that could be pointed at http:// would let a network
    attacker rewrite the state the browser is about to sign against — the same
    reason the award path refuses it.
    """
    endpoint = (getattr(profile, "channel_endpoint", "") or "").strip()
    if not endpoint or not endpoint.startswith("https://"):
        return None
    return endpoint


def _wallet_of(slip):
    """The slip's linked wallet, normalised, or None."""
    from services.post_awards import wallet_for_slip

    return normalize_address(wallet_for_slip(slip) or "") or None


def pool_label(profile):
    """What to call this pool in the UI. Never None once pooling is on."""
    name = (getattr(profile, "pool_name", "") or "").strip()
    return name or "Tips"


# The two ways a creator's tipping can be serviced. Kept apart in the data as
# well as in the UI, because the difference is the whole security question and a
# single "enabled" flag would erase it.
SIGNING_MAILBOX = "mailbox"
SIGNING_DELEGATE = "delegate"
SIGNING_MODES = (SIGNING_MAILBOX, SIGNING_DELEGATE)


def signing_mode(profile):
    """How this creator's tips are signed. Defaults to the SAFER mode.

    An unset or unrecognised value reads as mailbox, never as delegate: a
    creator who has not chosen must not be presented as having handed a
    volunteer signing authority they never granted.
    """
    mode = (getattr(profile, "pool_signing_mode", "") or "").strip().lower()
    return mode if mode in SIGNING_MODES else SIGNING_MAILBOX


def volunteer_of(profile):
    """The node id servicing this creator, or None."""
    return (getattr(profile, "pool_volunteer", "") or "").strip() or None


def volunteer_endpoint_of(profile):
    """Where that volunteer's mailbox is, or None.

    DERIVED FROM THE PROFILE, never from a request. A caller that could name the
    volunteer could name its own, and a contributor's signed proposal would be
    handed to a stranger — who could not spend it, but could withhold it and
    make a tip look lost.

    https only, for the same reason channel_endpoint is: a mailbox reachable
    over plain http could be substituted by anyone on the path.
    """
    endpoint = (getattr(profile, "pool_volunteer_endpoint", "") or "").strip()
    if not endpoint or not endpoint.startswith("https://"):
        return None
    return endpoint


def accepts_pooled_tips(author_slip):
    """Whether this author has a working pooled-tipping configuration.

    RECIPIENT-SIDE ONLY. It says nothing about whether a particular visitor can
    pay — availability() answers that, and is what a Tip button must consult.
    Split so the profile page can honestly say "pooled tipping is on" to a
    logged-out visitor without implying they personally can send one.
    """
    profile = _profile_of(author_slip)
    if profile is None:
        return False
    if not getattr(profile, "pool_enabled", False):
        return False
    if not _wallet_of(author_slip):
        return False
    if not _endpoint_of(profile):
        return False
    if deployment() is None:
        return False
    # A volunteer must have been chosen. Without one there is nowhere for a
    # tipper's frame to go, and a Tip button that appears anyway is the
    # "promises a payment path which does not exist" failure this module was
    # written to avoid.
    if not volunteer_of(profile):
        return False
    # A named volunteer with no reachable mailbox is not a working
    # configuration. Refused rather than half-offered: the Tip button would
    # appear, the recipient's node would be unreachable, and the fallback would
    # have nowhere to go.
    if not volunteer_endpoint_of(profile):
        return False
    return True


def availability(author_slip, viewer_slip):
    """Can `viewer_slip` send a pooled tip to `author_slip` right now?

    Returns a dict the template can render, or None. None is the default: every
    branch that cannot prove the path exists returns it.
    """
    if not accepts_pooled_tips(author_slip):
        return None

    author_wallet = _wallet_of(author_slip)
    viewer_wallet = _wallet_of(viewer_slip)
    if not viewer_wallet:
        # The visitor has no wallet, so there is nobody for the recipient's node
        # to open a channel with. The button explains this rather than failing
        # after the click.
        return None
    if viewer_wallet == author_wallet:
        return None

    profile = _profile_of(author_slip)
    return {
        "label": pool_label(profile),
        "recipient_slug": profile.slug,
        # The wallet is public information — it is on chain — and the browser
        # needs it to derive the channel. Nothing else about the recipient's
        # channels, balances or history is exposed here.
        "recipient": author_wallet,
    }


def tip_for(author_slip):
    """availability() with the viewer taken from the current session.

    THE ONE ENTRY POINT EVERY SURFACE USES. Profile, forum post, article,
    byline and stream all call this and nothing else, so the eligibility rule
    is decided in a single place. Five surfaces each deciding for themselves
    would be four chances to render a button that cannot pay.

    Never raises. A template that blew up mid-render because a tip could not be
    evaluated would take down a page whose actual job is showing a post, so
    every failure returns None — which the macro renders as nothing.
    """
    try:
        from model.Slip import get_slip

        return availability(author_slip, get_slip())
    except Exception:
        return None


QUOTE_TTL_SECONDS = 120


def quote(author_slip, viewer_slip, amount=None, now=None):
    """What the browser needs to pay this author over a channel.

    The same shape channel_awards.channel_quote returns, because it is the same
    payment machinery. There is no pooled-payment protocol: a pooled tip is an
    ordinary bilateral channel payment, and the "pool" is only how the recipient
    later aggregates what arrived.

    Raises PooledTipError with a message safe to show the visitor.
    """
    if not accepts_pooled_tips(author_slip):
        raise PooledTipError("This user is not accepting pooled tips.")

    author_wallet = _wallet_of(author_slip)
    viewer_wallet = _wallet_of(viewer_slip)
    if not viewer_wallet:
        raise PooledTipError("Link a wallet to your account before sending a tip.")
    if viewer_wallet == author_wallet:
        raise PooledTipError("You cannot tip yourself.")

    config = deployment()
    if config is None:
        raise PooledTipError("Channel payments are not configured on this site.")
    chain_id, manager = config

    profile = _profile_of(author_slip)
    endpoint = _endpoint_of(profile)
    if not endpoint:
        raise PooledTipError("This user has not published a payment node.")
    volunteer_endpoint = volunteer_endpoint_of(profile)
    if not volunteer_endpoint:
        # FAIL CLOSED. Never substitute the recipient's own endpoint here: that
        # is precisely the confusion this field exists to end.
        raise PooledTipError("This user's tip mailbox is not configured.")

    amount, amount_base = parse_tip_amount(amount)

    issued = int(now if now is not None else time.time())

    # NO CHANNEL ID, NO PARTY ORDER, NO NONCE, NO ROUTE.
    #
    # The browser derives the channel itself from its own wallet address and the
    # recipient's (tip-channel.js deriveChannelId), so a channel identifier here
    # would be at best redundant and at worst an instruction — a quote that named
    # a channel could point the wallet at one somebody else had prepared.
    #
    # A quote is NOT authorization and moves no money. It is the description the
    # user reads before deciding.
    return {
        "recipient": author_wallet,
        "label": pool_label(profile),
        # WHOLE AXON, for a person to read. A STRING, now that fractions are
        # allowed: JSON numbers are doubles, and 0.1 does not survive one
        # intact. The display and the signed amount must agree exactly or the
        # dialog is describing a different payment from the one being authorised.
        "amount": format_tip_amount(amount),
        # No fee is charged by this site. Stated rather than omitted so the
        # total is unambiguous at the point of authorisation.
        "fee": 0,
        "total": format_tip_amount(amount),
        # BASE UNITS, for the protocol. Two fields rather than one so that
        # neither the display nor the signed state has to guess which it is
        # holding — the bug this replaces was exactly that guess going wrong.
        # A string, because 10**18 exceeds what JSON's number type carries
        # exactly and a rounded amount is a rounded payment.
        "amount_base": str(amount_base),
        # The RECIPIENT'S node — where state is requested and payment proposed.
        "endpoint": endpoint,
        # The VOLUNTEER'S mailbox — where a frame is left when the above does
        # not answer. Deliberately a second field: one value serving both roles
        # is what made a real browser run end UNKNOWN instead of queued.
        "volunteer_endpoint": volunteer_endpoint,
        # The volunteer's node id. Half of every mailbox challenge, so without
        # it a contributor cannot ask what they have already had accepted and
        # every repeat tip would rebuild from the chain — reusing the previous
        # tip's update number.
        "volunteer_node_id": volunteer_of(profile),
        "manager": manager,
        "chain_id": chain_id,
        "issued_at": issued,
        "expires_at": issued + QUOTE_TTL_SECONDS,
    }


def quote_is_fresh(quoted, now=None):
    """Whether a quote may still be acted on.

    An expired quote must be re-requested rather than reused: the recipient may
    have switched pooling off, unlinked their wallet or changed node in between.
    """
    try:
        expires = int(quoted.get("expires_at", 0))
    except (AttributeError, TypeError, ValueError):
        return False
    return int(now if now is not None else time.time()) < expires
