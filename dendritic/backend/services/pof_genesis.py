"""The genesis epoch seed.

Witness selection is seeded from `EpochManager.randomnessOf(epoch)`, which only
exists once an epoch has been submitted. The first epoch therefore has nothing
to draw from — a bootstrapping gap that has to be filled by exactly one
externally-supplied seed.

Why the server mints it rather than a node or the aggregator: whoever chooses
the seed chooses the witness draw. A provider that picked it could keep drawing
until the selected witnesses were its own friends. The seed must come from a
party with no receipt in the epoch, be fixed before any work is challenged, and
be public so anyone can re-derive the same witness sets afterwards. Published
randomness is the design — `randomnessOf` is a public view.

The seed is generated once and never rotated: rotating it would silently change
the witness sets for work already performed, invalidating honest receipts.
"""

import datetime
import json
import secrets

from model.SiteSetting import get_setting, set_setting
from shared import db

GENESIS_SETTING = "pof_genesis_seed"

# One hour, matching the roadmap and the Go client's DefaultEpochSeconds. Long
# enough that settlement gas is amortised over real work, short enough that an
# operator sees earnings the same day.
EPOCH_SECONDS = 3600


def _now_iso():
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def get_genesis(create=False):
    """Return the genesis record, minting it on first request if `create`.

    Reads never mint by default, so a stray GET cannot fix the seed before an
    operator intends to.
    """
    raw = get_setting(GENESIS_SETTING, "") or ""
    if raw:
        try:
            record = json.loads(raw)
            if isinstance(record, dict) and record.get("seed"):
                return record
        except ValueError:
            pass
    if not create:
        return None
    record = {
        "seed": "0x" + secrets.token_hex(32),  # 32 bytes — a bytes32 on-chain
        "epoch": 0,
        "created_at": _now_iso(),
        "submitted_tx": None,
        "submitted_at": None,
    }
    set_setting(GENESIS_SETTING, json.dumps(record))
    db.session.commit()
    return record


def mark_submitted(tx_hash):
    """Record that the genesis epoch was posted on-chain.

    Advisory only: the chain is the authority on whether epoch 0 exists, and the
    UI checks it there. This exists so the admin page can show the transaction
    without re-scanning, and so a second submission attempt is visibly a repeat.
    """
    record = get_genesis(create=False)
    if record is None:
        return None
    record["submitted_tx"] = tx_hash
    record["submitted_at"] = _now_iso()
    set_setting(GENESIS_SETTING, json.dumps(record))
    db.session.commit()
    return record


def _parse_iso(value):
    """Parse the ISO timestamps this module writes. None when unparseable."""
    if not value:
        return None
    text = str(value)
    if text.endswith("Z"):
        text = text[:-1]
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def genesis_anchor_unix(record):
    """When epoch `record["epoch"]` began, as unix seconds.

    Anchored on the on-chain submission rather than on when the seed was armed:
    submission is the moment the epoch became a public fact anyone can verify
    against EpochManager, whereas arming happened privately on this server.
    Falls back to the arming time so a node can still count while genesis is in
    flight, and to None when neither timestamp parses — a caller that cannot
    place the anchor must wait rather than guess, since guessing puts every node
    on a different epoch.
    """
    if not record:
        return None
    stamp = _parse_iso(record.get("submitted_at")) or _parse_iso(record.get("created_at"))
    if stamp is None:
        return None
    return int(stamp.replace(tzinfo=datetime.timezone.utc).timestamp())


def current_epoch_number(record=None):
    """The epoch number "now" falls in, counted from genesis. None if unarmed."""
    if record is None:
        record = get_genesis(create=False)
    anchor = genesis_anchor_unix(record)
    if anchor is None:
        return None
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if now < anchor:
        return int(record.get("epoch", 0))
    return int(record.get("epoch", 0)) + (now - anchor) // EPOCH_SECONDS


# Randomness derivation lives in services/pof_randomness.py so it can be tested
# with no app around it and checked against the Go implementation.
from services.pof_randomness import derive_epoch_randomness  # noqa: E402  (re-export)


def epoch_randomness(epoch, record=None):
    """(randomness_hex, source) for an epoch, or (None, reason) if unknowable.

    Derived only for epochs at or after genesis. An epoch BEFORE genesis has no
    randomness under any rule, and inventing one would let a node claim work in
    a period the network did not exist.
    """
    if record is None:
        record = get_genesis(create=False)
    if not record:
        return None, "Genesis has not been armed yet."
    genesis_epoch = int(record.get("epoch", 0))
    if int(epoch) < genesis_epoch:
        return None, "Epoch %d is before genesis (epoch %d)." % (epoch, genesis_epoch)
    if int(epoch) == genesis_epoch:
        # The genesis epoch's randomness IS the seed — that is the value that
        # was submitted on-chain, and the derivation has to agree with the
        # record rather than with itself. Returning keccak(seed || 0) here would
        # give a different answer than randomnessOf(0) for the one epoch where
        # the chain already has the answer.
        return record.get("seed"), "the genesis seed itself, as submitted on-chain"
    derived = derive_epoch_randomness(record.get("seed"), epoch)
    if derived is None:
        return None, "The genesis seed is malformed."
    return derived, "derived from the genesis seed: keccak256(seed || uint64_be(epoch))"
