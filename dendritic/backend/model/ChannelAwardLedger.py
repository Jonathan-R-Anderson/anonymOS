"""How much of a channel's inflow has already been spent on awards — P9-c.

One row per channel, holding a number that only ever goes up.

WHY THIS TABLE EXISTS
---------------------
On chain, an award is keyed to the transaction that paid for it, and a
transaction cannot be spent twice. Off chain there is no transaction, and the
obvious substitute — key it to the state's nonce — has a hole that only opens
once payments are free.

Two parties can pass the same ten AXON back and forth forever. Each pass is a
new nonce, so each would buy another award, and the whole thing costs nothing
because that is the point of a channel. On chain the same trick exists but gas
makes it pointless.

So awards are credited against the most the author has ever been ahead, and this
row remembers how much of that has been claimed. Sending value back lowers what
the author has received, so re-sending it credits nothing: the mark is already
above it.

WHY THE AMOUNT IS A STRING
--------------------------
Wei. 100 AXON is 1e20, which overflows a signed 64-bit integer at around 9.2e18
— so a BigInteger column would take a few gold awards to break. Stored as a
decimal string and converted with int(), which in Python is unbounded.
"""

import datetime as _datetime

from shared import db


class ChannelAwardLedger(db.Model):
    """The high-water mark for one channel."""

    __tablename__ = "channel_award_ledger"

    id = db.Column(db.Integer, primary_key=True)
    # The channel id, 32 bytes of lowercase hex with no 0x. Derived from the two
    # wallets rather than supplied, so it cannot be aimed at somebody else's row.
    channel_id = db.Column(db.String(64), nullable=False, unique=True, index=True)
    # Denormalised for a human reading the table. Not used for any decision: the
    # channel id already fixes both parties.
    recipient_wallet = db.Column(db.String(42), nullable=False, default="")
    # Total wei of this channel's inflow already spent on awards. Only rises.
    awarded_wei = db.Column(db.String(80), nullable=False, default="0")
    updated_at = db.Column(db.DateTime, nullable=False,
                           default=_datetime.datetime.utcnow)
