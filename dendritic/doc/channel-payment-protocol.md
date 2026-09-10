# Syndichan channel payment protocol — SCPP/1

**Status: implemented.** `storage-client/internal/channel/{transition,scpp,session}.go`,
tested by two nodes on separate disks exchanging only serialised frames.

Written before the code on purpose: the hard part is not the wire format, it is
what each side does after a crash, and that is far cheaper to get right on paper.
Where the implementation and this document disagree, this document is wrong —
report it rather than adjusting the code to match.

This document is complete when it answers three questions with no room for
interpretation:

1. What exactly goes over the wire?
2. What exactly constitutes a valid state transition?
3. What does each side do after every possible crash or reconnect point?

Everything it describes must work unchanged for all three payment shapes:

```text
direct     Tipper ───────────────────── Recipient
routed     Tipper ─── Hub ───────────── Recipient        one HTLC hash
multi-hop  Tipper ─── Hub A ─── Hub B ─ Recipient        the same hash
```

---

## 1. Invariants

These are not goals. If an implementation violates one, it is wrong.

**I1. The payer signs first. The payee's signature completes the payment.**
A payer's lone signature moves nothing, so signing early costs them nothing. A
payee signs only after full validation, so they risk nothing either. The reverse
order is the dangerous asymmetry: it would let a payee hold a completed state the
payer never agreed to.

**I2. One state machine.** A direct tip and an HTLC hop are the same transition
type carrying different contents. There is no separate HTLC protocol, and no
message that bypasses `Channel.Accept`.

**I3. "Validates" means the complete validation, never "the signatures verify".**
See §4. A strictly higher nonce is safe to adopt *only* under the full check. Two
signatures recovering correctly proves authorship, not legality.

**I4. A node never signs two different states at one nonce.** Not after a crash,
not after a timeout, not to unstick anything. This is what makes a same-nonce
conflict provable misbehaviour rather than an ambiguity.

**I5. Persist before transmitting.** Both sides. A signature that is on the wire
but not on disk is a state the peer can prove and the signer cannot.

**I6. Nothing is modified after the other party signs.** A counter-signature
covers an exact byte sequence. A "corrected" state is a new proposal at a new
nonce, never an edit.

**I7. Fail closed.** On any doubt about which state is authoritative, refuse to
sign. A stalled channel is recoverable; a double-signed one may not be.

---

## 2. What this protocol is not

Out of scope, deliberately, so they are not half-specified here:

- **Transport security and peer identity.** SCPP/1 assumes an authenticated,
  confidential, ordered byte stream already exists between two nodes. What
  provides it is P5's problem.
- **Route discovery.** Choosing a path through hubs is P6. This document defines
  what happens on each hop once a path is known.
- **On-chain submission.** Opening, closing, claiming and settling on chain are
  contract calls, not messages. The protocol only informs a peer that one is
  coming (§9).
- **Fees.** A hub's charge for forwarding is an economic decision (roadmap D3),
  not a protocol one. When it exists it will appear as a difference between the
  incoming and outgoing lock amounts, which this protocol already expresses.

---

## 3. What goes over the wire

### 3.1 Framing and encoding

Messages are JSON objects, one per frame, length-prefixed with a 4-byte
big-endian unsigned byte count. A frame larger than 1 MiB is refused without
parsing — a channel state is small, and an unbounded read is an easy denial of
service.

**Carriers.** The framing above is the TCP carrier. A browser cannot open a
socket, so there is a second one: `POST /scpp/v1`, one envelope in the request
body and one in the response, with 204 for "nothing to say" and a non-2xx status
alongside an `ERROR` envelope when a frame cannot be processed at all. The
length prefix is redundant there — HTTP already delimits — but the 1 MiB bound
still applies.

Both carriers dispatch to the same handler. This is a transport difference and
nothing more: same envelopes, same message types, same reject codes, same
validation. A browser-specific *protocol* would be a second place for the state
machine to be subtly different, and money would find the difference.

Neither carrier is authenticated. What authorises a message is the signature
inside it, so a bearer token would add nothing and would wrongly imply that
possession of it conferred authority over a channel. The HTTP carrier permits
any origin and no credentials — the pairing that turns a public endpoint into a
confused deputy is *any origin plus credentials*, and browsers refuse that
combination anyway.

**Canonical encoding rules.** These match `store.go`'s on-disk form exactly, so a
state can move between wire and disk without reinterpretation:

| Kind | Encoding |
|---|---|
| Amounts (wei) | Decimal **string**. Never a JSON number: 100 ANON is 1e20, past `Number.MAX_SAFE_INTEGER`, and this is the same JSON a browser will eventually read |
| 32-byte values | Lowercase hex, **no** `0x` prefix |
| Addresses | Lowercase hex **with** `0x`, 20 bytes |
| Signatures | Lowercase hex, no prefix, exactly 65 bytes: `r ‖ s ‖ v` |
| Nonces, expiries | JSON numbers. Both fit in a double without loss |
| Absent lock set | Omitted or `[]`. Both mean the zero root |

Locks appear **sorted by `id`, ascending, with no duplicates** — the same
canonical order `ChannelManagerV2.htlcRoot` requires and `State.HTLCRoot`
produces. A receiver MUST reject an unsorted or duplicated set rather than
sorting it, because one lock set must have exactly one encoding.

### 3.2 Envelope

```json
{
  "v": 1,
  "type": "STATE_PROPOSE",
  "channel": "<32-byte hex>",
  "body": { }
}
```

`v` is the protocol version. A receiver that does not implement `v` replies
`ERROR` and closes; it does not guess.

### 3.3 Message types

| Type | Sent by | Purpose |
|---|---|---|
| `HELLO` | either | Version and the sender's channel-signing address |
| `CHANNEL_ANNOUNCE` | either | "I have an on-chain channel with you" — id, parties, deposits, contract, chain |
| `STATE_PROPOSE` | payer | A complete next state, plus the payer's signature and the transition that produced it |
| `STATE_ACCEPT` | payee | The counter-signature over the identical state |
| `STATE_REJECT` | payee | Refusal, with the rule that failed |
| `STATE_REQUEST` | either | "What is your latest fully signed state for this channel?" |
| `STATE_RESPONSE` | either | That state, or "none" |
| `CONFLICT` | either | Evidence of two different states at one nonce |
| `CLOSING` | either | "I am submitting state N on chain" — informational |
| `ERROR` | either | Malformed frame, unknown version, unknown channel |

**There is deliberately no `HTLC_PROPOSE`, `HTLC_CLAIM` or `HTLC_EXPIRE`.**
Adding, settling and refunding a lock are all state transitions and all travel as
`STATE_PROPOSE`. A separate message family would be a second state machine, which
is exactly what invariant I2 forbids. The *kind* of transition is named inside
the proposal so the payee can check the state against the intent rather than
inferring it.

### 3.4 `STATE_PROPOSE` body

```json
{
  "intent": "<32-byte hex>",
  "transition": { "kind": "PAY", "amount": "25000000000000000000" },
  "state": {
    "channel":   "<32-byte hex>",
    "nonce":     11,
    "balance_a": "475000000000000000000",
    "balance_b": "25000000000000000000",
    "pending":   []
  },
  "sig": "<65-byte hex>"
}
```

The `state` object is complete. The payee never reconstructs a state from a
delta, because a delta applied to a different base produces a different state
that both parties would then sign believing it was the same payment.

`withdraw_a` and `withdraw_b` are part of the state and appear when non-zero,
which is only for a `CHECKPOINT`. They are inside the signed digest, so a state
that travelled without them would be a *different* state carrying a signature
that no longer covers it — and every check downstream would then do the right
thing with the wrong data. They are omitted when zero so that an ordinary
payment, which is every payment before the first checkpoint, encodes exactly as
it always did.

`transition.kind` is one of:

| Kind | Meaning | Effect on the state |
|---|---|---|
| `PAY` | An ordinary tip | Moves `amount` from payer's balance to payee's |
| `LOCK_ADD` | Offer a conditional payment | Adds a lock; removes `amount` from the payer's balance into neither |
| `LOCK_SETTLE` | The preimage is known | Removes the lock; adds `amount` to the payee's balance |
| `LOCK_REFUND` | The lock expired | Removes the lock; returns `amount` to the payer's balance |
| `CLOSE` | Final state for a cooperative close | Same as `PAY` with amount zero, and asserts no locks remain |

`LOCK_ADD` carries the lock's `id`, `hash`, `amount` and `expiry`.
`LOCK_SETTLE` carries the lock `id` and the `preimage`.
`LOCK_REFUND` carries the lock `id`.

---

## 4. What makes a state transition valid

A receiver runs **all** of these, in this order, and stops at the first failure.
Cheap checks first, so an expensive signature recovery is never spent on a state
that was already doomed.

### 4.1 The state itself

Already implemented as `Channel.Accept` in `state.go`, and this protocol adds no
second opinion:

1. **Channel identity.** `state.channel` equals this channel's id. A valid
   signature over another channel's state is still a valid signature.
2. **Nonce.** Strictly greater than the stored nonce. Equal is refused as firmly
   as lower — two different states at one nonce is what a double spend looks
   like.
3. **No negative amounts.** In either balance or any lock.
4. **Lock structure.** Sorted by id, no duplicates, every amount positive, every
   expiry set (non-zero).

   **Note what is deliberately absent: whether an expiry is in the *future*.**
   State validation is a pure function and must stay one. If it consulted a
   clock, two nodes with a few seconds of skew would disagree about whether the
   same signed state is valid, and a state that validated when signed could stop
   validating while sitting on disk — which would turn `store.go`'s load-time
   check into a time bomb. Freshness is a **policy** question, answered at the
   protocol layer (§4.2) where a clock and a skew tolerance exist, never inside
   the state machine.
5. **Conservation.** `balance_a + balance_b + Σ locks == deposit_a + deposit_b`,
   against the deposits observed **on chain**, never against a number the peer
   supplied.
6. **Signatures.** Both recover, over the V2 digest — which covers the lock root,
   so this is also what proves the locks presented are the ones agreed.

### 4.2 The transition on top

`Channel.Accept` answers "is this a legal state". These answer "is this the state
the stated transition would produce", which is what makes a proposal
*unambiguous* rather than merely legal:

7. **The transition matches.** Applying `transition` to the stored latest state
   must yield **byte-identical** bytes to the proposed state. Not "an equivalent
   balance" — the same encoding. This is what makes §5 work.
8. **The payer is the one who loses.** `PAY` and `LOCK_ADD` must reduce the
   *proposing* party's balance. A proposal that pays its own sender is refused
   however well signed.
9. **`LOCK_SETTLE` carries a preimage that opens the named lock**, checked with
   `HTLC.Matches`. A settle without the secret is a refund wearing the wrong
   name.
9b. **`LOCK_SETTLE` names a lock whose expiry has NOT passed.** Added in P13.5,
    and derived from the contract rather than invented:

    ```solidity
    claimLock   if (block.timestamp >= lock.expiry) revert LockHasExpired();
    expireLock  if (block.timestamp <  lock.expiry) revert LockNotExpired();
    ```

    A preimage is worth the lock's value strictly before expiry and nothing at or
    after it, so a node co-signing a late settlement signs a state the chain
    would have reverted. Skew works AGAINST the settler, mirroring check 10:
    settle needs `Expiry > now + skew`, refund needs `Expiry <= now - skew`. The
    2*skew band where neither is permitted is deliberate — both valid at once is
    a race over one lock. Refusal code `LOCK_EXPIRED`, not retryable.

    This check was missing from BOTH this spec and the implementation until
    P13.5. Its absence is what let §9's hop lose money: settle downstream late,
    then find the upstream claim already dead. Check 11 below enforced the margin
    when the lock was CREATED; nothing enforced it when the value moved.

    A node must also refuse to SIGN such a settlement when it is the proposer,
    not merely refuse to accept one — a doomed proposal still records a signature
    at that nonce (§I4), which then blocks the peer's legitimate refund with
    `ALREADY_SIGNED_NONCE`.

10. **`LOCK_REFUND` names a lock whose expiry has passed.** Early refunds steal
    payments that are legitimately in flight. This is the layer that owns the
    clock, per §4.1's note.
11. **`LOCK_ADD` offers an expiry far enough out to be useful**, against this
    node's own policy and clock skew tolerance. A lock expiring in four seconds
    is structurally valid and worthless, and accepting it is how a hop ends up
    settled downstream with an expired claim upstream (§9).

**Rule I4 is enforced here.** Before signing, a node checks its own record of
nonces it has already signed for this channel. If it has signed *any* state at
this nonce, it refuses — even if that state was never completed, even if the
proposal now in hand looks better.

---

## 5. Determinism

> If the same payment can produce two different valid state 11s, retries become
> dangerous.

**Every payment carries an `intent`**: 32 bytes chosen by the payer, unique per
payment, and never reused for different contents.

**The proposed state is a pure function of (stored latest state, transition).**
Same base, same transition → byte-identical proposal. A payer that must retry
re-sends exactly what it sent before, so a duplicate arrival is recognisable as a
duplicate rather than as a competing version.

**The payee records applied intents per channel.** A `STATE_PROPOSE` whose intent
has already been applied is **not** re-applied. The payee replies with a
`STATE_ACCEPT` carrying the same counter-signature it produced the first time, or
a `STATE_RESPONSE` if the channel has since moved on. Idempotence is a property
of the protocol, not something callers are asked to arrange.

This is what makes the retry in the user's example impossible:

```text
retry #1:  nonce 11, Alice, 25 ANON        intent I
retry #2:  nonce 11, Alice, 30 ANON        ← cannot happen under one intent
```

A 30 ANON payment is a different intent, and by the time it is proposed the
channel is at nonce 12 — because intent I either completed or was rejected.
Two competing versions of one nonce never exist.

**Note what determinism does not mean.** If the channel advances between attempts
(another payment landed), the same intent proposed again correctly produces a
*different* state, at a higher nonce. That is not a violation — the base changed.
The applied-intent record is what stops it being applied twice.

---

## 6. The normal path

```text
Payer                                             Payee
  │                                                 │
  │ 1. build state N+1 from stored latest           │
  │ 2. refuse if already signed anything at N+1     │
  │ 3. sign                                         │
  │ 4. PERSIST pending{intent, state, own sig}      │
  │                                                 │
  │ 5.  ── STATE_PROPOSE ──────────────────────────▶│
  │                                                 │ 6. validate §4, all of it
  │                                                 │ 7. refuse if already
  │                                                 │    signed anything at N+1
  │                                                 │ 8. sign
  │                                                 │ 9. PERSIST complete state
  │                                                 │    as latest, + intent
  │ 11. ◀── STATE_ACCEPT ───────────────────────────│ 10.
  │                                                 │
  │ 12. verify the counter-signature                │
  │ 13. PERSIST complete state as latest            │
  │ 14. payment accepted                            │
```

Steps 4, 9 and 13 are the ones that make §8 work. Persisting after transmitting
would mean a peer holding a signature the signer has no record of — recoverable
only by that peer's goodwill, which is not a mechanism.

Note the payee reaches "complete state" at step 9, one round trip before the
payer at step 13. That gap is where most of the crash table lives, and it is
unavoidable: somebody has to be second.

---

## 7. Resynchronization

The most important operation in this protocol, and the one that turns a crash
into a recoverable event.

```text
STATE_REQUEST { channel }   ──▶
                            ◀── STATE_RESPONSE { state | none }
```

The response is a **complete signed state**, and the requester subjects it to
the entire §4.1 validation. There are exactly three outcomes:

```text
peer nonce > local nonce
        ↓  validates completely (§4.1, not just signatures)
     ADOPT — safe in this direction only, because both parties signed it

peer nonce < local nonce
        ↓
   DO NOT ADOPT — stale. Optionally offer our latest so they can catch up.

peer nonce == local nonce, different state
        ↓
    CONFLICT — never choose
```

**The same-nonce conflict is not a tie to break.** Two *fully signed* states at
one nonce means a party signed twice at that nonce, which invariant I4 forbids
and which the two states together prove. There is no rule that could pick
correctly between them, so the protocol does not have one.

On detecting it, a node MUST:

1. stop proposing and stop signing on that channel, permanently;
2. preserve both states — they are the evidence;
3. send `CONFLICT` carrying both, so an honest peer learns it too;
4. force-close on chain with the best state it holds, promptly.

Promptness matters: `challenge` requires a **strictly** greater nonce, so between
two states at the same nonce the one submitted first wins on chain. Detecting a
conflict and waiting is how the honest party loses.

Same nonce and *identical* state is not a conflict. It is the ordinary result of
a retry, and the answer is to do nothing.

---

## 8. Crash and reconnect

Every point at which a party can die, and what the protocol requires. This table
is the specification; the message formats above are just how it is carried out.

| Failure point | Required behaviour |
|---|---|
| Payer crashes before persisting the pending proposal | Nothing happened. No state, no signature, no record. Start over |
| Payer crashes after persisting, before sending | On restart, re-send the **identical** proposal from the pending record |
| Proposal sent, payee never receives it | Retry the identical proposal. Determinism makes the retry indistinguishable from the original |
| Payee receives and rejects | Neither side changes state. The payer discards the pending record; that intent is dead and MUST NOT be reused with different contents |
| Payee signs, payer crashes before receiving | The payee holds the completed state as latest. Payer reconnects, `STATE_REQUEST`, sees nonce 11 > local 10, validates fully, adopts. The payer can confirm its own signature on a state it does not remember making — signatures recover to an address, so no local record is needed to answer "did I sign this" |
| Payer receives the completed state, crashes before persisting | Identical to the row above. Recover from the peer |
| Payee persists, payer never does | Identical again. Resync recovers it |
| Both hold the same nonce and the same state | Nothing to do. The common case after any retry |
| Both hold the same nonce, different states | **Conflict.** Never choose. §7 |
| Peer reports a lower nonce | Reject as stale. Optionally push our latest |
| Peer reports a higher nonce that validates completely | Adopt |
| Peer reports a higher nonce that fails any §4.1 check | Reject and treat as hostile. A peer offering an invalid state is either broken or probing |
| Stored state fails validation at startup | **Fail closed.** Refuse to start. Already implemented — `store.go` recomputes the digest and re-recovers both signatures at load |
| Restored from a backup | Not solvable at this layer. A restored backup is a valid-looking older lineage; see roadmap P12. The node must not sign until recovery has established which lineage is current |

The last row is the one this protocol cannot fix by itself, and it is recorded
here so nobody mistakes resync for a backup strategy. Resync asks a peer, and a
peer can be gone, or lying, or the same restored backup.

---

## 9. HTLCs on the same machine

A routed payment is a sequence of ordinary transitions on separate channels,
sharing one hash:

```text
Tipper ──LOCK_ADD(H, 25, T+4h)──▶ Hub ──LOCK_ADD(H, 25, T+2h)──▶ Recipient
                                                                      │
                                        reveals preimage of H  ◀──────┘
Tipper ◀──LOCK_SETTLE(H)── Hub ◀──LOCK_SETTLE(H)── Recipient
```

Each arrow is a `STATE_PROPOSE` on its own channel, validated by §4 like any
other. Nothing about routing appears in the state machine.

Two rules the protocol enforces, both about the hop in the middle:

**Expiries strictly decrease along the route.** Each hop's outgoing lock must
expire *before* its incoming lock. Otherwise a hub can be settled downstream and
find its own upstream claim already expired — paid out, unable to collect. The
contract cannot check this (it sees one channel), so it is checked here, and a
hop MUST refuse to forward when the margin is insufficient.

**A hub settles upstream only after it can settle downstream.** The preimage is
what makes that possible, and it travels backwards for exactly this reason. This
is the property `ChannelManagerV2.test.ts` already demonstrates on chain: the hub
puts up 100 and recovers 100.

Multi-hop is not a different case. It is the same two rules applied at each hop,
which is why the protocol has nothing to say about the number of hops.

---

## 10. Rejections and errors

`STATE_REJECT` names the rule that failed, from a closed set, so a payer can tell
"try again later" from "never do that again":

| Code | Meaning | Retryable |
|---|---|---|
| `NONCE_STALE` | Not strictly greater than stored | After resync |
| `ALREADY_SIGNED_NONCE` | I4: already signed a different state at this nonce | No |
| `NOT_CONSERVED` | Balances plus locks do not match deposits | No |
| `BAD_SIGNATURE` | Did not recover to the expected party | No |
| `LOCKS_MALFORMED` | Unsorted, duplicated, expired or non-positive | No |
| `TRANSITION_MISMATCH` | The state is not what the stated transition produces | No |
| `PREIMAGE_BAD` | `LOCK_SETTLE` without a preimage that opens the lock | No |
| `LOCK_EXPIRED` | `LOCK_SETTLE` at or after the lock's expiry — the chain would revert the claim | No |
| `LOCK_NOT_EXPIRED` | `LOCK_REFUND` too early | Later |
| `INSUFFICIENT_CAPACITY` | The payer cannot cover it | Later |
| `CHANNEL_CONFLICTED` | This channel is stopped under §7 | No |
| `CHANNEL_CLOSING` | An on-chain close is in progress | No |

A rejection changes nothing on either side. That is what makes it safe to send.

---

## 11. Open questions

Recorded rather than guessed:

- **Who initiates a resync**, and how often. Always on reconnect is obviously
  correct; whether to resync periodically is not settled.
- **How long a pending proposal lives** before the payer gives up and treats the
  intent as dead. Too short risks abandoning a payment the payee completed; too
  long holds capacity.
- **What a hub does when the downstream hop is unreachable after `LOCK_ADD`.**
  The lock expires and refunds, which is correct but slow. Whether there is a
  cooperative cancellation is undecided.
- **Whether `CHANNEL_ANNOUNCE` needs proof.** A peer claiming a channel exists is
  checkable on chain, and probably should be checked rather than believed.

---

## 12. What this settles for the implementation

- The wire format, the encoding, and the exact bytes of every message (§3).
- What a valid transition is, as ten ordered checks, six of which are already
  implemented in `Channel.Accept` (§4).
- Determinism through intents, and idempotence as a protocol property (§5).
- Every crash point and its required behaviour (§8).
- One state machine for direct, routed and multi-hop (§9).

`Native`, `keys.go`'s `proofDigest`, `SignBalance`/`VerifyBalance` and `wire.go`
implement none of this and cannot be adapted to it — their digest is not the
contract's, their signing key is not the party's, and `Amount int64` cannot hold
one gold award. SCPP/1 is implemented against the V2 types directly. `wire.go` is
replaced, not extended.
