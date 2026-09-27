# P15 — Many-to-one tipping pools: design

> **Status: the aggregation layer is BUILT** — `internal/channel/pool.go`,
> 16 tests, 8/8 mutations caught. What remains is the recipient-facing config
> and executing checkpoints against the deployed contract.

**The central claim: a pool is a DERIVED VIEW over signed bilateral states the
recipient already holds. It is not a ledger, not a custodian, and it stores no
balance that could be wrong.**

Everything below is answered from the existing primitives rather than proposed,
because P15's own text says guessing at these is how a pool becomes the trusted
database it must not be.

---

## The shape

```text
Alice ──[bilateral channel A]──┐
Bob   ──[bilateral channel B]──┼──► RECIPIENT NODE
Carol ──[bilateral channel C]──┘         │
                                         │  pool = a VIEW, computed
                                         ▼
                          aggregate = Σ recipient's balance
                                         │
                                         │  per channel, co-signed
                                         ▼
                         KindCheckpoint ──► contract.checkpoint()
```

There is no pool object holding value. The aggregate is a **sum over channels,
recomputed from co-signed states**. Delete it and nothing is lost; corrupt it and
the next recomputation corrects it.

That is what makes the non-custodial requirement structural rather than a
promise: **there is no balance to manufacture** because no balance is stored.

## The primitives already exist

| need | primitive | where |
|---|---|---|
| a contribution | a co-signed V2 `State` with `BalanceA`/`BalanceB` | `state.go:304` |
| value out without closing | **`KindCheckpoint`** — "takes value OUT of the channel without closing it" | `transition.go:59` |
| the withdrawal amount | `State.WithdrawA`/`WithdrawB`, covered by the digest | `state.go:313` |
| on-chain call | `CheckpointCalldata(ch)` | `chainwriter.go:145` |
| replay prevention | `Channel.AppliedAt(intent)` + strictly-increasing nonce | `state.go:605` |
| unilateral exit | `closeUnilateral` — needs no counterparty | contract |

**Nothing new is needed at the protocol or contract layer.** That is the finding,
and it is the opposite of what "build a pool" usually implies.

---

## The 14 questions

**1. How is a contribution bound to contributor, recipient, pool, amount, intent?**
By the existing state digest. A contribution *is* a co-signed state in the
bilateral channel between contributor and recipient; the digest covers the
channel id, nonce, both balances, the HTLC root and both withdrawals. The pool is
not in the digest **and must not be** — binding to a pool would make the pool a
party, which is exactly the custodian being avoided. Pool membership is the
recipient's local policy, not a cryptographic fact.

**2. Is a contribution an existing state, a new authorisation, or another primitive?**
An **existing bilateral channel state**. No new primitive.

**3. How is replay prevented?**
`AppliedAt(intent)` answers "has this intent already been applied, and at what
nonce", and nonces are strictly increasing. Both already carry P4 §5's
idempotence. A retry after an unknown outcome lands on the recorded answer.

**4. How does the pool handle an unknown payment outcome?**
Exactly as a bilateral tip does — it is the same code path. The pool adds no new
outcome and no new ambiguity, because it adds no new message.

**5. How do contributors leave or expire?**
They close their channel, or stop contributing. There is no membership to revoke;
"in the pool" is the recipient's view of channels that exist.

**6. How does the recipient checkpoint the aggregate?**
**They cannot, in one transaction — and this is the design's hard constraint.**

`ChannelManagerV2.checkpoint()` takes **one channel id** and requires **both
signatures** (`sigA, sigB`). So an aggregate of N contributors is **N
transactions, each co-signed by that contributor**. There is no batching path
that does not change the contract.

This is where a naive pool invents a custodian: aggregate off-chain into one
balance, settle once, and trust the operator. **That trade is refused.** The cost
of non-custodial pooling is N on-chain checkpoints, and the honest design says so
rather than engineering it away.

What pooling *does* buy is off-chain: one view, one policy, and the recipient
choosing **when** each channel is worth checkpointing.

**7. What if the recipient disappears?**
Each contributor holds a co-signed state and can `closeUnilateral` alone. The
watchtower defends them. Unchanged from bilateral.

**8. What if the pool coordinator disappears?**
**There is no coordinator.** The pool is the recipient's own view over their own
store. That question dissolves — which is the strongest evidence the shape is
right.

**9. Can pooled contributions contain HTLCs, and how do unresolved locks interact
with checkpointing?**
Yes, and here the contract is more permissive than expected:

```solidity
checkpoint(CheckpointArgs a, Lock[] calldata locks, ...)
    uint256 locked = _lockedTotal(locks);
    if (a.balanceA + a.balanceB + locked + a.withdrawA + a.withdrawB
        != ch.depositA + ch.depositB) revert BalanceMismatch();
```

**`checkpoint` tolerates outstanding locks**, conserving them explicitly —
whereas `closeCooperative` refuses any non-zero HTLC root. So a recipient can
withdraw settled value while locks are still live. Only *unlocked* balance may
leave, which the conservation check enforces.

**10. How are direct and routed payments represented in pool history?**
Identically — both are `KindPay` applications on a bilateral channel. `history.go`
already records them with their intent. The pool reads that history; it does not
keep its own.

**11. Can multiple pools exist for the same recipient?**
Yes, as views — **but they must partition the channel set, not overlap.** A
channel's value can be checkpointed once. Two overlapping views would both count
it and the recipient would believe they hold more than they can withdraw. **A
pool must own a disjoint channel set**, and that is an invariant a test has to
pin, because nothing structural prevents it.

**12. Can one contributor contribute to several recipients or pools?**
Yes, trivially — those are different channels. No interaction.

**13. How is pool state recovered after restart?**
There is none to recover. The view is recomputed from the store, which already
survives restart and crash (P3, P11).

**14. How is the aggregate proven without trusting a mutable local database?**
**The signed states are the proof.** Each is co-signed and independently
verifiable; the aggregate is a sum, recomputable from them at any time. A mutable
local database is never consulted for a value that matters — which is the same
rule `evidencereader.go` applies to chain state.

---

## The security floor, restated

| requirement | how it holds |
|---|---|
| peer collateral never authoritative | unchanged — pool reads no peer claims |
| signed state authoritative off-chain | the pool reads *only* signed states |
| chain authoritative for collateral | checkpoint goes through the contract |
| transport failure ≠ payment success | unchanged code path |
| a retry cannot duplicate | `AppliedAt(intent)` |
| no caller-selected state | the caller asks "tip X"; the node builds the state |
| **a pool cannot manufacture balances** | **it stores none** |

## What this design deliberately does not do

- **No N-party channel.** Ruled out by the phase, and unnecessary.
- **No pool operator, coordinator, or service.** Question 8 has no subject.
- **No aggregate stored anywhere.** It is a sum, computed on read.
- **No new message, transition kind, or contract function.**
- **No batching of checkpoints.** Not possible without a contract change, and the
  contract is not on the table.

## What still has to be built

The phase is not complete because the shape is simple. Per its own bar —
"aggregation, cryptographic authorisation, idempotence, recovery and checkpoint
behaviour must each be designed, built and tested":

1. **the recipient policy flag** — pooling off by default; bilateral stays the default path;
2. **the aggregation view** — sum over a *disjoint* channel set, recomputed, never stored;
3. **checkpoint policy** — when a channel is worth checkpointing, given gas;
4. **the disjointness invariant** — a test that fails if two pools claim one channel;
5. **HTLC interaction** — checkpointing with live locks, since the contract allows it;
6. **recovery test** — the view is correct after restart because it is recomputed.

## The one number this design lacks

**`checkpoint` gas is NOT MEASURED.** `doc/fixtures/p14-economics.md` measured
`openChannel`, `deposit`, `closeCooperative`, `closeUnilateral`, `challenge` and
`settle` — but not `checkpoint`, which is the transaction a pool sends most.

It does not change the structure: N checkpoints is N transactions whatever each
costs. It decides **policy** — the threshold below which checkpointing a small
contribution loses money — and that is implementation-time work. It is a local
hardhat measurement, not a network campaign. **Not run**, per the instruction not
to start additional testing.

## Classification

| | class |
|---|---|
| `KindCheckpoint` exists and takes value out without closing | **VERIFIED** (source) |
| `State` carries digest-covered `WithdrawA`/`WithdrawB` | **VERIFIED** |
| `checkpoint()` is per-channel and needs both signatures | **VERIFIED** (contract) |
| `checkpoint` tolerates live locks; `closeCooperative` does not | **VERIFIED** (contract) |
| `AppliedAt(intent)` provides idempotence | **VERIFIED** |
| a pool needs no new primitive | **DERIVED** from the above |
| overlapping pools would double-count | **DERIVED** — needs a test |
| `checkpoint` gas | **NOT MEASURED** |
