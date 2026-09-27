# P15 — Pipelined mailbox tipping: protocol analysis

**Status: DESIGN ANALYSIS. No code written. No contract modified.**

Deliverable requested before implementation: does Case B require a protocol
change, and must ChannelManagerV2 change?

---

## 0. Answers

1. **ChannelManagerV2 does NOT need to change.** Not "we prefer not to" — the
   contract never sees an intermediate state, so pipelining is invisible to it.
2. **Most of Case B is not pipelining at all** and already works today.
3. The genuinely new case is narrow: **one contributor tipping the same
   recipient repeatedly while they are offline.** It needs no new state model —
   it needs the contributor to remember its own chain, and the mailbox already
   holds it.
4. The `Pending` constraint I reported last phase is real but **does not apply
   to browser contributors**, which is the case that matters here.

---

## 1. The reframing: Alice/Bob/Carol is not one queue

The brief's Case B is:

```
Alice → +25 → mailbox
Bob   → +40 → mailbox
Carol → +15 → mailbox
```

Alice, Bob and Carol are **different contributors**, so these are **three
different bilateral channels**:

```
channel(Alice, R)   nonce N_a → N_a+1
channel(Bob,   R)   nonce N_b → N_b+1
channel(Carol, R)   nonce N_c → N_c+1
```

`Pending` is a field on `Channel` (`state.go:510`), and the store holds one
`Channel` per id. Three channels are three independent `Pending` slots. **There
is no nonce collision, no ordering question and no shared queue** — the brief's
own Phase 12 says as much, and Phase 12 and the second half of Phase 8 describe
the *same* thing.

So multi-contributor accumulation against an offline recipient is a property the
system already has. It needs testing, not designing.

**The only real pipelining case is Phase 8's first half:**

```
Alice +25      one channel
Alice +40      three proposals
Alice +10      recipient never online
```

## 2. Why it needs no new state model

The naive reading is that the recipient must countersign N+1, then N+2, then
N+3, in order. That is not so, because of how Alice builds them:

```
N+1 = N   + 25        balances after tip 1
N+2 = N+1 + 40        balances after tips 1 AND 2
N+3 = N+2 + 10        balances after tips 1, 2 AND 3
```

**Each state subsumes its predecessors.** N+3 is not "the third tip", it is *the
whole relationship after three tips*. So the recipient does not need N+1 and N+2
at all: countersigning **only the highest** realises every tip in the chain.

That is not a new rule. It is the ordinary payment-channel rule — a newer state
beats an older one — applied to a case where several newer states arrived at
once.

### It is already permitted by the code

`Channel.Accept` requires the nonce to be **strictly greater**, not exactly one
greater:

```go
if st.Nonce <= c.Latest.State.Nonce && !(...) { return ErrNonceRegressed }
```

So accepting N+3 directly, having never seen N+1 or N+2, is already legal.

### It is safe for both parties

| | |
|---|---|
| **Recipient** | N+3 pays them the most of the three. Accepting the highest is the choice that favours them, so there is no incentive problem and nothing to enforce. |
| **Alice** | She signed all three. The two she is *not* bound by give her MORE than N+3, so a recipient submitting N+1 instead would be choosing to receive less. Alice cannot be harmed by which one is chosen. |
| **I4** | Each party signs **at most one state per nonce**. Alice signs N+1, N+2, N+3 — one each. The recipient signs N+3 only. The invariant is untouched, and it is untouched *without weakening it*. |

### Superseded proposals are discarded, and that is correct

The brief says "never silently discard an item because its predecessor is
missing." Under subsumption the opposite is true and worth stating plainly:
discarding N+1 and N+2 after accepting N+3 **loses nothing**, because their value
is inside N+3. What must never be discarded is the *highest* proposal.

The missing-middle case behaves well:

- N+2 lost, N+3 present → accept N+3. All three tips realised.
- N+3 lost, N+2 present → accept N+2. Tips 1–2 realised; **tip 3 is simply not
  yet delivered**, and Alice re-sends it built on N+2. No money is lost or
  duplicated, and the failure is visible rather than silent.

## 3. Why the contract is indifferent

ChannelManagerV2 only ever sees a state that is submitted to it —
`checkpoint`, `closeCooperative`, `closeUnilateral` or `challenge`. It has no
notion of intermediate states and no way to ask how many existed.

`stateDigest(op, chainid, contract, id, nonce, balA, balB, root, wA, wB)`
describes one state. A state at nonce N+3 with cumulative balances is an
ordinary state; the contract cannot tell it apart from one reached by three
round trips.

Checked each settlement path for an assumption pipelining would break:

| path | assumption | broken? |
|---|---|---|
| `checkpoint` | `a.nonce > ch.nonce`, conservation vs deposits | no |
| `closeCooperative` | conservation, both signatures | no |
| `closeUnilateral` | both signatures, conservation | no |
| `challenge` | strictly greater nonce | no — a watchtower holding N+3 still beats N+1 |
| `settle` / `_payout` | pays `partyA`/`partyB` | no |

**Conclusion: no contract change. Do not touch a deployed-nowhere contract for a
problem it does not have.**

## 4. Where the real constraint actually lives

`PeerSession.Propose` refuses a second outstanding proposal:

```go
if p := ch.Pending; p != nil { return Envelope{}, fmt.Errorf("...already pending at nonce %d") }
```

That is a **Go node, proposer-side** rule. The contributor in this design is a
**browser**, and `tip-channel.js` builds its own `STATE_PROPOSE` (`proposeEnvelope`)
without ever entering that path. So the constraint I reported last phase is real
for node-to-node pipelining and **does not bind the case we need**.

It should stay as it is. One outstanding proposal per channel is what makes
"have I already signed at this nonce" cheap to answer on a node that signs
unattended, and nothing here needs it relaxed.

## 5. What must actually be built

Only one thing is missing: **the contributor must know its own latest signed
state** to build the next one. Today `proposeEnvelope` bases everything on the
chain, which is why only the first tip is correct.

The state is not in the recipient's node (they never saw it) and not on chain
(it is off-chain by definition). The contributor is its sole holder — **and so is
the mailbox, which is already holding those exact frames.**

So the smallest correct mechanism reuses what exists:

```
Alice's browser ──"what are you holding from me for R?"──► volunteer
                ◄──her own signed proposals, verbatim─────
                    rebuild the chain, verify her OWN signature,
                    build the next state from the highest
```

Alice verifies the signature on what comes back is *hers*, so a volunteer cannot
forge a chain — the worst it can do is withhold, which stalls Alice's next tip
and steals nothing. No new database, no browser persistence required, and the
volunteer gains no authority it did not already have.

**Sequential Case A** needs the complementary half: after the recipient
countersigns, the co-signed state is handed back to the volunteer to serve
read-only on `fetchState`. `tip-channel.js` already re-derives the digest and
calls `requireSigner` on both signatures before trusting anything handed to it,
so the volunteer is a cache of something self-verifying.

### Invariants (Phase 2's questions, answered)

| question | answer |
|---|---|
| how proposals get nonces | contributor's chain: previous proposal + 1 |
| who may create N+1 | either party; in practice the payer |
| dependency | N+1 is built from N's balances; each subsumes its predecessors |
| accepted in order? | **no** — accept the highest; the rest are superseded |
| N+2 before N+1 | fine. N+2 already contains N+1 |
| one rejected | the chain from that point is void; rebuild from the last accepted |
| cancellation | stop sending; unaccepted proposals expire unrealised |
| expiration | mailbox depth cap + authorization expiry, both already present |
| duplicate identity | existing `intent` + `AppliedAt` |
| stale detection | nonce ≤ latest accepted |
| revoked delegate | `canSign` is asked per signature; queued proposals simply stop being signable |
| reorg | unchanged — on-chain state is read through the existing finality rules |
| restart | rebuild from the mailbox and the store; nothing new to recover |

## 6. Scope, revised

| brief's phase | real status |
|---|---|
| 8 (second half), 12 — multi-contributor | **already supported**; needs a test, not a design |
| 8 (first half) — same contributor repeated | needs §5's chain rebuild |
| Case A — sequential | needs §5's co-signed read-back |
| 4 — economic model | **Approach 1 (chained), with the recipient accepting only the highest.** Approach 2 (independent claims) is unnecessary and would need a contract change |
| 5 — contract implications | **none** |
| 3 — I4 | preserved unweakened |

## 7. What I have NOT done

No code. No devnet run. No browser run. Phases 6–15 are untouched. The estimate
above is that Case B is *smaller* than the brief assumes — but it is an estimate
until the mailbox chain-rebuild is built and a real devnet run shows three tips
from one contributor accumulating correctly.

**Pooled tipping is not live, and mailbox mode still works reliably only for the
first tip on a channel.**
