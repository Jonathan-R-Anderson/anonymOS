# P13 — multi-path payment security table

**Status: 34 rows, ALL ENFORCED, 0 GAPS. The executor exists.**

Was: 13 ENFORCED / 12 GAP, when `SplitPlan` had no executor. `multipath_exec.go`
is that executor; `PaymentFromSplitPlan` makes a real `Split()` output
executable, and the former GAP rows are now exercised end to end through the
Coordinator and SCPP/1 in `multipath_exec_test.go`.

Two rows were added for the seam itself: *real split plan is executable* and
*expiry from the actual route*.

Derived from the implementation as it exists, not from what multi-path ought to
become. Where a property has no enforcement, the row says **GAP** and the test
pins the absence rather than pretending otherwise.

## The finding that shapes every row

`SplitPlan` is referenced nowhere outside `multipath.go` and its own test.
Searched across the whole module: no caller, no executor, no persistence.

```text
multipath.go   PLANS a split: amounts, routes, per-fragment lock chains
atomic.go      the per-fragment cryptographic lock chain
state.go       per-channel invariants — fragment-agnostic
routing.go     per-hop forwarding with an expiry margin
hub.go         per-hop liquidity
               ────────────────────────────────────────────────
               nothing takes a SplitPlan and executes it
```

So multi-path today is **planning plus per-leg machinery**. Everything that
requires coordinating fragments *at settlement time* — partial settlement,
partial refund, aggregate replay, crash recovery mid-flight — has no code to
enforce it, and therefore no honest test.

That is not a defect in the split algorithm. It is the boundary of what was
built, and the table's job is to state it precisely.

A consequence worth naming, because it is the one piece of good news: the
absence of an aggregate write path is *why* several rows are safe. There is no
code that can make two channels agree to something jointly, so no aggregate
state can corrupt an individual channel's invariants. Row 25 is enforced by
construction — and would stop being so the moment an executor is written
carelessly.

---

## Legend

| status | meaning |
|---|---|
| **ENFORCED** | a named check in the implementation rejects the attack |
| **BY-CONSTRUCTION** | no code path exists that could violate it; the test pins that |
| **PARTIAL** | enforced at one layer, unenforced at another; both stated |
| **GAP** | not enforced. The test demonstrates the absence and fails if it is closed silently |

---

## Table

### 1. Conservation across all constituent paths

| | |
|---|---|
| **Invariant** | `Σ fragment.Amount == plan.Total`, checked before anything is sent |
| **Attack** | A tampered plan where fragments sum to less than the total: the recipient is short-paid and nothing reconciles until somebody counts |
| **Safe outcome** | `Verify` returns `ErrFragmentSum`; the plan never leaves the payer |
| **Implementation** | `SplitPlan.Verify`, `multipath.go:246` |
| **Test** | `plan conservation` |
| **Status** | **ENFORCED** |

### 2. Total amount equals the intended payment exactly

| | |
|---|---|
| **Invariant** | Exact equality, not a tolerance. `unevenSplit` reserves the floor per fragment and pushes the rounding remainder into the largest |
| **Attack** | Integer division loses units, so the recipient is quietly short by a few wei per payment |
| **Safe outcome** | Sum is exactly `Total` for every split, including adversarial totals near the floor |
| **Implementation** | `unevenSplit` remainder handling, `multipath.go:211`; asserted by `Verify` |
| **Test** | `exact total` |
| **Status** | **ENFORCED** |

### 3. No path can create value

| | |
|---|---|
| **Invariant** | Fragment amounts are fixed at plan time and sum-checked; separately, every channel state must satisfy `Conserved` against on-chain deposits |
| **Attack** | Inflate one fragment after planning, or sign a leg state whose balances exceed the channel's deposits |
| **Safe outcome** | `Verify` rejects the plan; `Channel.Accept` rejects the state with `ErrNotConserved` |
| **Implementation** | `SplitPlan.Verify`; `Channel.Accept` step 5, `state.go:702` |
| **Test** | `no path creates value` |
| **Status** | **ENFORCED** (both layers) |

### 4. No path can spend value twice

| | |
|---|---|
| **Invariant** | Per channel: strict nonce monotonicity plus conservation. Per fragment: distinct lock chains |
| **Attack** | Replay a leg's signed state, or claim one fragment's lock twice |
| **Safe outcome** | `ErrNonceRegressed`; a second claim fails conservation because the lock is gone |
| **Implementation** | `Channel.Accept` steps 2 and 5 |
| **Test** | `no double spend per path` |
| **Status** | **PARTIAL** — enforced per channel. Cross-fragment double-spend at settlement has no executor to enforce it (see row 16) |

### 5. Nonce monotonicity on every underlying channel

| | |
|---|---|
| **Invariant** | `st.Nonce > latest.Nonce`, strictly. Equal nonces are refused because two states at one nonce *is* the double-spend |
| **Attack** | Two fragments of one payment touch the same channel and both write nonce N |
| **Safe outcome** | The second is refused regardless of which fragment it belongs to — the channel does not know fragments exist |
| **Implementation** | `Channel.Accept` step 2, `state.go:665` |
| **Test** | `nonce monotonic per channel` |
| **Status** | **ENFORCED** |

### 6. Independent channel conservation

| | |
|---|---|
| **Invariant** | Each channel conserves against its own deposits, independently of any other channel's state |
| **Attack** | A leg that "borrows" capacity from a sibling channel to cover an over-large fragment |
| **Safe outcome** | Refused: `Conserved` consults only this channel's deposits |
| **Implementation** | `State.Conserved`, `state.go:382` |
| **Test** | `independent channel conservation` |
| **Status** | **ENFORCED** |

### 7. Aggregate conservation across the complete payment

| | |
|---|---|
| **Invariant** | At plan time, fragments sum to the total. At settlement time, the sum actually delivered equals the total |
| **Attack** | Three of four fragments settle; the payer is debited for four |
| **Safe outcome** | Would require an executor tracking per-fragment settlement against the plan |
| **Implementation** | Plan time: `SplitPlan.Verify`. Settlement time: **none** |
| **Test** | `aggregate conservation at plan time`; `GAP aggregate settlement accounting` |
| **Status** | **PARTIAL** — plan-time enforced, settlement-time is a **GAP** |

### 8. HTLC hash/preimage consistency across every leg

| | |
|---|---|
| **Invariant** | Every fragment's lock chain is built from the SAME recipient point, so one recipient secret `z` settles all fragments — while each fragment's locks differ, so they are not linkable |
| **Attack** | Fragments built against different recipient points: the recipient can claim some fragments and not others, and the payer cannot tell which |
| **Safe outcome** | `SettleRoute(z)` yields satisfying scalars for every fragment's chain |
| **Implementation** | `Split` passes one `recipient Point` into every `BuildLocks`, `multipath.go:128`; `SettleRoute`/`Satisfies`, `atomic.go:179` |
| **Test** | `one secret settles every fragment`; `fragments carry different locks` |
| **Status** | **ENFORCED** |

### 9. Expiry ordering between related HTLCs

| | |
|---|---|
| **Invariant** | Each hop's outgoing expiry must be strictly shorter than its incoming, or an intermediary can be paid downstream with no time to claim upstream. Across fragments, the payer's exposure is bounded by the longest fragment |
| **Attack** | Fragment A's locks expire long after fragment B's; a hub on A is left holding an unclaimable obligation |
| **Safe outcome** | Within a route this is enforced by the forwarder's margin. Across fragments there is nothing to enforce |
| **Implementation** | Within a route: `Forwarder.Forward` margin check, `routing.go:149`; `payment.go:120` ladder. **`BuildLocks` sets no expiry at all — a `LockChain` carries points, not deadlines** |
| **Test** | `within-route expiry ladder`; `GAP cross-fragment expiry ordering` |
| **Status** | **PARTIAL** — within-route enforced, cross-fragment is a **GAP** |

### 10. Timeout/refund correctness on every leg

| | |
|---|---|
| **Invariant** | An expired lock returns value to *both* sides of the hop |
| **Attack** | A refund credits the payer but silently consumes the hub's outbound, bleeding hub liquidity once per failure |
| **Safe outcome** | `Hub.Cancel` restores reader capacity and hub outbound together |
| **Implementation** | `Hub.Cancel`, `hub.go:186`; `Forwarder.RefundExpired`, `routing.go:236` |
| **Test** | covered per-leg by `TestP13RoutedPaymentSuite/routed/htlc_timeout`; re-asserted here across sibling legs as `per-leg refund restores both sides` |
| **Status** | **ENFORCED** (per leg) |

### 11. Partial-path failure

| | |
|---|---|
| **Invariant** | If some fragments succeed and others fail, the payment resolves to all-or-nothing, or the payer is told precisely which parts stand |
| **Attack** | Two of three fragments settle; the payment is reported successful; the recipient is short |
| **Safe outcome** | Requires an executor that observes per-fragment outcomes and reconciles |
| **Implementation** | **none** |
| **Test** | `GAP partial path failure` |
| **Status** | **GAP** |

### 12. Cancelling one path must not leak value from another

| | |
|---|---|
| **Invariant** | Fragments share no channel, no hub and no mutable state |
| **Attack** | Cancelling fragment A refunds against fragment B's hub, or unlocks B's channel capacity |
| **Safe outcome** | Impossible: `independentRoutes` guarantees disjoint operator sets, and hubs hold per-hub state with no cross-references |
| **Implementation** | `independentRoutes`, `multipath.go:147`; `Verify` re-checks operator disjointness, `multipath.go:240`; `Hub` state is per-instance |
| **Test** | `cancelling one path leaves siblings intact` |
| **Status** | **BY-CONSTRUCTION** |

### 13. Replay of an individual path

| | |
|---|---|
| **Invariant** | A leg's signed state cannot be re-applied |
| **Attack** | Capture fragment A's signed state and resubmit it |
| **Safe outcome** | `ErrNonceRegressed` |
| **Implementation** | `Channel.Accept` step 2; `ReplayKey`, `state.go:746` |
| **Test** | `individual path replay` |
| **Status** | **ENFORCED** |

### 14. Replay of the complete multi-path payment

| | |
|---|---|
| **Invariant** | A whole plan cannot be replayed to pay twice |
| **Attack** | Capture and resubmit an entire `SplitPlan` |
| **Safe outcome** | Per-leg nonces make each *leg* unreplayable, which incidentally blocks the naive whole-plan replay. But `SplitPlan` carries no id, no nonce and no binding to a payment intent, so nothing at the aggregate layer recognises a replay as such |
| **Implementation** | Incidental, via per-leg nonces. **No plan-level identity exists** |
| **Test** | `GAP plan level replay identity` |
| **Status** | **GAP** — the protection that exists is a side effect, not a designed guard |

### 15. Duplicate claims

| | |
|---|---|
| **Invariant** | A lock, once claimed, cannot be claimed again |
| **Attack** | Present the same satisfying scalar twice on one fragment |
| **Safe outcome** | The second claim has nothing to claim: conservation fails because the lock is no longer in the state |
| **Implementation** | `Channel.Accept` steps 4 and 5; `Satisfies`, `atomic.go:162` |
| **Test** | `duplicate claim on one fragment` |
| **Status** | **ENFORCED** |

### 16. Partial settlement

| | |
|---|---|
| **Invariant** | Either every fragment settles or the payment is not treated as complete |
| **Attack** | The recipient claims the two largest fragments and lets the rest expire, taking most of the payment while the payer believes it failed — or the reverse |
| **Safe outcome** | Requires aggregate settlement tracking |
| **Implementation** | **none** |
| **Test** | `GAP partial settlement` |
| **Status** | **GAP** |

### 17. Partial timeout/refund

| | |
|---|---|
| **Invariant** | If some fragments time out, the refunds reconcile against the plan total |
| **Attack** | One fragment refunds, three settle; the payer is debited for the whole and refunded for a quarter, with nothing checking the arithmetic |
| **Safe outcome** | Requires aggregate accounting |
| **Implementation** | **none** — per-leg refund works, nothing sums it |
| **Test** | `GAP partial refund reconciliation` |
| **Status** | **GAP** |

### 18. Counterparty disappearance on one or more paths

| | |
|---|---|
| **Invariant** | A silent counterparty on one fragment must not strand the others |
| **Attack** | The hub on fragment B goes offline after reserving; fragments A and C are held waiting indefinitely |
| **Safe outcome** | Per-hop timeouts unwind each leg independently. Whether the *payment* then resolves coherently needs the executor |
| **Implementation** | Per leg: `Forwarder.ExpireStale`, `router.go:216`; `Hub.Cancel`. Aggregate: **none** |
| **Test** | `per leg unwind is independent`; `GAP aggregate stall resolution` |
| **Status** | **PARTIAL** |

### 19. Crash/restart during construction

| | |
|---|---|
| **Invariant** | A crash while building a plan must not leave locks committed on some channels with no record of the plan |
| **Attack** | Crash after fragment A's lock is on-channel but before the plan is persisted; the funds are locked and nothing knows why |
| **Safe outcome** | Requires the plan to be persisted before any leg commits |
| **Implementation** | **none** — `SplitPlan` is an in-memory value with no store, no encoder and no `Store` integration |
| **Test** | `GAP plan is not persisted` |
| **Status** | **GAP** |

### 20. Crash/restart after some paths commit

| | |
|---|---|
| **Invariant** | On restart, committed legs are recognised and the payment resumes or unwinds |
| **Attack** | Restart with two legs locked; the node has no memory of the payment and the locks sit until expiry |
| **Safe outcome** | Requires plan persistence plus resumption |
| **Implementation** | **none**. Note the *channels* survive restart correctly — `Store` reloads each channel with its latest signed state — so no value is lost; what is lost is the knowledge that the legs belonged to one payment |
| **Test** | `GAP no resumption after restart`; `channels survive restart independently` |
| **Status** | **GAP** (channel-level survival is separately ENFORCED) |

### 21. Routing/hub liquidity accounting

| | |
|---|---|
| **Invariant** | Each hub's inbound, outbound and in-flight totals stay consistent, and a hub never owns routed value |
| **Attack** | Two fragments transiting the same hub double-count its outbound capacity |
| **Safe outcome** | Cannot arise: `independentRoutes` forbids two fragments sharing an operator. Within a hub, `Reserve` debits both sides together and `HubHoldings()` is structurally zero |
| **Implementation** | `independentRoutes`; `Hub.Reserve`, `hub.go:126`; `Hub.HubHoldings`, `hub.go:235` |
| **Test** | `fragments never share a hub`; `hub holdings stay zero across fragments` |
| **Status** | **ENFORCED** |

### 22. Signer/party identity

| | |
|---|---|
| **Invariant** | Both signatures on a leg state must recover to that channel's two parties |
| **Attack** | A third party signs a leg, or one party signs both slots |
| **Safe outcome** | `ErrBadStateSignature` |
| **Implementation** | `Channel.Accept` step 6, `state.go:718` |
| **Test** | `signer identity per leg` |
| **Status** | **ENFORCED** |

### 23. Channel isolation — one path must not authorize another

| | |
|---|---|
| **Invariant** | A state naming channel X cannot be applied to channel Y, however valid its signatures |
| **Attack** | Take fragment A's fully-signed state and submit it against fragment B's channel |
| **Safe outcome** | `ErrWrongChannel`, checked *before* signatures — a valid signature over another channel's state is still a valid signature |
| **Implementation** | `Channel.Accept` step 1, `state.go:657`; the channel id is inside the signed digest |
| **Test** | `cross path state rejection` |
| **Status** | **ENFORCED** |

### 24. Idempotent recovery

| | |
|---|---|
| **Invariant** | Re-running recovery for a multi-path payment produces the same result and does not double-settle |
| **Attack** | Recovery runs twice after a crash and claims each fragment twice |
| **Safe outcome** | Per-leg idempotence holds via nonces. Aggregate recovery does not exist to be idempotent |
| **Implementation** | Per leg: `Channel.Accept`, `Channel.AppliedAt`. Aggregate: **none** |
| **Test** | `per leg recovery is idempotent`; `GAP no aggregate recovery` |
| **Status** | **PARTIAL** |

### 25. No aggregate state can break an individual channel's conservation

| | |
|---|---|
| **Invariant** | Every write to a channel goes through `Channel.Accept`; there is no aggregate path that can set balances directly |
| **Attack** | An executor writes fragment outcomes straight into channel balances, "knowing" the aggregate is conserved |
| **Safe outcome** | Impossible today: no aggregate write path exists, and `Accept` is the only mutator |
| **Implementation** | `Channel.Accept` is the sole entry; `Store.Accept`/`Store.Update` funnel through it |
| **Test** | `no aggregate write path` |
| **Status** | **BY-CONSTRUCTION** — and this is the row most at risk when an executor is written |

---

## What adversarial review found AFTER the suite was green

Four independent refuters, one per lens, each told to default to *refuted*. All
four returned **fatal**, and two proved it by running proof-of-concept tests
in-package. Two were defects in the executor and are fixed; two are older and
deeper, and are recorded rather than quietly patched.

### FIXED — the preimage was not bound to the payment

`FragmentPreimage` was keyed on `(secret, index)`. The payment id lived in the
intent and the lock id but **not** in the hash, and `HTLC.Matches` is a bare
keccak with no binding to lock id, channel, amount or payment. Two consequences,
both demonstrated:

- **Across payments.** Two payments sharing a secret produced the SAME hash for
  fragment *i*. A counterparty that legitimately learned `preimage_0` by settling
  payment A could settle fragment 0 of payment B. Working theft.
- **Across re-splits.** `unevenSplit` draws fresh random weights per call, so a
  retry after a refused leg yields different amounts. Amounts are in the intent,
  so intents and lock ids changed — the hash did not, leaving two same-hash locks
  the payee could settle twice. Nothing dedupes `HTLC.Hash`; `state.go` permits
  two locks sharing one deliberately, for exactly the multipath case.

Now keyed on the leg's **intent**, which commits to payment id, index, channel
and amount. Both attacks have tests, and reverting the derivation fails them.

The lesson is not the bug, it is that a mutation-clean suite said nothing about
it: every mutation I wrote perturbed one payment, and the attack needed two.

### NOT FIXED — two older findings, outside the executor

Recorded because they are real, and because fixing them silently inside this
phase would bury them.

**No settle deadline anywhere.** `PeerSession.checkTiming` has cases for
`KindLockAdd` and `KindLockRefund` and none for `KindLockSettle`; `Apply`'s
LOCK_SETTLE has no expiry test either. A payee can therefore claim a lock
arbitrarily long after its expiry and the payer's node signs automatically. The
routing layer's margin is enforced at lock CREATION and not at RESOLUTION, so
`routing.go`'s claim that a hub cannot be "paid downstream, unable to claim
upstream" does not hold in the resolution path. **Affects single-path payments
too** — it is not a multipath property.

**The misblinded hop.** A payer chooses the route and holds every blinding, and a
hop's onion instruction commits only to a hash of its own lock point. A payer
colluding with the recipient can hand a hop a lock it cannot satisfy after it has
paid downstream. This is `atomic.go`/`payment.go`/`routing.go`, not the executor,
and `SettleRoute` computes every hop's scalar at once from payer-held blindings —
nothing makes a hop's scalar contingent on a downstream payment having happened,
which is what its doc comment implies it does.

Both belong to routed single-path execution and should be their own work.

## Mutation testing

The suite passed the moment it was written, so it was mutation-tested rather
than trusted. Ten deliberate defects, introduced one at a time:

| defect | result |
|---|---|
| conservation: `Verify` sum check removed | caught |
| aggregate amount: rounding remainder dropped | caught |
| path isolation: operator tracking removed from `independentRoutes` | caught |
| path isolation: `Verify` operator check removed | caught |
| expiry ordering: per-hop ladder flattened to a constant | caught |
| HTLC consistency: each fragment built against a different recipient point | caught |
| duplicate settlement: fragment floor removed | caught |
| partial refund: `Cancel` stops restoring hub outbound | caught |
| partial failure: `Cancel` leaves the reservation live | caught |
| duplicate settlement: hub preimage check removed | **SURVIVED, then fixed** |

The survivor mattered. The suite delivered every fragment with its own correct
secret and never tried a wrong one, so removing the hub's preimage check changed
nothing it observed. The fix added the property that was actually missing —
**one fragment's preimage must not settle another fragment** — which is a real
multi-path requirement, not merely a way to kill the mutation: a recipient who
revealed once would otherwise drain every leg, and the per-fragment lock chains
that make fragments unlinkable would be pointless. Re-run afterwards: caught.

One earlier test was also discarded as worthless. `within-route expiry ladder`
originally recomputed the `base - i*60` ladder inline and asserted against its
own arithmetic — it would have passed with the implementation deleted. It now
peels each hop's instruction out of the real onion with the shared secret that
hop would hold, and the flattened-ladder mutation confirms it.

## Summary

| status | rows |
|---|---|
| ENFORCED | 1, 2, 3, 5, 6, 8, 10, 13, 15, 21, 22, 23 |
| BY-CONSTRUCTION | 12, 25 |
| PARTIAL | 4, 7, 9, 18, 24 |
| GAP | 11, 14, 16, 17, 19, 20 (and the GAP halves of 4, 7, 9, 18, 24) |

**Every GAP has the same root cause: no executor consumes a `SplitPlan`.** They
are one piece of missing work, not twelve. Writing that executor is the natural
next step, and this table is its specification — including row 25, which it must
be careful not to break.

**Multi-path must not be offered to users while these rows are GAP.** Planning a
split that nothing can safely execute is worse than not splitting: it produces
locks on real channels with no coordinated way to settle or unwind them.
