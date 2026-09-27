# P14 — aggregate-only metrics, and what they cost in fidelity

**Status: implemented and privacy-tested. Two requested metrics are NOT
MEASURABLE under the constraint and are recorded as such rather than
approximated quietly.**

The layer answers *"how economically and operationally viable is the channel
system?"* and is built so it cannot answer *"who paid whom, when, over which
channel?"* — not by policy, but because the types cannot carry the data.

## The boundary is structural

Every recording method takes amounts, counts, durations or small enums. None
takes a channel id, payment id, address, hash, nonce, preimage or route id — and
none takes a `string`, which is where those arrive in practice, hex-encoded and
looking harmless.

```go
Metrics.TipCompleted(amount *big.Int)          // yes
Metrics.TipCompleted(paymentID, channelID, …)  // cannot compile past the tests
```

Enforced by reflection over the method set, as an **allowlist** rather than a
blocklist: a blocklist has to predict what somebody adds next and will eventually
be wrong. Anything new fails until a human decides it is safe.

There is no event list — no ring buffer, no capped "last N payments for
debugging". A sequence of records is a payment history however short, and a short
one still correlates a tip with whatever was live at that moment.

## Classification of every requested metric

| metric | status | how |
|---|---|---|
| tips attempted / completed / failed / refunded | **MEASURED** | counters |
| total tip value, total channel value | **MEASURED** | `big.Int` accumulators |
| channel opens / closes | **MEASURED** | counters |
| cooperative vs disputed closes | **MEASURED** | counter per `CloseKind` |
| HTLCs created / settled / refunded | **MEASURED** | counters |
| routed payments, multi-path payments, legs | **MEASURED** | counters |
| executor failures | **MEASURED** | counter |
| watchtower observations / recoveries | **MEASURED** | counters |
| proof verification | **MEASURED** | verified/rejected counters |
| DHT evidence reads/writes + bytes | **MEASURED** | counters; no keys accepted |
| RPC volume | **MEASURED** | counter |
| CPU / memory / disk | **MEASURED** | last sample + peak, not a series |
| aggregate tips per channel cohort | **MEASURED** | histogram observed at close |
| aggregate settlement frequency | **MEASURED** | interval histogram |
| aggregate channel utilisation | **DERIVED** | tip value ÷ channel value |
| HTLC utilisation | **DERIVED** | settled ÷ created |
| routing success rate | **DERIVED** | completed ÷ attempted |
| aggregate open/close costs | **DERIVED** | counts × measured gas, `p14-economics.md` |
| aggregate value throughput | **DERIVED** | tip value ÷ elapsed |
| **mean** channel lifetime | **DERIVED** | Little's Law — see below |
| **distribution** of channel lifetimes | **NOT MEASURABLE** | needs per-channel timestamps |
| per-channel anything | **NOT MEASURABLE** | that is the thing being prevented |

## Channel lifetime without timestamps

The obvious implementation is a per-channel opened-at, and that is a per-channel
analytics table — the forbidden thing. `Channel` holds no timestamp today, so
adding one would exist *only* for metrics.

Little's Law gives the mean without dating anything. For a system in steady
state, mean time in system = number in system ÷ departure rate:

```text
mean lifetime = channels currently open ÷ closes per second
```

Two counters and a gauge. Nothing remembers when any particular channel opened,
and the substitution is exact for the mean rather than an approximation of it.

**What is lost:** the distribution. Percentiles, medians and tails are not
recoverable this way, and producing them needs individual channels dated —
which is why the distribution row above says NOT MEASURABLE rather than
offering a worse number under the same name.

**What it assumes:** steady state. During a ramp-up or a mass close the figure is
wrong in a knowable direction — with opens outpacing closes it *understates*
lifetime. It is a fleet statistic, not a per-channel one, and reading it as
though it were the latter is the mistake to avoid.

## Deliberate coarseness

Histogram buckets double: 1, 2, 4, 8 … 512. Fine buckets over a small population
are a fingerprint. "Exactly 37 tips" identifies a channel in a way "between 32
and 64" does not, and a test asserts no bucket is narrow enough to pin an exact
count.

Resource usage keeps the last sample and the peak, never a series. A series
timestamped beside payment counters lets an observer align a load spike with the
moment a payment happened — a timing side channel assembled from otherwise
harmless numbers.

## Privacy tests

| test | proves |
|---|---|
| `TestMetricsAPICannotAcceptIdentifiers` | no method accepts an identifying type |
| `TestSnapshotCarriesNoIdentifyingFields` | no output field is an identifier |
| `TestSerialisedMetricsContainNoIdentifiers` | the JSON has no 40/64-char hex run, no `0x`, no long opaque strings |
| `TestMetricsHoldsNoPerEventStorage` | no map, no slice on the collector |
| `TestRestartingMetricsCreatesNoHiddenHistory` | a fresh collector is empty; no string/writer field could persist |
| `TestAggregationCannotReconstructOrdering` | two orderings of the same events give byte-identical output |

Correctness under load is covered separately: concurrency, mixed
success/fail/refund, multiple channels, multiple recipients, routed and
multi-path.

### Mutation-tested

Seven deliberate breaches of the boundary, all caught:

| breach | result |
|---|---|
| a method taking a channel id (`[32]byte`) | caught |
| a method taking a `string` label | caught |
| a method taking an `Address` | caught |
| a per-event `[]string` on the collector | caught |
| a `map[[32]byte]uint64` on the collector | caught |
| a `channel_id` field in the snapshot | caught |
| a `storePath` field on the collector | caught |

One of those initially reported as surviving; the pattern had failed to apply
because gofmt realigned the target line, so the mutation was never made. Re-run
against the real text, it was caught. A mutation that does not apply reports as
a survivor and looks exactly like a hole in the tests.

## Integration — the production call sites

Wired into the real paths. Each row states what is in scope at that boundary and
what actually crosses.

| # | event | metric | value supplied | why no identifier is needed | kind |
|---|---|---|---|---|---|
| 1 | `Coordinator.Pay` reaches a real attempt | `TipAttempted` | nothing | the question is how many, not which | MEASURED |
| 2 | proposal refused locally | `TipFailed` | nothing | a terminal outcome; the reason narrows *which* | MEASURED |
| 3 | peer rejects | `TipFailed` | nothing | the reject code would narrow it | MEASURED |
| 4 | transport fails | `TipFailed` | nothing | outcome unknown, attempt terminal | MEASURED |
| 5 | `KindPay` applied | `TipCompleted` | `tr.Amount` | the amount is already in hand; the channel is not passed | MEASURED |
| 6 | `KindLockAdd` applied | `HTLCCreated` | nothing | lock id and hash stay in the transition | MEASURED |
| 7 | `KindLockSettle` applied | `HTLCSettled` | nothing | the preimage never leaves the transition | MEASURED |
| 8 | `KindLockRefund` applied | `HTLCRefunded` | nothing | as above | MEASURED |
| 9 | `Forwarder.Forward` | `RoutedPayment` | nothing | both channels and the hash are in scope; none crosses | MEASURED |
| 10 | `Executor.Lock` | `MultipathPayment` | leg **count** | one payment, N legs — never which legs | MEASURED |
| 11 | executor leg error | `ExecutorFailure` | nothing | which leg failed identifies the leg | MEASURED |
| 12 | `Executor.Settle` | `TipCompleted` | delivered **total** | per-leg state stays inside `Summarise` | MEASURED |
| 13 | `Watchtower.Sweep` per channel | `WatchtowerObservation` | nothing | `id` is in the loop variable and not passed | MEASURED |
| 14 | challenge submitted | `WatchtowerRecovery` | nothing | the tx hash stays in the `Watch` result | MEASURED |
| 15 | `EvidenceStore.Put` | `EvidenceWrite` | byte count | `e.Key()` goes to the backend only | MEASURED |
| 16 | `EvidenceStore.Get` | `EvidenceRead` | byte count | `key` is a parameter, not forwarded | MEASURED |
| 17 | evidence backend error | `EvidenceFailure` | nothing | the key would identify the record | MEASURED |

The evidence store lives in `ethproof`, which must not import `channel`. It
reports through `ethproof.EvidenceMetrics` — three methods taking `int` — so the
interface **cannot express** a key, a channel id or a hash.

### Three bugs the real-path tests found

Worth recording, because all three would have passed a collector-level suite.

**Nil metrics panicked the payment path.** `m.bump(&m.counter)` evaluates
`&m.counter` *before* `bump` is entered, and taking a field address on a nil
pointer panics — so the guard inside `bump` was unreachable. Every
un-instrumented deployment would have panicked on its first payment. Only a
real-path test hits it, because a node without a collector is the ordinary case
there. The guard now lives in each method.

**Locally-refused payments were never terminal.** A non-conserving amount is
refused at `Propose`, before the peer is contacted, so it counted as attempted
and never as failed — leaving `attempted > completed + failed` with nothing
showing where the difference went.

**`HTLCCreated` fired at attempt time.** A 3-leg split with one dead
counterparty reported three HTLCs where two existed. It now counts on
application.

### Retries are not double-counted

`Pay` answers an already-applied intent from its record and returns before the
counters, so a retry after an ambiguous outcome — the ordinary case — adds
nothing. Asserted directly.
