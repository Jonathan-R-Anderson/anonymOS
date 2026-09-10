# P14 — the staged load ramp, and the boundary it found

**The declared 10,000-channel / 30-second envelope does not hold. Measured, not
estimated: the current watchtower would need ~1,961 seconds per sweep, 65× the
interval.**

The local work is negligible. The constraint is entirely chain reads, and the
ramp is what made that visible — the two costs differ by four orders of
magnitude and only one of them was ever measured before.

## The ramp — every row measured at that stage

`P14_RAMP=1 go test ./internal/channel/ -run TestP14LoadRamp`

| channels | adopt | sweep | sweep/ch | heap | disk/ch |
|---:|---:|---:|---:|---:|---:|
| 100 | 198 ms | <1 ms | 1.99 µs | 2 MB | 526 B |
| 1,000 | 1.84 s | 3 ms | 2.57 µs | 4 MB | 526 B |
| 5,000 | 9.90 s | 23 ms | 4.54 µs | 8 MB | 526 B |
| 10,000 | 22.42 s | 38 ms | 3.80 µs | 12 MB | 526 B |

Nothing here is extrapolated. Each stage was built and swept at its own size.

**Two-watchtower envelope**, two independent 10,000-channel sweeps: 43 ms and
34 ms. Two watchtowers are two independent sweeps sharing no state — a single
20,000-channel sweep would be a different system and is not what was declared.

Disk is exactly 526 B per channel at every stage, so 10,000 channels is 5.1 MB.
Storage is not a constraint at this envelope and does not become one.

## The measurement that matters

The ramp runs against `FakeChain`, where a chain read is a mutex and a map
lookup. `Watchtower.Check` does **one `ReadChannel` per channel per sweep**
(`watchtower.go:236`), so in production each of those is an RPC round trip.

Measured against the real mainnet endpoint, five samples:

```text
single eth_call latency   min 0.174s   median 0.196s   max 0.208s
```

| approach | 10,000-channel sweep | vs. 30 s interval |
|---|---:|---|
| sequential, **as implemented today** | **1,961 s** (33 min) | **65× over** |
| batched 50/request (not implemented) | 94 s | 3.1× over |
| batched 200/request (not implemented) | 49 s | 1.6× over |

```text
reads/sec needed for 10,000 in 30s : 333
best measured batched throughput   : 205  (batch of 200)
shortfall even with batching       : 1.6×
```

**The boundary of the current implementation: ~153 channels per watchtower**, at
30 s and 196 ms per read. That is the number, and it is recorded rather than
tuned away.

> **CORRECTION, P14.5.** The 196 ms samples above were taken with fresh
> connections. Measured through a pooled client — which is what a long-running
> watchtower uses — the same `eth_call` is **34.4 ms**, putting the boundary at
> **~872 channels** and the 10,000 envelope 11× out of reach rather than 65×.
> The finding stands; the magnitude was pessimistic by 5.7×. See
> `doc/fixtures/p145-receipts-measurements.md`. Nothing here has been rewritten —
> the original numbers are what that run measured.

## What this does and does not mean

It does **not** say the design is wrong. It says the watchtower reads the chain
once per channel per sweep and nothing batches or caches those reads, so the
envelope's viability rests on work that has not been built. Batching to 200 gets
within 1.6×; caching unchanged channels, or watching events instead of polling
state, would change the shape entirely. None of that exists today.

It does mean the envelope must not be described as validated.

### The P12-8 detection evidence shares this gap

`TestDetectionAtProductionEnvelope` also uses `NewFakeChain()`. So the filed
detection evidence — 31 s at the 10,000-channel envelope — measures **local scan
cost against a zero-latency chain**, exactly as this ramp did before the RPC
measurement was added.

That does not make the recorded number wrong; it makes its scope narrower than
"detection". Real detection includes finding out what the chain says, and that is
the part costing 1,961 s.

**Nothing has been changed in response.** The `challengePeriod` is untouched, the
budget terms are untouched, and no evidence has been amended — this is reported,
not acted on.

## Classification

| measurement | value | class |
|---|---|---|
| adoption cost per channel | 2.24 ms at 10,000 | MEASURED |
| local sweep, 10,000 channels | 38 ms | MEASURED |
| local sweep, two watchtowers | 43 ms worst | MEASURED |
| heap at 10,000 channels | 12 MB | MEASURED |
| disk per channel | 526 B | MEASURED |
| single chain-read latency | 196 ms median | MEASURED |
| batched read throughput | 106–205 reads/s | MEASURED |
| **real sweep at 10,000 channels** | **1,961 s sequential** | **DERIVED** (measured latency × measured read count) |
| boundary of current implementation | ~153 channels | DERIVED |
| aggregate metrics overhead | not separable at this scale | NOT MEASURABLE |
| detection latency against a real chain | — | NOT MEASURED (the gap above) |
| DHT evidence read/write latency | — | NOT MEASURED (no DHT in the harness) |
| proof verification latency | — | NOT MEASURED |
| CPU under sustained load | — | NOT MEASURED (the ramp is not sustained) |

The metrics overhead row is honest rather than convenient: at 38 ms for 10,000
sweeps the counter increments are inside the noise, so the ramp cannot separate
them. Claiming "negligible" would be an assumption wearing a measurement's
clothes.

## Stop conditions

None fired. Disk stayed at 5 MB against 70 GB free, heap peaked at 12 MB against
22 GB available, no adoption failed, and every stage observed exactly its channel
count. The ramp stopped because it finished, not because anything broke.

---

# P14 baseline — DHT evidence, proof verification, sustained resources

Measured with the implementation unchanged. This is the "what the unoptimised
system actually does" baseline, to compare a redesigned chain-reading path
against later.

## Evidence store — node-side

Real `EvidenceStore` (seal, serialise, key derivation, index) over 500 writes and
256 reads of **real mainnet evidence records**.

| | min | median | p95 | max |
|---|---:|---:|---:|---:|
| write | 52.9 µs | **56.7 µs** | 164.2 µs | 676.6 µs |
| read | 64.7 µs | **68.7 µs** | 274.9 µs | 896.2 µs |

| | |
|---|---|
| record size | **9,236 bytes** (real proof, not synthetic) |
| concurrent throughput | **150,528 writes/sec**, 8 workers |

**Storage growth**, from the measured record size:

```text
one channel        9.0 KB raw   ->  13.5 KB after 6+3 erasure
10,000 channels   88.1 MB raw   -> 132.1 MB after 6+3 erasure
```

**NOT MEASURED: DHT network latency, erasure coding, I2P transport.** Those need
a reachable node. A local figure presented as DHT latency would be wrong by
orders of magnitude in the flattering direction — the same mistake the load ramp
made before the RPC measurement was added, and the reason it is called out here
rather than left implicit.

## Proof verification

BLS aggregate verification, against the consensus-spec vectors:

| | |
|---|---|
| single verify | min 69 µs, **median 872 µs**, p95 1.02 ms, max 1.03 ms |
| sustained, 1 core | **921.8 verifications/sec** |
| 4 workers | 2,666.9/sec |
| 16 workers | **6,505.9/sec** |
| heap | 1 MB |

Scaling across cores is close to linear to 4 and still improving at 16, so
verification is CPU-bound and parallelises — which matters, because it is the
one part of the trust path that cannot be cached away.

**The caveat that limits this number:** the available vectors are **4-key**
aggregates. A real sync committee is **512 keys**, and pairing cost is dominated
by aggregate size. So 921/sec is *not* a production rate — it is an upper bound
measured on the wrong size, and the 512-key figure is **NOT MEASURED** because no
512-key vector is installed. Quoting 921/sec as the watchtower's verification
capacity would be the flattering error again.

## Sustained mixed workload

20 seconds of BLS verification and evidence writes together:

| | |
|---|---|
| BLS verifications | 18,417 (**920.9/sec** — unchanged under load) |
| evidence writes | 1,541,454 (77,073/sec) |
| heap | 5 MB, **peak 19 MB** |
| sys memory | 39 MB |
| goroutines | 3 |

Verification throughput was identical sustained and in isolation, so the evidence
traffic did not contend with it at this scale.

**NOT MEASURED: disk I/O and RPC utilisation.** This workload touches neither —
the backend is in-memory and no chain reads occur — so reporting a number would
be reporting zero as though it were a measurement.

## Baseline summary

| measurement | value | class |
|---|---|---|
| evidence write, node-side | 56.7 µs median | MEASURED |
| evidence read, node-side | 68.7 µs median | MEASURED |
| evidence record size | 9,236 B | MEASURED |
| evidence throughput, 8 workers | 150,528 writes/s | MEASURED |
| BLS verify, 4-key | 872 µs median | MEASURED |
| BLS sustained, 1 core, 4-key | 921.8/s | MEASURED |
| BLS concurrent, 16 cores, 4-key | 6,505.9/s | MEASURED |
| sustained heap / peak | 5 MB / 19 MB | MEASURED |
| storage growth at 10,000 channels | 132 MB erasure-coded | DERIVED |
| BLS verify, **512-key** sync committee | — | NOT MEASURED (no vector) |
| DHT network write/read latency | — | NOT MEASURED (no node) |
| DHT aggregate throughput | — | NOT MEASURED (no node) |
| disk I/O under load | — | NOT MEASURED |
| RPC utilisation under load | — | NOT MEASURED |

Nothing in this section changes the earlier finding. The watchtower's constraint
remains chain reads at 196 ms each; every figure here is microseconds and none of
it is on that path.
