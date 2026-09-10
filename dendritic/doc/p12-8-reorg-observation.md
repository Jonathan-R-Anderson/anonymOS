# P12-8 reorg observation — running, unattended

**Term: `reorg depth`. Budgeted 30m. NOT MEASURED and will stay that way until
a reorganisation is actually observed.**

The last unvalidated term in P12-8. It cannot be measured by waiting, because
an absence of events does not bound the depth of one —
`ReorgObservation.AsEvidence` refuses to convert "no reorgs seen" into evidence,
deliberately, and nothing here changes that.

## A detection problem found while making this durable

The observer this replaces — and `internal/channel.ObserveReorgs`, which shares
its method — detects a reorganisation by noticing that a height it has **already
seen** now reports a **different hash**. That only fires if the head number goes
backwards or repeats between polls.

Post-merge mainnet reorgs are usually single-slot: block N is orphaned, a
different block N replaces it, and the chain immediately extends to N+1. A
poller watching only the head number sees N, then N+1, then N+2 — monotonic,
nothing repeated, **nothing detected**.

```text
what the old detector needs        what mainnet actually does
  head 25738700  hash A              head 25738700  hash A
  head 25738700  hash B  <- fires    head 25738701  parent = B  <- silent
```

So the earlier run's "0 reorgs in 442 blocks over 88 minutes" is **not evidence
that no reorganisation occurred**. It is consistent with the detector being
unable to see the common case.

### What the new observer does instead

Chain-linkage verification: every new head must name our recorded hash for the
previous height as its `parentHash`. A single-slot rewrite breaks that link on
the very next poll.

```text
head N+1 parentHash ──?── hash recorded for N
                    mismatch => N was rewritten
```

On a mismatch it walks back to the fork point to establish depth. It keeps both
detectors — the height-collision check still runs — so the new method can only
find **more** events than the old, never fewer. Nothing about what counts as
evidence changed.

Gaps are backfilled: if a poll ever skips a height, the missing blocks are
fetched and linked rather than assumed good. A gap too large to backfill is
written to `gaps.jsonl` as a hole in the record, not passed over.

### The in-repo function still has the old method

`internal/channel.ObserveReorgs` was **not** modified — an observation was
running against it and changing it mid-flight is its own hazard. It has filed no
evidence and will file none while this stands. **It should be brought up to
linkage detection before it is ever used to validate this term.**

## Running

| | |
|---|---|
| Service | `systemd --user`, `p12-reorg.service`, `Restart=always` |
| Lingering | enabled — survives logout and starts at boot |
| Binary | `~/p12-reorg/bin/p12reorg` (source: `storage-client/cmd/p12reorg`) |
| Data | `~/p12-reorg/data/` — outside `/tmp`, outside the repository |
| Poll | 4s against Ethereum Mainnet |
| Started | 2026-08-12T12:20:48Z |

Data files, all append-only except the atomically-rewritten state:

```text
blocks.jsonl   every canonical block observed: number, hash, parent, timestamp
events.jsonl   every reorg: height, depth, old hash, new hash, detection method
gaps.jsonl     heights that could not be observed live
state.json     counters + rolling window; rewritten atomically for restart
status.txt     human-readable summary
```

Restart-safety was verified rather than assumed: the service was stopped and
started, and the counters resumed (`restarts: 1`) instead of resetting.

## Alerting

`~/p12-reorg/check.sh`, from cron every 11 minutes, independent of any Claude
session. Each alert fires **once** — a marker file per alert — so a quiet
observation does not produce a repeating notification.

| condition | alert |
|---|---|
| any reorg observed | immediately, per event, with depth |
| observer stalled (no block in 15m) | immediately |
| service not active | immediately |
| milestones 24h, 72h, 7d, 14d, 30d | once each |

**"Still zero reorgs" is deliberately not an alert.** It is the expected state,
it is not news, and it is not evidence.

The stall and service-down alerts exist because a dead observer reports zero
reorgs indefinitely, which looks identical to a quiet chain. Silence had to be
made distinguishable from success.

The alert logic was tested against a simulated reorg and a simulated 25-hour
run before being relied on, including that re-running does not duplicate alerts.

### A false alarm the test itself caused

The first test ran `check.sh` with `HOME` redirected to a scratch directory, on
the assumption that this isolated it. It did not. **`notify-send` talks to the
D-Bus session bus, which does not follow `HOME`**, so the log line went to the
scratch copy while a real desktop notification — "REORG OBSERVED: 1 event(s),
max depth 2" — went to the operator. There had been no reorg.

The guard now ties notification to the canonical data directory:

```sh
CANONICAL="/home/bruns/p12-reorg/data"
[ "$D" = "$CANONICAL" ] && notify-send ... || echo "[dry run: suppressed]"
```

Re-running the exact test that leaked now suppresses the notification and says
so. Worth recording because the failure is general: **redirecting `HOME` does
not sandbox anything that speaks to a session bus, a socket, or a daemon**, and
a test harness for an alerting system is precisely where that bites.

## One candidate event, unresolvable from here

A scan of 352 recent blocks found exactly one empty slot:

```text
block 25,738,728   slot 14,975,949
                   slot 14,975,950   <- EMPTY
block 25,738,729   slot 14,975,951
```

An empty slot is either a **missed proposal** (nobody produced a block) or an
**orphaned block** (one was produced and lost a fork race — a reorg). An
execution RPC cannot tell them apart, because it serves only the canonical
chain and the orphaned block is simply absent from it. Two independent beacon
APIs return 404 for that slot, which is what both cases look like.

Resolving it needs a node that witnessed the fork live, or an explorer that
records orphaned blocks. **It is therefore not counted as an observed reorg**,
and it fell before this observer started (block 25,738,879) — inside the window
of the old, linkage-blind watcher, which is exactly the class of event that one
could not have seen.

## Standing

`reorg depth` is **NOT MEASURED**. The budget term, the evidence rules and the
deployment gate are unchanged. The observation runs until an event occurs; when
one does, its depth becomes the first real datum for this term, and one event
still will not be thirty.
