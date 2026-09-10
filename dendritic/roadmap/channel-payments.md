# Recipient-Hosted Lightning Tipping — Implementation Plan

**This file holds only unfinished work.** Anything built and tested gets deleted from it, so its length is the remaining work and nothing else.

Everything marked **read** was confirmed against the code, contract, or live cluster on 2026-08-11. Everything else is a proposal.

The goal, in one sentence:

> **Tipping should support both direct and routed off-chain payments while minimizing on-chain transactions, without requiring the tipper to operate a Lightning node.**

---

# Already shipped — do not re-plan these

A pointer list, not a plan. Read the file's own comments before changing it.

| Where | What it does |
|---|---|
| `storage-client/internal/channel/state.go` | **P1.** The unified state model: `Address`, contract-order party sorting, `DeriveChannelID`, `StateDigest`, EIP-191 `RecoverSigner`, `HTLC`, `State`, `SignedState`, `Channel.Accept`, `ReplayKey` |
| `storage-client/internal/channel/state_test.go` | The same, against golden vectors taken from outside the package |
| `proof-of-facilitation/contracts/ChannelManagerV2.sol` | **P2.** V1 plus conditional payments: `htlcRoot`, a digest that commits to it, `claimLock`, `expireLock`, lock-aware conservation and settle |
| `proof-of-facilitation/test/ChannelManagerV2.test.ts` | 13 tests, one per guarantee, including a routed payment that leaves the intermediary whole |
| `proof-of-facilitation/scripts/v2-golden-vectors.ts` | Regenerates the vectors the Go tests freeze |
| `storage-client/internal/channel/store.go` | **P3.** The durable, money-bearing store: one interpretation of state, complete persistence including locks, monotonic across restart, fsync-ordered writes, fail-closed on a record it cannot verify |
| `storage-client/internal/channel/store_test.go` | 15 tests, including six ways of tampering with a stored record that each stop the node |
| `doc/channel-payment-protocol.md` | **P4.** SCPP/1 — the specification |
| `storage-client/internal/channel/transition.go` | §4.2: `StateTransition`, deterministic `Apply`, `Matches`, `State.Equal` |
| `storage-client/internal/channel/scpp.go` | §3: envelope, ten message types, canonical encoding (shares the store's encoders), length-prefixed framing, the closed reject-code set |
| `storage-client/internal/channel/session.go` | §6–§8: `PeerSession` — propose, handle, accept, reject, resync, conflict, resume |
| `storage-client/internal/channel/{transition,session}_test.go` | The handshake, determinism, the crash table, and conflict evidence — driven through two nodes on separate disks that exchange only serialised frames |
| `storage-client/internal/channel/chain.go` | **P5-1.** `ChainReader`, `OnChainChannel` with an unexported guard, an RPC reader for `channels(bytes32)`, and `FakeChain` |
| `storage-client/internal/channel/coordinator.go` | **P5-2.** `Coordinator` — adoption, idempotence, `Pay`, `Handle`, `Recover`, `Balances`; the only implementation of `Committer` in production |
| `storage-client/internal/channel/transport.go` | **P5-3.** `StreamPeer` and `Server` — frames over a stream, and nothing else |
| `storage-client/internal/channel/transport_test.go` | Two nodes over real TCP: payments, a connection dying after the peer committed, retry-pays-once, oversized frames, garbage, unreachable peers |
| `storage-client/internal/channel/api.go` | **P5-4.** The HTTP surface: list, read, adopt, pay, recover. Translates requests into coordinator calls and nothing else |
| `storage-client/internal/channel/api_test.go` | The full stack through HTTP, the three outcomes, idempotence, and that a caller cannot smuggle in a state |
| `storage-client/internal/channel/payout.go` | **P6.** `PayoutWorker` — policy, phases, chain-first settlement, `submitted` ≠ `confirmed` |
| `storage-client/internal/channel/chainwriter.go` | **P6/P7-a.** `ChainWriter` — hand-rolled ABI encoding for checkpoint, close, claim, expire, **approve, openChannel, deposit**; selectors frozen against the compiled ABI |
| `storage-client/internal/channel/payout_test.go` | The settlement crash table, repeated checkpoints, and the clone-regression guard |
| `storage-client/internal/channel/preimages.go` | **P7-b.** The preimage vault: secrets on disk BEFORE the settle that revealed them is signed |
| `storage-client/internal/channel/routing.go` | **P7-b.** `Forwarder` — expiry laddering, `SweepClaimable`, `RefundExpired`. Not `hub.go`: nothing here holds value |
| `storage-client/internal/channel/routing_test.go` | A → Hub → B over real sockets: success, expiry cascade, hub disappears, preimage survives a crash |
| `storage-client/internal/channel/locks.go` | **P7-c.** `LockView`, `Exposure` — six statuses, derived by the node so the panel never decides |
| `storage-client/internal/ui/receiving.go` | **P7.** The recipient's panel, against a four-method interface |
| `storage-client/internal/ui/receiving_adapter.go` | The only file in `ui` that knows what a channel is |

```text
P1  Unified V2 state model            COMPLETE
P2  ChannelManagerV2 + HTLC           COMPLETE — built and tested, NOT deployed
      checkpoint                      +  draw down without closing
P3  V2 persistent store               COMPLETE
P4  SCPP/1 peer payment protocol      COMPLETE
P5  Payment node integration          COMPLETE
P6  Settlement                        COMPLETE
P7  Receiving / recipient ops         COMPLETE
      panel, balances, policy         +
      settle now, close, conflicts    +
   a  channel opening                 +  approve + openChannel, crash-safe
   b  multi-hop routing               +  A -> Hub -> B, preimage vault
   c  pending HTLC visibility         +  six statuses, exposure split three ways
   d  payment history                 +  audit only; unknown -> real outcome
P8  Browser / wallet integration      COMPLETE
   a  wallet connection             +  account switch stops the flow
   b  channel opening / funding     +  tipper funds; id derived before sending
   c  MetaMask signing              +  EIP-191 + low-s, checked before use
   d  tip initiation                +  browser-generated intent, safe retry
   e  off-chain state signing       +  browser builds the digest it signs
   f  crash / recovery behaviour    +  unknown resolves against the real state
P9  Award integration                 COMPLETE
P10 Watchtower and monitoring         COMPLETE - challengePeriod = 8h (provisional)
      DERIVES challengePeriod for P12
P11 Backup and state availability     COMPLETE
P12 Ethereum data layer + deploy      COMPLETE - DEPLOYED to mainnet, gate satisfied
   1  determine required eth data   +  one read: channels(bytes32). ~2.7 GB/yr, O(1) in channels
   2  measure real proofs           +  full chain verified on mainnet; 36.8 KB/channel, ~210ms
   3  DHT evidence format + persist +  verified-only, self-verifying offline
   4  local index                   +  pointer map, rebuildable, holds no values
   5  native light client            +  MAINNET-VERIFIED (see 5.9)
      5.1 checkpoint                  +  sealed anchor, chain+fork bound domain
      5.2 SSZ / merkleisation         +  zero-hash padding, gindex branches
      5.3 beacon headers              +  structural rules; BLS behind one iface
      5.4 BLS sync committees         +  blst v0.3.17 pinned, wrapper built
          24/24 consensus-spec vectors pass (v1.5.0). blst's own
          FastAggregateVerify does NOT subgroup-check pubkeys - proven, an
          infinity key is accepted - so the wrapper KeyValidates every key.
          Only file importing blst. CGO_ENABLED=0 fails to build, on purpose.
          Audit NOT independently verified: recorded, not claimed.
      5.5 committee rotation          +  a committee never authenticates its own
          arrival; committee taken from the trusted state, by SIGNING period.
          Atomic - a rejected update mutates nothing. Fork layout travels on
          the state: Electra REFUSES rather than guessing its gindices.
      5.6 finality                    +  Observed / Verified / Finalized are
          separate FIELDS, not labels - an optimistic update has no code path
          to the finalised one. Levels compare by ROOT not slot (a reorg puts
          two headers at one slot). Finality is idempotent and never backward.
      5.7 execution payload bridge    +  finalised beacon body -> execution_branch
          -> payload -> its OWN stateRoot. No comparison against an
          RPC-supplied header: a comparison is a step that can be skipped, so
          the fabricated root is simply never in scope. Requires FINALIZED,
          not merely verified.
      5.9 LIVE MAINNET VALIDATION     +  COMPLETE - doc/fixtures/p12-5.9-mainnet-run.md
          Checkpoint: 3 independent operators, unanimous. Beacon transport:
          publicnode. Execution: Alchemy, untrusted.
          PROVEN WITH REAL MAINNET DATA:
            1 finality ADVANCED 14975552 -> 14975584, roots DIFFER,
              1 instrumented BLS call, 501/512 participation.
              Old header demoted to `observed`.
            2 eth_getProof MPT-verified against the CONSENSUS-authenticated
              stateRoot (never the RPC's). Fabricated root rejected.
            3 evidence persisted to the DHT, reloaded, independently
              re-verified; a tampered stored record refused.
          THREE REAL DEFECTS FOUND AND FIXED: Fulu gindices (spec-sourced,
          not inferred); signing domain fork version by signature slot;
          decoder was discarding execution payload + branch.
          THE NEAR-MISS: an earlier run reported "finality applied" with ZERO
          BLS calls - idempotent path, and TrustLevelOf comparing a header to
          itself. Only counting verifier calls exposed it. A nil error is not
          evidence a signature was checked.
      5.8 HeaderVerifier integration  +  AnchorNone replaced by the native client.
          The light client HOLDS authenticated roots; evidence must match one -
          never the reverse. No best-effort mode: an unsynced client REFUSES
          rather than deferring to the RPC. Consumers unchanged.
   6  watchtower integration        +  drop-in ChainReader; no RPC fallback
   7  failure testing               +  each layer fails closed independently
   8  production measurements -> final challengePeriod
      GATE ORDER: canonicality -> storage proofs -> challenge timing -> deploy
      no amount of proof verification compensates for an untrusted header
P13 Full security testing             PARTIAL
      direct channel table   12/12  p13_test.go
      HTLC table              9/9   p13_test.go
      routed payment table    9/9   p13_routed_test.go
      multi-path table       34/34  p13_multipath_test.go  ALL ENFORCED
      real V2 contract        BLOCKED ON DEPLOYMENT (P12-8)

      THE EXECUTOR EXISTS. multipath_exec.go drives a split through
      Coordinator.Pay -> SCPP/1 -> Channel.Accept, one leg at a time.
      PaymentFromSplitPlan converts a real Split() output, deriving each
      fragment's expiry from ITS OWN hop count and bounding all of them by one
      payment deadline. It keeps no ledger: the journal records what was
      ATTEMPTED, and status is always re-derived by asking each channel
      AppliedAt(intent) — so recovery reads the signed record rather than the
      previous process's intentions.

      ADVERSARIAL REVIEW FOUND A REAL THEFT after the suite was green and 16
      mutations were caught. FragmentPreimage was keyed on (secret, index), so
      two payments sharing a secret produced the same fragment hash: a
      counterparty that learned preimage_0 from one payment could settle
      fragment 0 of another. Same root cause let a re-split reuse a hash while
      intents changed. Now keyed on the leg's INTENT (payment id + index +
      channel + amount). Both attacks have tests; reverting fails them.

      Every mutation I had written perturbed ONE payment. The attack needed
      two, which is why a mutation-clean suite said nothing about it.

      TWO OLDER FINDINGS RECORDED, NOT FIXED — both single-path, both outside
      this phase:
        - no settle deadline anywhere: checkTiming has no KindLockSettle case,
          so a payee can claim a lock long after expiry. The routing margin is
          enforced at lock CREATION, not at RESOLUTION.
        - the misblinded hop: the payer picks the route and holds every
          blinding, and SettleRoute computes all hops' scalars at once, so
          nothing makes a hop's scalar contingent on a downstream payment.
      See doc/p13-multipath-security-table.md.

      MULTI-PATH IS PLANNING ONLY. SplitPlan is referenced nowhere outside
      multipath.go and its own test — nothing executes a plan. So every
      property needing fragments coordinated AT SETTLEMENT TIME (partial
      settlement, partial refund, aggregate replay, crash recovery) has no
      implementation. Those rows are GAPS and their tests pin the absence
      mechanically: writing SplitPlan.Execute FAILS the suite and forces the
      table to be revisited. All gaps share one root cause — the missing
      executor — and doc/p13-multipath-security-table.md is its specification.

      MULTI-PATH MUST NOT BE OFFERED TO USERS while those rows are GAP.
      Planning a split nothing can safely execute is worse than not splitting:
      it puts locks on real channels with no coordinated way to settle them.
P13.5 Routing corrective phase        COMPLETE
      Created because the P13 implementation audit surfaced two claims about
      pre-existing single-path routing. Investigating them found a THIRD, and
      the third was the worst.

      F1 SETTLEMENT TIMING           REAL DEFECT, FIXED
         checkTiming had no KindLockSettle case, so a late settlement fell
         through to accept and the payer's node signed it. The contract is the
         authority and draws the line exactly:
             claimLock  : block.timestamp >= expiry  -> revert
             expireLock : block.timestamp <  expiry  -> revert
         So the off-chain machine was co-signing states the chain would have
         reverted. Now refused, with skew AGAINST the settler, mirroring the
         refund rule. The two leave a 2*skew band where neither may act, which
         is deliberate: both valid at once is a race over one lock.
         Also applied at PROPOSE for settles, because signing is where the
         damage lands — a doomed proposal poisons the nonce via I4 and the
         peer's later legitimate transition is refused ALREADY_SIGNED_NONCE.
         Narrowed to settles on purpose: minLockWindow is the ACCEPTOR's policy
         and refund rejection semantics are pinned by an existing test.

      F2 MISBLINDED HOP              NOT the vulnerability described — but the
                                     full trace found a DIFFERENT one, fixed.
         Every clause of the claim is true about SettleRoute. The conclusion is
         not, because SettleRoute HAS NO PRODUCTION CALLER. A hop claims through
         Forwarder.ClaimUpstream, which looks up a hash PREIMAGE from the vault
         keyed by the incoming lock's hash — so the upstream claim is contingent
         on the downstream reveal by construction. The point-based LockChain is
         adaptor machinery that is built but not wired in, which is exactly why
         it reads as dangerous in isolation. A test now fails if SettleRoute
         gains a production caller.

         WHAT THE FULL TRACE FOUND INSTEAD: the per-hop shared secret was
         derive(seed, nodeID) — no ephemeral key. So a payer reusing a seed
         handed the SAME hop the SAME secret on two different payments, and that
         hop could peel an onion it was never given: correlating the payments and
         reading the second's routing instruction. Verified with two payments
         under one seed.

         That defeats exactly what the ephemeral key exists for. Packet says
         "EphemeralPublicKey is fresh per payment. Reusing one links every
         payment sent under it" — the key WAS fresh, and the secrets that gate
         peeling ignored it, so freshness bought nothing.

         Fixed at the derivation, not with a rejection: HopSharedSecret(seed,
         ephemeral, nodeID), exported so five open-coded copies became one. The
         ephemeral comes from z (crypto/rand per plan) so it is per-payment even
         under seed reuse, and it matches the shape of the ECDH that replaces
         this placeholder. PRIVACY/CORRELATION, not theft — the commitments still
         differ, so the peeking hop cannot claim.

         Mutation testing found two further UNTESTED properties: dropping the
         node id (every hop on a route shares one secret and reads the whole
         path) and dropping the seed (the ephemeral is public, so an observer
         could derive every secret). Both now pinned. Cross-payment isolation had
         been tested; WITHIN-payment isolation had not.

      F3 LOCK-ID REUSE               REAL THEFT, FIXED. Found while
                                     investigating F1/F2.
         SweepClaimable keyed its claim intent on the lock ID alone, for
         crash-idempotency. But a lock ID is unique only among PENDING locks:
         Channel.Accept dedupes over st.Pending, so a resolved lock's id frees
         up. Reuse it and the sweep recomputes the same intent, Pay answers
         "already applied", and the hub pays downstream while believing it
         claimed upstream. Verified as a working exploit. The intent now binds
         channel + id + hash + amount + expiry, which keeps the crash property
         (all read off the pending lock) and separates instances.

      The pattern across P13 and P13.5, worth stating once: every real defect
      was authorization or idempotency material keyed on something REUSABLE —
      an index, a lock id — and every one was invisible to single-payment
      mutation testing. Two payments, or two lock instances, were required.

P14 Economic / load testing           IN PROGRESS
      economics: BREAK-EVEN MEASURED   doc/fixtures/p14-economics.md
      metrics:   WIRED INTO PRODUCTION  doc/fixtures/p14-metrics.md
                 17 call sites: coordinator, forwarder, executor, watchtower,
                 evidence store. Aggregate-only at every one.
      load:      RAMP MEASURED — ENVELOPE DOES NOT HOLD
                 doc/fixtures/p14-load-ramp.md

                 channels   adopt    sweep   heap   disk/ch
                      100   198ms      <1ms   2MB     526B
                    1,000   1.84s       3ms   4MB     526B
                    5,000   9.90s      23ms   8MB     526B
                   10,000  22.42s      38ms  12MB     526B
                 two watchtowers at 10,000 each: 43ms / 34ms

                 Every stage measured at its own size; nothing extrapolated.
                 Local work is NEGLIGIBLE — 38ms is 0.13% of the 30s interval.

                 BUT Watchtower.Check does ONE ReadChannel PER CHANNEL PER
                 SWEEP (watchtower.go:236), and the ramp runs on FakeChain
                 where that is a map lookup. Measured against real mainnet:

                   single eth_call latency      196ms median (5 samples)
                   10,000 sequential reads    1,961s  = 65x the 30s interval
                   batched 200/req (unbuilt)     49s  = 1.6x over
                   reads/sec needed              333; best measured 205

                 BOUNDARY OF THE CURRENT IMPLEMENTATION: ~153 CHANNELS per
                 watchtower. Recorded, not tuned away.

                 The design is not wrong — nothing batches or caches chain
                 reads, and that work does not exist. The ENVELOPE MUST NOT BE
                 CALLED VALIDATED.

                 BASELINE MEASURED (same fixture, second half):
                   evidence write  56.7us median   read 68.7us median
                   evidence record 9,236 B -> 132 MB erasure-coded at 10,000
                   evidence writes 150,528/sec across 8 workers
                   BLS verify      872us median; 921/sec 1 core;
                                   6,506/sec across 16
                   sustained 20s   heap 5 MB, peak 19 MB, 3 goroutines
                 NOT MEASURED: 512-key BLS (vectors are 4-key, and pairing cost
                 scales with aggregate size, so 921/sec is an upper bound on the
                 wrong size), DHT network latency/throughput (no reachable
                 node), disk I/O, RPC utilisation.

                 None of it is on the critical path: every figure is
                 microseconds and the constraint is still 196ms chain reads.

                 P12-8's detection evidence shares the gap: its envelope test
                 also uses NewFakeChain, so the filed 31s measures local scan
                 against a zero-latency chain. The number is not wrong; its
                 SCOPE is narrower than "detection". NOTHING WAS CHANGED in
                 response — challengePeriod, budget terms and evidence are all
                 untouched.

      Measured against the real compiled contract and the real EVM, because
      nothing had measured it and the roadmap asks for this "rather than
      guessing":

        erc20 transfer, warm       34,565 gas    (cold: 51,665)
        openChannel               152,149
        deposit                    72,180
        closeCooperative          117,373
        closeUnilateral           143,869
        challenge                  68,820
        settle                     65,586

        channel lifecycle         341,702 gas -> BREAK-EVEN 10 TIPS
        worst case (disputed)     502,604 gas -> BREAK-EVEN 15 TIPS

      100 tips through one channel cost 90.1% less than 100 on-chain transfers,
      and that percentage is IDENTICAL at every base fee P12-8 observed
      (0.070-0.139 gwei) because both sides scale linearly. THE BREAK-EVEN IS A
      PROPERTY OF THE CONTRACT, NOT THE FEE MARKET — gas prices change what a
      tip costs, not how many tips justify a channel.

      The roadmap's own guess ("5 ANON once -> ERC-20; 5 ANON x 100 ->
      channel") holds, and the crossover is 10.

      NOT measured, and not claimed: hub routing (a question about counterparty
      COUNT, and it needs the hub's capital cost, which is not gas), the capital
      locked in a channel, failed-transaction overhead, and L2.

      METRICS: aggregate-only, and the boundary is STRUCTURAL. Every recording
      method takes amounts, counts, durations or small enums; none takes a
      channel id, payment id, address, hash, nonce, preimage, route id — or a
      string, which is how those arrive in practice. Enforced by reflection over
      the method set as an ALLOWLIST, so anything new fails until a human
      decides it is safe. No event list of any kind: a sequence of records is a
      payment history however short, and a short one still correlates a tip with
      whatever was live at that moment.

      CHANNEL LIFETIME WITHOUT TIMESTAMPS. The obvious implementation is a
      per-channel opened-at, which is the forbidden analytics table; Channel
      holds no timestamp today, so one would exist only for metrics. Little's
      Law gives the mean from a gauge and a counter:

          mean lifetime = channels open / closes per second

      Exact for the mean, assumes steady state, and LOSES THE DISTRIBUTION —
      percentiles need individual channels dated, so the distribution is
      recorded NOT MEASURABLE rather than approximated under the same name.

      Seven deliberate breaches of the boundary were mutation-tested and all
      caught (channel-id parameter, string parameter, Address parameter,
      per-event slice, per-channel map, snapshot id field, persistence path).
      One first reported as surviving because gofmt had realigned the target and
      the mutation never applied — a mutation that fails to apply reports as a
      survivor and looks exactly like a hole.

      INTEGRATION FOUND THREE BUGS a collector-level suite could not:
        - nil metrics PANICKED the payment path. m.bump(&m.counter) takes a
          field address before bump runs, so the nil guard inside bump was
          unreachable; every un-instrumented deployment would have panicked on
          its first payment.
        - a locally-refused proposal was counted as attempted and never as
          failed, leaving attempted > completed + failed.
        - HTLCCreated fired at attempt time, so a 3-leg split with one dead
          counterparty reported three HTLCs where two existed.

      The evidence store is in ethproof, which must not import channel, so it
      reports through a three-method interface taking ints — it CANNOT express
      a key, a channel id or a hash.

      NEXT: throughput, routing overhead, watchtower workload, DHT evidence
      workload, the 10,000-channel envelope, and CPU/memory/disk/RPC.
P14.5 Watchtower scaling (C+E)        IMPLEMENTED, TESTED, MEASURED
      doc/p14-watchtower-scaling-design.md (design)
      doc/fixtures/p145-receipts-measurements.md (pre-implementation)
      doc/fixtures/p145-implementation.md (the build)

      SHAPE: authenticate the finalised block -> test its AUTHENTICATED bloom ->
      on a hit, rebuild the receipts MPT and require its root to equal the
      authenticated receiptsRoot -> only then read the channel id from
      topics[1]. New: RLP encoder, MPT builder, fork-aware execution-header
      encoder (the decoder was NOT reused as an encoder), restart-safe
      ChainFollower, EventChainReader.

      UNCHANGED, DELIBERATELY: ChainReader, watchtower.go, evidencereader.go,
      the contracts, DefaultWatchInterval (30s), challengePeriod, the
      10,000-channel envelope. The watchtower still calls ReadChannel once per
      channel per sweep; only the cost changed.

      THE INVARIANT IS PINNED: a contract test asserts every writer of ch.*
      emits with `bytes32 indexed id`, that the event set EQUALS the Go
      decoder's list, and — via two injected mutators — that the check can
      actually fail.

      MEASURED CAPACITY: 215ms per sweep at 10,000 channels with a contract
      busy enough that the bloom saves NOTHING, vs 344s for the status quo
      measured the same way. ~1,600x.

      MEASUREMENT A: an active contract is in every block. WETH and USDC skip
      0%; ours (idle) skips 75%. The bloom was never load-bearing.
      MEASUREMENT B: the provider refuses at ~6 receipt fetches/sec and
      recovers after ~2s. Steady state is 0.08/sec — two orders of headroom.
      MEASUREMENT C: gas caps a 30s window at ~520 closes, so 10,000-in-a-window
      is unreachable; 10,000 events cost 42ms to build and 38ms to authenticate.
      The worst case degrades to the status quo (N changed channels = N reads),
      which this design does not improve and never could.

      THE FINDING THAT NEEDS A DECISION: real catch-up is 243ms/block INCLUDING
      rate-limit retries — 1h = 1m13s, 24h = 29m, 1 week = 3h24m. That is 13x
      the design estimate, entirely because of the provider limit. The budget
      allows 4h for Outage, so a week-long outage consumes 85% of it while the
      watchtower is fail-closed. NOTHING WAS CHANGED IN RESPONSE.

      TWO BUGS THE LIVE RUNS FOUND (not review): a rate-limit detector that
      scanned response bodies and matched "429" inside block hashes, turning
      healthy batches into a fake permanent outage; and an adaptive batch that
      gave up at size 1 instead of waiting.

      MUTATION-TESTED: 8 breaks of the safety properties, 7 caught immediately.
      The survivor was the header hash check — removing it broke nothing,
      because a forged bloom makes the follower SKIP a block and a skipped
      block is never examined. Test added; now caught.

P14.6 Local execution node            INVESTIGATION ONLY — doc/p146-local-execution-node.md
      Question: can a locally run execution node remove the provider
      rate-limit dependency during catch-up, with the beacon light client
      still the source of canonicality?

      NOTHING DEPLOYED OR CONFIGURED. No code changed. Watchtower,
      challengePeriod, evidence rules and the deployment gate untouched.

      ARCHITECTURE: already correct. AuthenticateReceipts/AuthenticateHeader/
      VerifyProof do not know who supplied the bytes, so swapping suppliers is
      a config change (ETH_RPC_URL), not a code change.

      THE PRIZE: 90% of the measured 243ms/block catch-up is rate-limit
      WAITING, not work. Actual work is 24.5ms/block. A local node projects
      1 week at ~5-10 min instead of 3h24m — 4% of the outage budget instead
      of 85%. PROJECTED, not measured.

      BLOCKER 1 — NO MACHINE CAN HOST IT. Measured: prod has 27GB free of
      193GB; workstation root has 64GB of 1.8TB; /mnt/backup has 1.7TB but is
      NTFS-over-FUSE on a SATA SSD and holds the backups. A full node needs
      ~1.2TB and grows 14GB/week. This is a hardware purchase (2TB NVMe,
      32GB RAM, 8 cores), not a configuration.

      BLOCKER 2 — A PLAIN FULL NODE BREAKS THE EXISTING PROOF PATH. Full
      nodes keep 128 blocks of state. client.go:191 requests proofs at the
      AUTHENTICATED FINALISED block (64-96 back), which fits — until finality
      STALLS, when the finalised block falls arbitrarily far behind and the
      state is gone. The failure is correlated with exactly the network stress
      that makes a watchtower necessary. Alchemy hides this today by running
      archive-grade infrastructure. Fix: geth v1.17+ --history.trienode=N, or
      path-based archive with trie history (~6.5TB).

      EASY HALF: receipts. We need 1 week; partial history expiry drops only
      PRE-merge data and the proposed rolling window is ~5 months. Two orders
      of magnitude of headroom.

      DHT: stays completely out of it. The node's database is mutable,
      rebuildable from Ethereum p2p by anyone, and not our content. The DHT
      stores evidence; that boundary does not move.

      TRUST: a local node is NOT a trust anchor as long as verification is
      unchanged — an eclipsed node fails all four checks. The real risks are
      complacency ("it's our node") and single-supplier availability.
      RECOMMENDED: keep Alchemy as a SECOND UNTRUSTED SUPPLIER. That is not an
      RPC fallback: the rule forbids falling back to UNVERIFIED data, and two
      suppliers through the identical gate change nothing about what is
      believed.

      DO NOT PROCEED ON THE CATCH-UP NUMBER ALONE. It rests on two unmeasured
      assumptions about local RPC latency. Sync one node and measure
      eth_getBlockReceipts against it first.

P14.6b Local node performance         MEASURED — doc/fixtures/p146-local-node-validation.md
      Disposable geth v1.17.5 devnet, loopback, deleted after. 209 consecutive
      FULL blocks at 470 receipts / 3.0 logs each / 1324 KB per block — HEAVIER
      than the mainnet sample it is compared against, so the comparison runs
      against the conclusion rather than for it.

      ACCEPTANCE QUESTION: YES. One-week catch-up 3h24m -> ~8 min (~25x),
      entirely behind the existing verification boundary.

      BUT NOT FOR THE ASSUMED REASON. Local eth_getBlockReceipts is only 2.9x
      Alchemy (28.4ms vs 81.6ms median), because a megabyte of JSON costs the
      same to serialise wherever it lives. ~90% of the current catch-up is
      RATE-LIMIT BACKOFF, so the win is removing throttling, not latency.
      => A HIGHER ALCHEMY TIER REMOVES THE SAME 90% FOR NO HARDWARE. Price it
      first. Rate limit gone but still remote = ~20 min; local node = ~8 min.

      ROBUST TO THE DEVNET'S WEAKNESS: the devnet DB is page-cached, so 28ms is
      a LOWER BOUND. Assume a real local node is exactly as slow as Alchemy and
      one week is still ~17 min — 12x better. The gain does not need the node to
      be fast, only to stop refusing.

      FULL PIPELINE (not just the RPC): fetch 28.4 + decode 8.7 + authenticate
      2.2 = 39.2 ms/block. Real ChainFollower.Advance measured at both bloom
      extremes: 41.4 ms/block worst case (3% skipped), 1.68 ms/block best case
      (100% skipped). Zero rate-limit events in every local run.

      SAME GATE, NO EXEMPTION: ExecutionForkAt(1337) refuses; header re-encoded
      and hashed to its claimed value; 470 receipts rebuilt to the receiptsRoot
      bound into that header; a tampered local receipt STILL refused.

      PROOF WINDOW = EXACTLY 128 BLOCKS, reproduced on 5 independent chains
      (129 refuses "historical state not available"). Requirement is 64-96
      (the finalised block) => fits with 33 blocks margin, FAILS during a
      finality stall. Corrects the P14.6 investigation: geth v1.17 has TWO
      knobs — --history.state (90,000, flat state) and --history.trienode
      (-1 = OFF, the Merkle nodes eth_getProof needs). State history does NOT
      give proofs, and here eth_getStorageAt failed at the same 128 boundary
      too, so BOTH numbers need confirming on a real mainnet node.

      THE OPEN NUMBER: --history.trienode=N disk cost. NOT MEASURED, and a
      devnet cannot produce it. Measure it before buying anything.

      NO HARDWARE BOUGHT. No production node. No code changed (one _test.go
      added). Watchtower, challengePeriod, evidence rules, gate untouched.

P14.6c Trie history + A/B economics   doc/fixtures/p146-trie-history-and-economics.md
      TWO FINDINGS THAT INVERT THE QUESTION.

      1. --history.trienode IS NOT REQUIRED for normal operation. Traced in our
         own code: EvidenceChainReader reads STORED evidence and never touches
         an RPC ("No path here reaches an RPC"); eth_getProof is called only at
         ACQUISITION, and VerifiedRead pins the proof to the header it just
         fetched — a FRESH block. No code path requests a historical proof.
         It matters only for acquiring evidence during a finality stall longer
         than the 128-block (~25 min) window. Required N: 1,200 for a 4h stall
         (matches the Outage budget term), 7,200 for 24h.

      2. WE ARE ON ALCHEMY'S FREE TIER. 500 CU/s, and eth_getBlockReceipts costs
         500 THROUGHPUT CU — exactly ONE call/second. That is the entire 3h24m.
         PAYG is 10,000 CU/s (20x) at $0.45/M CU.

      DISK AT N=7,200: NOT MEASURED, and CANNOT BE without a synced mainnet node
      — which needs the 1.2TB this measurement exists to justify (we have 64GB
      free). Bounded instead: the quoted 4.5TB of trie history is for the ENTIRE
      25.75M-block chain (~175 KB/block); N=7,200 is ~1.3 GB, ~13 GB even at 10x.
      0.05-0.65% of a 2TB disk. IT IS NOT A SIZING CONSTRAINT. The disk is sized
      by the node itself. It is also a ROLLING window — bounded, not growing.

      ECONOMICS, measured workload x published CU weights:
        steady state  ~5.2M CU/month  -> INSIDE the free 30M allowance
        (volume was never the problem; throughput was)
        on PAYG       ~$2.34/month + ~$0.54 per one-week catch-up
        A: pay for throughput  1 week = ~20 min, ~$3/mo, no hardware
        B: own the node        1 week = ~8 min, 2TB NVMe + sync + maintenance

      RECOMMEND A FIRST. It closes ~92% of the gap for ~$3/month. The remaining
      12 minutes do not justify a machine that takes days to rebuild. B wins on
      exactly ONE argument — provider independence — and should be argued there,
      not on catch-up speed. Caveat: PAYG has no spending cap; set an alert.

      DECISION ORDERING: the trie-history disk number only matters under B.
      Measuring it costs the hardware in question or ~$50-150 of temporary cloud.
      DO NOT SPEND THAT UNTIL A-vs-B IS DECIDED.

      Nothing purchased. Nothing deployed. No production config changed.

P14.6d RPC tier upgrade (option A)    PRE-CHANGE RECORD FILED, awaiting the
      account change — doc/fixtures/p146d-rpc-tier-upgrade.md

      BLOCKED ON A HUMAN: the tier change and the billing alert live in the
      Alchemy dashboard behind billing details. Cannot be done from here.

      WHAT WE ARE BUYING: throughput, NOT volume. eth_getBlockReceipts bills
      20 CU but costs 500 THROUGHPUT CU; the free tier's 500 CU/s therefore
      allows exactly ONE call/second, which is the whole of the measured 3h24m.
      PAYG = 10,000 CU/s = 20 fetches/sec (20x).

      PROJECTED USAGE from measured inputs (20% bloom-hit rate, P14.5; Advance
      makes ZERO provider calls when finality has not moved):
        per watchtower  5.18M CU/month
        fleet of two   10.37M CU/month  = 35% of the FREE 30M allowance
        one-week catch-up 1.21M CU = $0.54
        EXPECTED COST ~$5/month (possibly $0 if PAYG carries the free allowance
        — confirm at signup)

      ALERT: $25/month recommended. Sized against the runaway ceiling — a loop
      fetching receipts flat out at PAYG throughput is 400 CU/s = $15.55/day =
      $467/month, so $25/mo catches it in ~2 days at ~5x expected spend. PAYG
      HAS NO SPENDING CAP; the alert is the only backstop.

      CHANGE SURFACE IS NIL: ETH_RPC_URL is consumed only by tests, RPCSource is
      not yet wired into any binary, V2 deployment is still gated. There is no
      production configuration to change today.

      VERIFICATION BOUNDARY UNCHANGED and structurally so — the endpoint is a
      string, the gate is code. No RPC fallback introduced; none exists.

      NEXT (mine, after the upgrade): TestP146DCatchUpOnUpgradedTier, already
      written. Runs UNTHROTTLED, counts CU per method invocation, and FAILS if
      any rate-limit event occurs — a measured time containing backoff must not
      be reported as clean.

      *** THE 4-HOUR OUTAGE BUDGET IS NOT VALIDATED BY ANY OF THIS. ***
      "PAYG should give ~20 min" is a PROJECTION. Outage and challengePeriod
      stay exactly as they are until the measurement has actually run. A
      measured catch-up time would still be one provider on one day, which is
      not the same thing as a validated budget.

P14.6e Current-plan throughput        MEASURED — doc/fixtures/p146e-current-plan-throughput.md
      NOT UPGRADED. No production code / verification boundary / challengePeriod
      / outage budget / deployment gate changed.

      VOLUME AND THROUGHPUT REPORTED SEPARATELY:
        volume     2,785,778 / 30,000,000 CU used, ~27.2M left. Projected fleet
                   steady state 10.37M/month. NOT A CONSTRAINT, never was.
        throughput 1.00 eth_getBlockReceipts/sec = 500 CU/s. THE CONSTRAINT.

      PACED PROBE (offer a rate, read the refusals — the first attempt hammered
      at fixed concurrency and got 98-100% refusals, which measures spam):
        0.5/s CLEAN | 1.0/s CLEAN | 1.5/s 18% refused | 2.0/s 35% | 3.0/s 74%
      The documented 500 CU/s cap and 500 throughput-CU weight are both exactly
      right. The ceiling is PUNITIVE above it: offering 3/s SERVED FEWER than
      offering 1/s. Refusals arrive as HTTP 429; no rate-limit headers exposed.

      CONFIRMATORY CATCH-UP, unthrottled (MinInterval 0) — NOT a clean result and
      not filed as one; the test fails its own assertion:
        2,000 blocks, 23m33s (706.7 ms/block), 929 receipt calls, 1,999 headers,
        58,560 CU ($0.026), 476 HTTP 429s, 428 retries, 48 batch shrinks.
        EFFECTIVE 0.657 receipts/sec — WORSE than the 1.00/s paced rate, because
        backoff idles the connection. If ever wired to production, MinInterval
        must pace at ~1/s rather than racing the limiter.

      THE SKIP RATE WAS WRONG, AND IT DECIDES EVERYTHING. Earlier 60-200 block
      samples gave 75-82%. A 3,000-block AUTHENTICATED sample gives 56.0%, with
      average bloom saturation 69.2% (not 57-60%). Break-even is 75.4%, so the
      small and large samples fall on OPPOSITE SIDES of the line — the early
      figure did not just lack precision, it pointed the wrong way.

      RESULT: one-week catch-up 6.72h paced / 9h54m measured, vs a 4h budget.
      MISSED BY 68%, with an IDLE contract.

      THE TRIGGER CANNOT BE CHANNEL ACTIVITY. skip = (1-ourEmitRate)x(1-FP), and
      the measured false-positive floor (33-44%) ALONE puts skip below
      break-even. Zero channel activity is required to breach it — other people's
      mainnet congestion already did. For monitoring, watch
      chain_blocks_skipped_by_bloom / chain_blocks_authenticated (both already
      exported); sustained below 75% means one week will not fit four hours.
      Currently ~56%.

      *** THE 4-HOUR OUTAGE TERM IS NOT VALIDATED BY THIS. *** It measures ONE
      input on ONE provider over ONE window. A number that MISSES the budget does
      not license changing the budget either. Term unchanged.

      RECOMMENDATION: the stated condition for upgrading is met — the limit does
      prevent the required performance. PAYG does the same work in ~20 min (8% of
      budget) for ~$5/month. Awaiting the dashboard change; cannot be done here.

      CORRECTION ON THE RECORD: my interim report said 3h22m fits inside 4h and
      recommended not upgrading. That used the 75-82% small-sample skip rate.
      With 56% the conclusion inverts.

P14.6g PAYG measured                  ACCEPTED — CURRENT PERFORMANCE BASELINE
      doc/fixtures/p146g-payg-measured.md
      BASELINE OF RECORD: 2,000 blocks / 1m29.4s / 877 receipt calls / 57,520 CU
      / 9.81 receipts-sec / 0 HTTP 429 / 0 retries / 0 backoff / 56% bloom skip
      / one-week equivalent ~37m33s. Parallelism headroom NOT to be used; no
      receipt parallelism, caching or batching unless a later measurement shows
      it necessary. VERIFY THE FIRST BILLING PERIOD against the projected
      12.44M CU/month fleet usage; keep the $25/month alert.
      ANSWER: YES. PAYG removes the throughput bottleneck.

      ENDPOINT VERIFIED: 25/25 concurrent served (Free: 13/25). Offered-rate
      probe clean at EVERY rung 5..30/s — highest tested 29.54/s = 14,769
      effective throughput CU/s, ABOVE the documented 10,000 cap. CEILING NOT
      FOUND; stopped because 30/s already exceeds what the workload needs.
      (Sequential probes cap at 1/latency ~12/s and would have reported the
      prober's bound as the provider's — hence the offered-rate design.)
      ONE DISCREPANCY, REPORTED NOT EXPLAINED AWAY: debug_traceBlockByNumber and
      trace_block still say "not available on the Free tier". Unused by our code;
      likely a separate Debug/Trace entitlement. Worth a dashboard glance.

      CATCH-UP, same workload/protocol, unthrottled (MinInterval 0), 2000 blocks:
                              FREE            PAYG
        elapsed            23m33.4s        1m29.4s   (44.7 ms/block)
        receipt calls           929            877
        header calls          1,999          1,999
        CU                   58,560         57,520   ($0.026)
        effective rcpts/s     0.657           9.81
        HTTP 429                476              0
        retries                 428              0
        backoff             >=856 s              0
        batch shrinks            48              0   (settled 99)
        bloom skip              54%            56%
      CLEAN by the stated definition. Corroborated by latency rather than
      asserted: median 91ms, p95 124ms, max 178ms, ZERO calls >= 2s.
      IMPROVEMENT 15.8x on identical work.

      ONE-WEEK EQUIVALENT: 37m33s = 15.6% of the 4-hour budget (Free: 9h54m =
      248%). Requirement met with 3h22m margin.

      *** NOT A VALIDATION OF THE 4-HOUR TERM. *** One input, one provider, one
      day, one skip rate. Budget unchanged. A PASSING number does not license
      REDUCING it either. DEPLOYMENT GATE NOT OPENED — catch-up performance is
      not its criterion.

      THE BOTTLENECK MOVED, and it is now OURS: ChainFollower fetches receipts
      one block at a time, so its ceiling is 1/latency ~11/s. It achieved 9.81/s
      against a provider serving >=29.54/s — 90% of wall time was inside receipt
      calls. ~3x headroom exists in parallelising them. NOT NEEDED (37 min
      already fits 4 hours) and NOT DONE — recorded as an option only.

      COST from MEASURED 28.76 CU/block (not the earlier 20%-hit assumption,
      which understated it): 6.22M CU/month per watchtower, 12.44M for a fleet of
      two = ~$5.60/month, ~$6.25 including a weekly catch-up. Possibly $0 if the
      30M allowance carries over — confirm on the first invoice.
      $25 ALERT: adequate, 4x headroom. The runaway ceiling ROSE with throughput
      ($23/day vs $15.55 on Free), so the alert matters MORE now; it trips in
      ~1.1 days. A daily alert would halve that.

      VOLUME vs THROUGHPUT still separate: volume 12.44M/month was never the
      constraint and is still inside the free allowance. The upgrade bought
      THROUGHPUT.

P12-8b Gate analysis + detection      doc/fixtures/p128-detection-finality.md

      WHAT ACTUALLY BLOCKS THE GATE: reorg depth, 7/30, running unattended on a
      clock. It cannot be hurried and an absence validates nothing. Everything
      else is filed and within budget.

      LATENT PROBLEM FOUND — WORSE THAN AN UNMEASURED TERM. Detection is marked
      VALIDATED at "31s", but TestDetectionAtProductionEnvelope builds its
      envelope on NewFakeChain() — no latency and NO CONCEPT OF FINALITY. The
      gate's own text requires detection measured "against a real RPC". When
      reorg depth completes, the gate would open on this.

      WHY IT MEASURES THE WRONG QUANTITY: AuthenticatedStateRoot refuses any
      header that is not FINALIZED, so the watchtower cannot see a state change
      until its block finalises. A zero-latency chain finalises instantly and
      cannot express the dominant term at all.

      MEASURED mainnet finality lag (12 readings): min 12.8 / median 14.8 /
      max 17.4 min = 43-58% of the 30m detection budget CONSUMED BEFORE THE
      WATCHTOWER DOES ANYTHING. The filed 31s understates real detection by
      ~25-35x, and the omitted part is the part NOTHING can optimise — not PAYG,
      not a local node, not receipt parallelism. It is Ethereum's.

      THE TERM STILL HOLDS: 17.4m finality + 30s sweep + ~2s work = ~17.9m of a
      30m budget (60%). BUDGET NOT REFUTED AND NOT CHANGED. The evidence is
      wrong, not the term — which is the distinction the gate exists to draw.

      RUNNING: TestP128FinalityLagForDetection, 30 INDEPENDENT samples (~3.2h),
      waiting for the finalised slot to CHANGE between observations. My initial
      12-reading probe contained only THREE distinct finality updates; counting
      repeats would let 12 samples masquerade as 30. The test FAILS if worst-case
      detection exceeds 30m, with the instruction to raise the term and
      re-derive challengePeriod — never to adjust the measurement.

      NOTED, NOT PURSUED: rpc-failure evidence is filed as "267ms / 80"; the gate
      requires genuinely INDEPENDENT providers plus an operator attestation.
      Worth confirming which two providers that used. Not blocking; chasing it
      now would be sprawl.

      NO OPTIMISATION STARTED. Detection is finality-dominated, so the P14.6g
      parallelism headroom would not have helped regardless.

P12-9 Execution-RPC transport failover  IMPLEMENTED + LIVE-VERIFIED
      doc/fixtures/p129-transport-failover.md

      TRANSPORT failover, NOT trust failover. The secondary is another way to get
      bytes, never another source of truth.

      WHERE: execution bytes enter through exactly two types, both
      Endpoint+http.Client — ethproof.Client (headers, eth_getProof) and
      RPCSource (receipts, batched headers). RPCChainReader has no real call
      sites and is superseded by EvidenceChainReader, which reaches no RPC.
      ONE NEW FILE plus a few lines in each of those two.

      THE SEPARATION IS STRUCTURAL, NOT A RULE. Verification runs ABOVE the
      transport on bytes it already returned, so a verification failure is not
      visible to the transport and there is NO PATH BACK IN. "A rejected -> B
      accepted -> therefore valid" is not forbidden by policy; it is unwritable.
      transport.go has zero Ethereum logic.

      FAILS OVER ON: connection/DNS/TLS/timeout, 5xx, 429 or capacity-refusal-on-
      200, unusable JSON-RPC framing.
      DOES NOT FAIL OVER ON: a well-formed JSON-RPC error (that is an ANSWER); a
      cryptographically invalid response (never reaches this layer); a malformed
      URL (our config fault — failing over would hide a typo forever).
      Bounded: each endpoint tried ONCE. Both fail -> ErrChainUnreachable, never
      stale data, never WatchQuiet.

      16 TESTS PASS including the regression test for the critical distinction.
      MUTATION-TESTED, 6 breaks: 3 caught, 3 survived informatively — two were
      tests being insufficiently specific (fixed: rate-limit classification is
      now pinned, config-fault path now covered) and one is an EQUIVALENT
      mutation (5xx falls through to the non-200 catch-all with the same reason),
      recorded as equivalent rather than dressed up as a hole.

      LIVE, TWO REAL INDEPENDENT ALCHEMY ACCOUNTS, block 25747812:
        A primary healthy      endpoint 0, 269 receipts, VERIFIED, 194ms
        B primary unavailable  endpoint 1, 269 receipts, VERIFIED,  93ms (503)
        C primary restored     endpoint 0, 269 receipts, VERIFIED,  62ms
        1 failover, 176ms outage, 73ms recovery latency.
      Every phase re-verified against the BEACON-authenticated receiptsRoot.
      The secondary's receipts are REFUSED against a root they do not rebuild to.

      CONFIG: ETH_RPC_URL_PRIMARY / ETH_RPC_URL_SECONDARY in .env. No URL or key
      in source, tests, fixtures, docs, logs or errors — the failover hook gets
      INDICES and a reason, never URLs, and a test asserts the failure error
      leaks neither endpoint.

      DOES NOT VALIDATE THE rpc-failure BUDGET TERM. That stays NOT MEASURED /
      NOT VALIDATED by architectural choice; this is transport availability, not
      the measured recovery-time evidence the gate asks for. 30m budget untouched.

P15 Many-to-one tipping pools                                        COMPLETE
      design: doc/p15-tipping-pools-design.md      code: internal/channel/pool.go
      also: p15-delegated-signing-design.md, p15-pipelined-mailbox-design.md
      a recipient CHOOSES pooling; the phase is still built.

      THE CENTRAL CLAIM, proven on a real EVM: a pool is a DERIVED VIEW over
      co-signed bilateral states the recipient already holds. Not a ledger, not
      a custodian. Delete it and nothing is lost.

      P15.1 AGGREGATION                                              COMPLETE
        Pool.View / CheckpointPlan / CheckDisjoint. Three contributors → 80 ANON,
        checkpointed independently 80 → 55 → 15 → 0, the recipient's ERC-20
        balance read from the token contract as the authority. Every channel is
        read separately and the pool derived from the sum.

      P15.2 DELEGATED SIGNING (contract)                             COMPLETE
        ChannelManagerV2 gained an OPERATION DOMAIN as the digest's first word
        and a per-party delegation registry. The domain closed a hole that
        predated delegation: with no live locks, closeCooperative and an ordinary
        agreed state hashed to THE SAME 32 BYTES.
        OP_STATE only; cooperative close has no bit to grant; checkpoint withheld.
        setDelegate/revokeDelegate are msg.sender-only. THE DELEGATE IS NEVER THE
        PAYEE — every payout goes to ch.partyA/ch.partyB. 8/8 mutations caught.

      P15.3 VOLUNTEER NODE                                           COMPLETE
        Mailbox mode holds frames and NO KEY — asserted structurally. Delegate
        mode asks canSign on every signature, never caches, refuses if the chain
        is unreachable. Case A and Case B both proven; NO CONTRACT CHANGE NEEDED.
        Also closed here: internal/channel was NOT MOUNTED in the node binary.

      P15.4 WEB INTEGRATION                                          COMPLETE
        Five surfaces render one shared component; recipient setup; tip quote;
        /v1/pool and /v1/pool/checkpoint. The server holds NOTHING financial.

      P15.5 REAL-BROWSER VALIDATION                                  COMPLETE
        Firefox + geckodriver against real Flask on real PostgreSQL, real
        EIP-1193 signing, real nodes, real EVM.

        THE ARCHITECTURAL FINDING, and the reason this phase took as long as it
        did: a Syndichan-served page CANNOT collect a tip. Accepting needs the
        recipient's channel key, which lives in their node, and the node exposes
        that authority on a loopback, spending-capable operator API. A Flask
        proxy was investigated and rejected — it would have given the website a
        credential able to settle and spend on a user's node, and it could not
        have worked anyway, since Flask would dial its own 127.0.0.1 rather than
        the recipient's machine.
        RESOLUTION: collection moved into the node's OWN console (the P7
        primitive), which calls the Receiving interface in-process. No credential
        crosses an origin, no CORS was added to /v1/*, and the operator API stays
        loopback-bound. Syndichan links out using the recipient's own configured
        address and FAILS CLOSED when it is unknown.

        SEVEN defects were found here, each fatal in a browser and each invisible
        to every non-browser test. Rule: ASSERT AGAINST THE ASSEMBLED PAGE.

      P15.6 REPEAT-TIP RECOVERY / CUMULATIVE CONTINUATION            COMPLETE
        The contributor's second mailbox tip must continue from what the
        recipient ALREADY ACCEPTED. The recovery machinery existed and tested
        clean; the shipped call site simply never passed the recovered state as
        `base`, so a second tip would have rebuilt from the chain and reused the
        first tip's update number.
        A base must be AGREED, not merely signed: selectLatest gained
        coSignedOnly, because a contributor's own queued-but-unaccepted proposal
        is a unilateral claim and must not advance their chain.
        A failed mailbox lookup now FAILS the repeat tip rather than silently
        building on an obsolete state and reporting it as queued.

        FINAL CLEAN FIREFOX RUN — the completion evidence:
          baseline recorded from the node: nonce 3, 485/15, total 500
          recipient OFFLINE for the whole contributor sequence
          tip 1 in Firefox → QUEUED via the real HTTPS volunteer → nonce 4, 480/20
            retained proposal: correct channel, contributor sig present,
            recipient and volunteer signatures ABSENT, value conserved
          recipient node accepted and countersigned → Pool.View 20 ANON
          contributor recovered the HIGHEST CO-SIGNED state (nonce 4) from the
            mailbox, ignoring the bare proposals at the same nonce
          tip 2 built from accepted nonce 4 → nonce 5, 475 contributor /
            25 recipient, total 500 = the original deposit
          recipient node accepted the cumulative state through its own console
          Pool.View() re-read from authoritative node state: 25 ANON
          publish created NO EVM transaction (block 231 → 231)
          duplicate acceptance idempotent; superseded proposals refused without
            regression, and now carry distinct "already included" semantics
        Two wallet prompts per repeat tip, both expected: the mailbox read proof
        signs a per-read challenge carrying no channel, nonce or amount, and
        cannot authorize a payment. The channel-state signature stays separate.

      HOLDING ACROSS ALL OF P15, verified rather than asserted:
        the recipient's channel key never entered a browser
        the browser never signed a channel state
        the volunteer never became a channel party and never held value
        the mailbox was never consumed by discovery, review, accept or publish
        /v1/* stayed loopback-only with NO CORS added
        Pool.View() was always re-read, never computed locally

      checkpoint gas: still unmeasured. It tunes MinCheckpoint; it does not
      change the structure (N checkpoints is N transactions regardless).

      real V2 contract integration    DONE on devnet; production still gated (P12)
     695 channel + 42 ui tests   build: PASS  vet: PASS  race: PASS
     117 contract tests (hardhat)
     152 browser-module tests (node:test)
     98 backend pooled-tipping / tip-surface tests
```

**Two of those are production gates, not enhancements.** P10 and P11 exist for
the same failure — an old state treated as current. A watchtower stops somebody
else doing that to you; recovery stops you doing it to yourself. And P12 waits
on P10 because `challengePeriod` is `immutable` and the watchtower's worst-case
response time is the number that decides it.

These are not unit tests around individual functions. Independent nodes with
separate stores on separate disks, exchanging serialised frames over real TCP,
with real restart-and-reload between steps, driven through the HTTP surface and
the dashboard — so the boundaries themselves are what is exercised.

What exists is the actual payment path:

```text
HTTP → Coordinator → SCPP/1 → real TCP → Coordinator
     → V2 state machine → Store → chain-backed collateral
```

**And the tipper still runs nothing.** The recipient's node does the persistent
work; the browser authorises a payment without being a participant in the state
machine.

The store's monotonicity holds across restart and crash. It does **not** hold
across a restored backup, which is a different lineage that looks valid from the
inside — see P11, which is a production gate rather than an enhancement.

**⚠ ChannelManagerV2 is written and tested but NOT DEPLOYED.** The live contract
is still V1 at `0xae70526931FF460894133201f6C8cA91bbA0E177`, which has no locks.
Deploying V2 and repointing `pof_contracts` is a deliberate, gas-spending act
that has not happened — see **P12** below.

**Verified against something outside the package, never against itself** — a
self-consistent encoding and a wrong one look identical from the inside. Two
authorities:

```text
mainnet, by eth_call to the live V1 contract
  channelId(0x1111…11, 0x2222…22)
    = 0x1bbe365357fe28ec15df954baa1b29fb309dd0e8a21208d768bce9ab1c0c4fd0
  stateDigest(thatId, 5, 340e18, 160e18)                        [V1, 6 fields]
    = 0x8765fe541624334ed869c7bf01146a298f9c27460902053a0e4c279fd68cbf39

the compiler and the EVM, by scripts/v2-golden-vectors.ts
  htlcRoot(twoLocks)
    = 0xe8303e521e3d9771a180e3f13b1f2d3b27ff1255adf20442232588b9528d6fa2
  stateDigest(thatId, 5, 340e18, 160e18, root)                  [V2, 7 fields]
    = 0x42ded98927e27fdd41c9c84c8b6b6b56459226d28ed2f622517c3f12c4c45348
```

`DeriveChannelID` is checked against both and agrees with each, which is the one
value that ties the two authorities together. `StateDigestV1` is kept solely to
hold the mainnet anchor; `State.Digest` signs the V2 form.

Five things P1 and P2 settled that the rest of the work now depends on:

- **Party A is the lower address, never the tipper.** Roles resolve through
  address ordering every time; there is no "tipper balance" field to get wrong.
- **Balances are `*big.Int`, not `Amount`.** One gold award is 1e20 wei and
  `Amount` is `int64`, which tops out near 9.2e18 — it would wrap, not truncate.
- **Locked value sits outside both balances.** Conservation is
  `balanceA + balanceB + sum(locks) == depositA + depositB`. Anything else lets
  a payer sign the same funds away twice.
- **There is one digest, and it always commits to the lock root.** No second,
  lock-free encoding to choose between, because a choice is a place to choose
  wrongly. With no locks the root is zero, on both sides.
- **A lock set has exactly one valid encoding.** Sorted by id, no duplicates.
  The contract *requires* that order rather than sorting, so the same locks
  cannot be presented two ways; the Go side owns the sort.

---

# The architecture — decided

The payment system is **Lightning-style from the beginning**.

The system supports two payment paths:

```text
                         PAYMENT REQUEST
                               │
                ┌──────────────┴──────────────┐
                │                             │
                ▼                             ▼
       DIRECT CHANNEL                    ROUTED PAYMENT
                │                             │
      tipper ↔ recipient             tipper → hub(s) → recipient
                │                             │
                │                            HTLC
                │                             │
                └──────────────┬──────────────┘
                               │
                         recipient node
                               │
                               ▼
                         settlement policy
                               │
                    ┌──────────┴──────────┐
                    ▼                     ▼
                 interval              close
                    │                     │
                    ▼                     ▼
                blockchain             blockchain
```

The distinction is important:

**Direct bilateral payments do not need an HTLC.**

A direct channel already has both parties signing the state.

**Routed payments do need HTLCs.**

The HTLC protects the payment when an intermediary is forwarding money and makes the multiple channel hops atomic.

Therefore HTLC support is part of the architecture **from the beginning**, even though a simple direct tip may use an ordinary signed balance update.

The system should never require rebuilding the channel protocol later to add routing.

---

# Who runs what — decided

## Recipient

The recipient operates the payment endpoint.

A recipient may be:

* a streamer
* author
* board user
* creator
* organization
* any account configured to receive tips

The recipient's payment node handles:

* channels
* channel state
* direct payments
* HTLCs
* routing
* settlement
* monitoring
* watchtower functions

## Tipper

The tipper does **not** operate a Lightning node.

The tipper needs only:

* their existing wallet
* MetaMask/browser signing
* enough funds to fund a channel or make an on-chain payment

The tipper does not need:

* a daemon
* a routing table
* a public IP
* a payment server
* a persistent node
* to stay online after making a payment

The browser is a lightweight signing client.

---

# Recipient-hosted channels

The recipient creates the opportunity to receive channel payments.

For a direct channel:

```text
Tipper ───────── Recipient
```

The tipper funds the channel.

The recipient operates the other endpoint.

The channel can then process many tips without another blockchain transaction for every tip.

Example:

```text
Initial funding:

Tipper deposits 500 ANON
                     │
                     ▼
              channel established

Tip #1     5 ANON
Tip #2    25 ANON
Tip #3   100 ANON
Tip #4     5 ANON
Tip #5    25 ANON
       ...
```

The individual tips are signed state updates.

They are not individual blockchain transactions.

---

# The important economic distinction

A channel is **per tipper-recipient pair**.

This means:

```text
Alice → Creator
```

having a channel does not mean:

```text
Bob → Creator
```

has one.

Therefore the payment selection condition is:

> **Does this specific tipper have a funded channel with this specific recipient?**

Not:

> Does this recipient have a channel?

The payment selection logic is:

```text
                  TIP
                   │
                   ▼
     Does this tipper have a funded
     channel with this recipient?
                   │
          ┌────────┴────────┐
         YES                NO
          │                  │
          ▼                  ▼
   direct channel       Can a route be
       payment          established?
                            │
                     ┌──────┴──────┐
                    YES            NO
                     │              │
                     ▼              ▼
                  HTLC route     ERC-20
                     │           transfer
                     └──────┬──────┘
                            ▼
                         recipient
```

The ERC-20 path remains permanently available.

This matters because a first-time user sending one 5-ANON bronze tip may be better served by the existing on-chain transfer than by funding a channel for a single payment.

---

# The existing contract — finding

**The deployed `ChannelManager` already provides the bilateral state machinery required for direct channels.**

`ChannelManager` is deployed at:

```text
0xae70526931FF460894133201f6C8cA91bbA0E177
```

It provides:

```text
channelId
openChannel
deposit
stateDigest
closeCooperative
closeUnilateral
challenge
settle
```

The existing cooperative close requires both parties to sign the state and checks conservation of balances.

Therefore the basic direct channel can operate as:

```text
Initial:
Tipper       500
Recipient      0

Nonce 1:
Tipper       495
Recipient      5

Nonce 2:
Tipper       470
Recipient     30

Nonce 3:
Tipper       370
Recipient    130

Nonce 4:
Tipper       365
Recipient    135

Nonce 5:
Tipper       340
Recipient    160
```

The blockchain ultimately needs to settle the latest valid state rather than every individual tip.

**However, the deployed contract must still be tested thoroughly before being trusted with real ANON.**

---

# HTLC is integrated from the beginning

HTLC is **not deferred to a later version of the architecture**.

It is implemented alongside the channel protocol.

Its purpose is specifically to support:

```text
Tipper → Hub A → Hub B → Recipient
```

without requiring the tipper to trust Hub A or Hub B.

A routed payment uses the same secret/hash across the route.

Conceptually:

```text
Tipper
  │
  │ HTLC
  ▼
Hub A
  │
  │ HTLC
  ▼
Hub B
  │
  │ HTLC
  ▼
Recipient
```

The recipient reveals the preimage to claim the payment.

That preimage allows the preceding intermediary to claim its corresponding payment.

Timeouts provide the refund path if the payment does not complete.

Therefore the system supports:

```text
ordinary signed state
        +
conditional HTLC state
```

from the beginning.

---

# What HTLC does NOT do

HTLC should not be forced into every direct payment.

For:

```text
Tipper ───────── Recipient
```

there is no intermediary.

The parties can simply agree on:

```text
new nonce
new balances
signatures
```

For:

```text
Tipper → Hub → Recipient
```

the payment becomes conditional because the hub is an intermediary.

This gives the system one unified channel architecture with two payment mechanisms:

```text
                   CHANNEL
                      │
          ┌───────────┴───────────┐
          │                       │
   ordinary state             HTLC state
          │                       │
          ▼                       ▼
 direct payment             routed payment
```

---

# P12 — Independent Ethereum data layer, then deployment — GATED

```text
P12-1  Determine required Ethereum data       COMPLETE   doc/ethereum-data-layer.md
P12-2  Real proof verification/measurement    COMPLETE   internal/ethproof
P12-3  DHT evidence format + persistence      COMPLETE   internal/ethproof/evidence.go
P12-4  Local index                           COMPLETE   internal/ethproof/index.go
       pointers only, never values; rebuildable from the store; Lookup
       refuses while canonicality is unestablished
P12-5  Native Ethereum light client          MAINNET-VERIFIED

       5.1  external mainnet checkpoint     COMPLETE  checkpoint.go
            sealed for a session; domain binds chain + fork
       5.2  SSZ / merkleisation             COMPLETE  ssz.go
            zero-hash padding, gindex branches, beacon header root
       5.3  beacon header verification     COMPLETE  lightclient.go
            slot ordering, participation threshold, finality + committee
            branches at their gindices — all checkable with NO BLS, which
            is why 5.3 finished before 5.4 picks a library.
            The committee comes from the AUTHENTICATED STATE, never from
            the update being checked.
       5.4  BLS sync committees             DECISION NEEDED - see below
       5.5  committee rotation
       5.6  finality (observed/verified/finalized)
       5.7  execution payload -> stateRoot
       5.8  HeaderVerifier integration

       SECURITY CONSTRAINT — DECIDED, DO NOT REVISIT AS AN OPTIMISATION

         We do NOT implement pairing, hash-to-curve, subgroup checks or
         cofactor clearing ourselves. A vetted BLS12-381 library provides the
         primitive; everything above it is ours.

         A future pass may notice the dependency and think removing it is a
         simplification. It is not. Hand-written protocol code fails LOUDLY —
         a wrong root does not match. Hand-written pairing code fails SILENTLY,
         by accepting forged signatures, which is the one outcome this entire
         phase exists to prevent.

         Before a library is selected, record: exact version, licence, Go and
         platform support, whether the API we call performs SUBGROUP CHECKS,
         its hash-to-curve DST, aggregate-signature behaviour, Ethereum test
         vectors, independent audit history, and how the build is pinned.
         And wrap it in ONE narrow function — VerifySyncCommitteeSignature —
         so no caller above it can reach a raw pairing operation and skip a
         validation step by accident.

       5.4 RATIONALE. Hand-writing RLP and the MPT verifier was
       sound: simple deterministic encodings, no secret material, checkable
       against published vectors, and a wrong answer is a loud mismatch.
       BLS12-381 pairing is NOT the same kind of thing — subgroup checks,
       cofactor clearing, hash-to-curve, miller loop and final exponentiation,
       where a subtle error means ACCEPTING FORGED SIGNATURES silently.
       This project already depends on decred/secp256k1 for the money-bearing
       channel signatures; a vetted BLS library is the same kind of dependency,
       and is different from vendoring a whole consensus client.

       COMPLETE WHEN: HeaderVerifier obtains and independently validates
       canonical Ethereum Mainnet headers through a DEFINED TRUST ANCHOR.

       MAINNET-VERIFIED on 2026-08-12. The full chain ran against real
       Ethereum mainnet data: independent checkpoint -> real sync committee ->
       real 501/512 aggregate signature -> finality ADVANCEMENT with roots
       differing -> authenticated execution payload -> authenticated stateRoot
       -> real eth_getProof MPT verification -> DHT persistence and
       independent re-verification on reload.

       Record: doc/fixtures/p12-5.9-mainnet-run.md

       Not "when a sidecar is installed" — A and B below are two
       implementations of that one property.

         A  native verifier          highest independence; BLS + SSZ + fork upkeep
         B  vendored light client    real verification sooner; a third party ON
                                     the security path, and it must be SAID so
         C  multi-provider agreement NOT in the security model. An availability
                                     cross-check; never described as proof
         D  accepted assumption      operationally possible, and fundamentally
                                     different from "independently verified"

       B must not become a disguised A: the sidecar IS the trust component,
       and the roadmap and the code should both say which one is in use.
P12-6  Watchtower integration               COMPLETE   internal/channel/evidencereader.go
       EvidenceChainReader implements the existing ChainReader, so the
       watchtower is UNCHANGED. No RPC fallback anywhere in the path.
P12-7  Failure testing                       COMPLETE   evidencereader_test.go
       every layer fails closed independently; see the table in that file
P12-8  Production measurements / challengePeriod    IN PROGRESS
       Envelope: 10,000 channels per watchtower, 2 watchtowers, 30s sweep,
       1h on-call response, 4h maximum outage. Measurements are taken AT that
       envelope, and evidence gathered outside it does not count.

       term               budget   measured        status
       local work         —        in-process      VALIDATED  TestLocalPathFitsItsBudget
       detection          30m      31s / 200k      VALIDATED  detection_test.go
       inclusion          30m      33s worst       VALIDATED  doc/fixtures/p12-8-inclusion.md
       rpc failure        30m      NOT APPLICABLE  NOT MEASURED / NOT VALIDATED
                                                    BY ARCHITECTURAL CHOICE — there is no RPC
                                                    failover mechanism and none will be built.
                                                    doc/fixtures/p128-rpc-failure-review.md
       watchtower outage  4h       commitment      VALIDATED  operational
       repricing          30m      48s worst       VALIDATED  doc/fixtures/p12-8-repricing.md
       reorg depth        30m      7 of 30 events  NOT MEASURED  doc/p12-8-reorg-observation.md

       RPC FAILURE: CLOSED AS NOT VALIDATED, DELIBERATELY.

       The production architecture has a SINGLE execution RPC provider and no
       failover mechanism, by explicit decision. A failure is handled by the
       existing fail-closed behaviour: the watchtower refuses to answer rather
       than believing anything unverified. No second provider will be acquired,
       no failover API will be built, and the verification path will not be
       changed to accommodate one.

       The term is therefore NOT MEASURED and NOT VALIDATED, and that is the
       honest state rather than a gap to be filled. The evidence requirements
       were NOT weakened to make it pass; the 30m budget number is UNTOUCHED and
       no replacement number has been invented.

       (For the record of what was found before the decision: the previous
       "VALIDATED 267ms / 80" had no provenance — that figure appears nowhere in
       the repository except the status line, ObserveFailover was never run
       against a real endpoint list, and every AsEvidence test used
       a.example/b.example placeholders. The review is filed; the rules
       themselves were sound.)

       *** STRUCTURAL CONSEQUENCE, FOR A HUMAN TO DECIDE ***
       ValidatedBudget.DeployableChallengePeriod returns an error while ANY term
       is unvalidated, and rpc failure can now never be validated. AS CODED, THE
       GATE CANNOT OPEN. Three ways out exist and all are decisions, not
       measurements:
         a) EXEMPT the term the way `local work` and `safety` are exempt, with
            the architectural reason recorded in code;
         b) fold its 30m into another term — this INVENTS A NUMBER and was
            explicitly ruled out;
         c) accept that the gate stays closed.
       NOTHING WAS CHOSEN. No code was changed. challengePeriod is untouched.

       Inclusion: 30 real EIP-1559 mainnet transactions from a dedicated
       measurement account, min 6s / median 9s / p95 23s / max 33s, total
       0.000112 ETH. The WORST sample is the evidence, not the median.

       Repricing took three protocols to measure. A 1 wei tip transaction was
       mined in the NEXT block, in a block 82% full — a near-zero tip does not
       strand a transaction while there is spare block space, because any
       positive tip beats an empty slot. The term is about a fee estimate
       overtaken by the market, and that happens when maxFeePerGas falls below
       the BASE fee, not when the priority fee is small. The first protocol
       drove the wrong variable.

       The adopted method sets maxFeePerGas to 50% of base — arithmetically
       unmineable, and unable to become mineable within one block because
       EIP-1559 caps a single-block decrease at 12.5%. 30/30 valid, 0 discarded.

       Recovery = one block (fixed trigger) + replacement inclusion, and 26 of
       30 samples are exactly two blocks. The number is close to inclusion plus
       one block BY CONSTRUCTION. That is deliberate: leaving the replacement
       decision to operator latency measures how fast somebody noticed, not how
       fast Ethereum recovers — the exploratory run's 300s was ~288s of
       deciding and ~12s of chain.

       NOT A CONGESTION MEASUREMENT. It measures recovery under the observed
       calm market (0.088-0.139 gwei). The recursive case — a replacement that
       is itself underpriced by a fast-moving market — is what the 30m term was
       sized for and remains unvalidated. AsEvidence refuses a campaign that
       does not state its fee conditions and embeds them in Method, so the
       figure cannot be quoted apart from its regime.

       Reorg depth is the term an absence cannot validate. Blocks observed
       with zero reorganisations bounds nothing — ReorgObservation.AsEvidence
       refuses to convert it, deliberately.

       The observation now runs unattended under systemd with lingering, all
       state persisted outside /tmp, and alerts on a reorg, a stall, or a
       reporting milestone. It survives crash and reboot; restart-safety was
       verified rather than assumed.

       DETECTION GAP FOUND: the previous observer, and ObserveReorgs itself,
       detect a reorg only when a height ALREADY SEEN reports a different
       hash — which requires the head number to repeat or go backwards.
       Mainnet's common case is single-slot: block N is orphaned, a different
       N replaces it, the chain extends to N+1, and a head-number poller sees
       nothing. The new observer verifies parent-hash linkage instead and
       backfills skipped heights. ObserveReorgs was NOT changed mid-flight and
       has filed no evidence; it should be brought up to linkage detection
       before it is ever used to validate this term.

       THE BUDGET DOES NOT MOVE TO MATCH THE MEASUREMENTS. Terms were set
       before measuring; a fast result validates a term, it does not lower it.
```

## P12-5 finding — there is no cheap version

Post-merge an execution header carries `difficulty 0x0` and `nonce 0x0`. There
is no proof-of-work, so fabricating a self-consistent header chain costs nothing
but hashing — correct parentHash linkage to any depth, any stateRoot, and
storage proofs beneath it that OUR OWN VERIFIER WILL CONFIRM, correctly, because
they are internally consistent.

```text
parentHash chain continuity          free to fabricate
stateRoot + proofs beneath it        free to fabricate
timestamps, gas, block numbers       free to fabricate
difficulty / nonce (pre-merge PoW)   no longer exists
```

Only beacon-chain validator signatures make a header canonical. So P12-5 needs
BLS12-381 aggregate verification, SSZ merkleisation, the light-client protocol
across five forks, and an anchor from outside the RPC being checked — a light
client, measured in thousands of lines plus fork maintenance.

**What was built instead: a gate.** `HeaderVerifier.VerifyHeader` returns
`ErrNoTrustAnchor` and fails closed. It deliberately does not fall back to
linkage checking, because linkage proves nothing. `SetAnchor` refuses an anchor
sharing a provider with the endpoint it would check — the circularity that moves
the trust boundary without shrinking it.

Options and a recommendation are in `doc/trust-anchor.md`. Briefly: vendor a
light client now, write one later, and do NOT build multi-provider corroboration
— it would look like verification in the code and in the logs, which is worse
than an honest `AnchorNone`.

---

## P12-1 result

The entire chain dependency of the payment system is **one read** —
`channels(bytes32)` — plus transaction broadcast. Not history, not arbitrary
receipts, not balances.

`solc --storage-layout` puts `channels` at slot 0 (`token` and `challengePeriod`
are immutable and occupy no storage), so a channel is eleven slots at
`keccak256(id ‖ uint256(0))`.

Two verification strategies, costed:

```text
A  prove every channel's storage every sweep
     full struct        0.4 GB / 30s sweep at 10,000 channels
     status slot only   29 MB / sweep = 1.0 MB/s sustained
     -> scales with channel count; untenable at the envelope

B  verified headers + logsBloom + receipt proofs on a hit
     ~1 KB per block, 7.1 MB/day, 2.73 GB/year
     -> INDEPENDENT of channel count
     plus 7.6 MB/year of sync-committee updates
```

**And B resolves the P10 polling-versus-events tension rather than reopening
it.** P10 chose polling because a dropped subscription is silent. A verified
header CHAIN has the opposite property: a gap is impossible to miss, because
headers are linked. It gets polling's completeness without polling's cost.

Detection then becomes block time plus verification rather than the sweep
interval — which may let the detection term come down, though that is P12-8's
measurement to make, not an assumption to bank.

## Why this belongs in the DHT and Geth's database did not

```text
this layer     append-only, immutable, content-addressed, ~2.7 GB/year
Geth's DB      mutable random-access state, 750 GB, continuously rewritten
```

The first is what the store is for. The second is what it is not.

## What P12-1 does NOT establish

Proof sizes are typical figures, not measurements. The slot arithmetic is the
compiler's answer, unverified against a real `eth_getProof`. Sync-committee
verification is unwritten, and until it exists this design trusts a provider
exactly as much as a plain RPC call does. And broadcast stays trust-requiring:
we can verify what we READ, but not that a provider actually sent what we gave
it — only that it later appeared in a verified block.

If the evidence turns out to need more local state than this predicts, the
answer is a light client or an external execution source, and this section
should be rewritten rather than defended.

---

# P12-old — the deployment gate itself (SATISFIED)

```text
P12-a  The gate, as code     +  DeployableChallengePeriod() errors until validated
P12-b  Read-only probes      +  reorg depth, RPC failover
P12-c  Live-chain validation +  all six terms measured on mainnet; gate returns 28800 s
P12-d  Deployment            +  0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c, block 25757314
```

The gate opened because the evidence was gathered, not because it was relaxed.
The one threshold that moved — reorg depth from 30 samples to 18, scoped to that
term alone — is recorded in `doc/deployment-gate.md`. Each measurement's
limitations are recorded there too and did not stop applying at deployment.

**Status: the gate is CLOSED and the system is not deployable.** Not as a
policy — `ValidatedBudget.DeployableChallengePeriod()` returns an error rather
than a number, and `TestTheSystemIsNotYetDeployable` asserts that it does. A
deployment script cannot obtain a value to deploy with.

Written up in `doc/deployment-gate.md`.

## What evidence has to be

Not a tick in a box. The gate refuses evidence from another chain, with fewer
than 30 samples, with no recorded method, older than 90 days, or — most
importantly — **evidence that exceeds its own budget**. A 45-minute inclusion
measurement does not validate a 30-minute term; it refutes it, and the correct
response is to raise the term and re-derive rather than to file the measurement
and carry on.

## The trap the probes guard

```text
5000 blocks observed, 0 reorganisations
        |
        v
"reorg depth: validated"      <- WRONG
```

An absence of events does not bound the depth of one. `AsEvidence` refuses when
no reorg was seen, refuses a single-endpoint failover sample — one endpoint is
not a smaller version of the failover assumption but the absence of it — and
refuses any round where nobody answered, which is an unbounded wait rather than
a measured one.

## What remains, and who can do it

```text
reorg depth   tooling provided, read-only, run it against the target chain now
rpc failure   tooling provided, read-only, across the REAL endpoint list

inclusion     needs transactions sent from a funded account
repricing     needs transactions sent from a funded account
detection     needs the watchtower at the channel count this will really hold
outage        an operational commitment about on-call response
```

Estimating the last four from the first two would be exactly the move the gate
exists to stop.

## The rule

> The contract cannot be deployed until the immutable challenge period has been
> derived from assumptions that have actually been validated for the target
> chain.

If the measurements confirm the estimates, 8h stands. If not, the executable
budget changes, the recommendation follows, and the contract is deployed with
whatever number is then safe — or not deployed.


# P5–P11 — COMPLETE

Payment-node integration, settlement, receiving, browser/wallet, award
integration, watchtower and backup are all built, tested and closed. Their
findings are in git history rather than here: a roadmap that keeps every
finished phase in full stops being read, and the detail that mattered has
long since moved into the code's own comments.

What they left standing, and what everything after them assumes:

- one component turns a request into money (P5-2);
- collateral comes from the chain, never from a peer (P5-1);
- submitted is not confirmed (P6);
- a recipient's console is served by their NODE, not by the website (P7);
- a browser is a channel party, not a second state machine (P8);
- awards denominate in whole ANON and the server converts once (P9);
- a watchtower needs no authority to defend a channel (P10);
- a backup is evidence, never an authority (P11).


# P13 — Full security test suite

Before real ANON is used, test both direct and routed payments.

**STATUS: the three tables below are covered; multi-path and the deployed
contract are not.** See `p13_test.go` and `p13_routed_test.go`.

The suite is written so coverage is CHECKABLE rather than believed: each table
is declared as data, every row registers itself when exercised, and the parent
test fails if a row was never claimed. Adding a row breaks the build until it
is tested. The package already had ~490 tests and most rows were covered
somewhere among them — what did not exist was any way to answer "is every row
covered?" without reading all of them and judging.

Both suites were mutation-tested rather than trusted for passing: eleven
deliberate defects were introduced one at a time into `state.go` and `hub.go`
(nonce regression, wrong-channel, conservation, signer identity, duplicate
HTLC, negative balance, preimage check, hub capacity, reader capacity, cancel
restoration, duplicate condition). All eleven were caught. A suite that passes
the moment it is written is not yet known to test anything.

NOT COVERED, and not claimed:
  - multi-path payments. The roadmap says "where supported"; splitting exists
    in multipath.go but a security table for it was never written, so there is
    nothing here to check it against. That table needs writing first.
  - the deployed ChannelManagerV2. Nothing in P13 is a claim about the real
    contract — it is not deployed. The digest golden vectors in state_test.go
    are the only place this package's encoding is tied to the EVM.
  - the expiry row is a state-machine test, not a clock test. Channel.Accept is
    deliberately pure and refuses an UNSET expiry while allowing a past one,
    because freshness is the protocol layer's job and a clock inside Accept
    would make a stored state stop validating while it sat on disk.

## Direct channel tests

| Test                    | Expected              |
| ----------------------- | --------------------- |
| Valid state             | succeeds              |
| Invalid signer          | fails                 |
| Wrong channel ID        | fails                 |
| Same nonce replay       | fails                 |
| Older nonce             | fails                 |
| Newer nonce             | succeeds              |
| Insufficient balance    | fails                 |
| Non-conserving balances | fails                 |
| Cooperative close       | succeeds              |
| Unilateral close        | enters challenge      |
| Newer state challenged  | newer state wins      |
| Crash/restart           | latest state survives |

## HTLC tests

| Test           | Expected |
| -------------- | -------- |
| Valid secret   | succeeds |
| Invalid secret | fails    |
| Double claim   | fails    |
| Expired claim  | fails    |
| Valid refund   | succeeds |
| Wrong hash     | fails    |
| Wrong amount   | fails    |
| Wrong channel  | fails    |
| HTLC replay    | fails    |

## Routed payment tests

```text
Tipper → Hub → Recipient
```

must test:

* hub failure;
* recipient failure;
* invalid route;
* insufficient channel capacity;
* HTLC timeout;
* successful preimage propagation;
* intermediary cannot steal funds;
* payment cannot settle on one hop without the corresponding payment condition being satisfied.

Also test:

```text
Tipper → Hub A → Hub B → Recipient
```

and multi-path payments where supported.

---

# P14 — Economic and load testing

The system must measure when each payment method makes economic sense.

For example:

```text
5 ANON one-time tip
```

may be better as:

```text
ERC-20
```

while:

```text
5 ANON × 100 tips
```

is an excellent candidate for:

```text
channel
```

And a user who frequently tips many different recipients may eventually benefit from:

```text
hub routing
```

The system should therefore collect anonymous operational metrics such as:

* channel creation frequency;
* average tips per channel;
* channel lifetime;
* settlement frequency;
* routing success rate;
* routing failure rate;
* average channel balance;
* average gas per settled ANON;
* percentage of tips using each payment path.

This data can determine whether the routing layer is economically worthwhile rather than guessing.

---
# P15 — Many-to-one tipping pools

> **A pool is a DERIVED VIEW over co-signed bilateral states.** Not a ledger,
> not a custodian, and it stores no balance that could be wrong. Delete the view
> and nothing is lost; corrupt it and the next read corrects it.

## Where it stands

The protocol is proven on a real EVM and the product half is finished: a real
Firefox has queued a tip, had it accepted by the recipient's own node, recovered
the co-signed state, and sent a cumulative second tip that the recipient
accepted. Receiving still requires running a node — that is the design, not a
gap.

| | |
|---|---|
| P15.1 aggregation layer | **COMPLETE** |
| P15.2 delegated signing (contract) | **COMPLETE** |
| P15.3 volunteer node | **COMPLETE** |
| P15.4 web integration | **COMPLETE** |
| P15.5 real-browser validation | **COMPLETE** |
| P15.6 repeat-tip recovery / cumulative continuation | **COMPLETE** |

**P15 is closed.** This does not make the tipping system production-ready — see
"Outstanding work" below for what remains outside this phase.

---

## P15.1 — The aggregation layer  COMPLETE

`internal/channel/pool.go`. `Pool.View()` sums the recipient's side across a
disjoint member set, recomputed on every read. `CheckpointPlan` lists what is
worth withdrawing; `CheckDisjoint` refuses two pools that claim one channel,
because a channel's value can be checkpointed once and two views would both
count it.

Devnet-verified: three contributors accumulating to 80 ANON, then checkpointed
independently 80 → 55 → 15 → 0, with the recipient's ERC-20 balance read
directly from the token contract as the authority. The aggregate is never
asserted as a literal — every channel is read separately and the pool derived
from the sum, so two cancelling errors still fail.

## P15.2 — Delegated signing  COMPLETE

ChannelManagerV2 gained an **operation domain** as the first word of
`stateDigest`, and a per-party delegation registry. Both were pre-production
changes and both are done.

The domain fixed a hole that existed independently of delegation: with no live
locks, `closeCooperative` and an ordinary agreed state hashed to **the same 32
bytes**. Nobody signed "close the channel" — they signed a balance split, and
the contract could not tell the difference. Harmless between two honest parties;
fatal the moment a delegate may sign, because an authority to countersign
payments would silently also authorise settlement.

Delegation is `OP_STATE` only. Cooperative close has **no bit to grant**, so no
argument to `setDelegate` can produce it; checkpoint is withheld. `setDelegate`
and `revokeDelegate` are `msg.sender`-only and there is no signature-accepting
variant — a delegate cannot appoint a successor, extend itself or revoke
anybody, enforced by the *absence of a function*.

**The delegate is never the payee.** Every payout path still transfers to
`ch.partyA`/`ch.partyB`, and `Channel` gained no field. Devnet-proven in both
party orderings; 8/8 mutations caught, including one that only a test added
afterwards could catch — making `checkpoint` pay `delegations[party].signer`
survived the whole suite until a test watched that payout with a delegation
present.

## P15.3 — The volunteer node  COMPLETE

Recipients should not have to run a node. Volunteers provide the infrastructure,
and the security question is what they hold.

**Mailbox mode** — the volunteer holds frames and **no key**. Not "is not
supposed to sign": there is no field on `Mailbox` that could hold a signer, and
a reflection test asserts it. Authorizations are signed by the recipient and
name the node, so a proof collected by one volunteer cannot be replayed by
another. Access to a channel's retained frames is **derived, not asserted** — a
channel id is `keccak(sorted(a,b))`, so the caller's proven address plus the
recipient recomputes it.

**Delegate mode** — the node holds a delegate key and asks
`ChannelManagerV2.canSign` on **every** signature. No cache: revocation is
instant, and a cached "yes" is a signature the recipient has already withdrawn.
If the chain cannot be reached it refuses rather than assuming.

Also closed here: `internal/channel` was **not mounted in the node binary** for
several phases — complete, tested, and reachable from nothing. `/scpp/v1` and
`/mailbox/v1/*` are public and signature-authorised; `/v1/*` is loopback-only and
token-gated, and config validation refuses to bind it anywhere else.

### Case A and Case B

**Case A** — queued tip → recipient accepts → co-signed state published →
contributor recovers it → next tip builds from it. Devnet-proven: tip 2 landed
at nonce 2 with tip 1 in its balances.

**Case B** — several tips from one contributor while the recipient is offline.
The analysis found this smaller than expected: different contributors use
different channels, so multi-contributor was never pipelining at all. The real
case is one channel, and it needs no new state model — **each state subsumes its
predecessors**, so the recipient countersigns only the highest. Devnet-proven:
three tips accepted as one state at nonce 3, superseded states refused, duplicate
refused, `Pool.View() = 75 ANON`. **No contract change was required.**

## P15.4 — Web integration  PARTIAL

Done: profile/forum/news/byline/stream all render one shared tip component;
recipient setup with volunteer and signing mode; `/profile/<slug>/tip/quote`;
`/v1/pool` and `/v1/pool/checkpoint`; the recipient dashboard reading the
recipient's own node.

The server still holds **nothing financial** — no balance, no channel id, no
contributor identity, no amount, no history. Tested, not asserted.

Recipient collection does NOT live here. It is served by the recipient's own
node console — see P15.5 for why a Syndichan-served page cannot do it.

Still outside this phase: delegated-mode authorization from the browser, and
channel opening from the UI.

## P15.5 — Real-browser validation  COMPLETE

Firefox + geckodriver against the real Flask app on real PostgreSQL, with a real
EIP-1193 provider backed by a Hardhat account — **real secp256k1 signing, not
MetaMask**, and the key never leaves the node.

**Proven in the browser:** profile → Tip → quote → confirmation → wallet
authorisation → recipient unreachable → HTTPS volunteer → **QUEUED**, with the
queued frame verified as a correctly-denominated 5-ANON proposal carrying one
contributor signature and conserved balances.

**Also proven in the browser:** recipient collection through the node's own
console — review (non-consuming), accept, node countersignature, publish, and
`Pool.View()` re-read — plus contributor recovery and the cumulative second tip
(P15.6).

### The architectural finding

A Syndichan-served page **cannot** collect a tip. Accepting needs the
recipient's channel key, which lives in their node, and the node exposes that
authority on a loopback, spending-capable operator API. A Flask proxy was
investigated and rejected on two independent grounds: it would have given the
website a credential able to settle and spend on a user's node, and it could not
have worked regardless, because Flask would dial its own `127.0.0.1` rather than
the recipient's machine.

The resolution reuses the P7 primitive: the node serves its own console and
calls the `Receiving` interface **in-process**. No credential crosses an origin,
no CORS was added to `/v1/*`, and the operator API stays loopback-bound.
Syndichan links out using the recipient's own configured address and fails
closed when it is unknown.

### Why this phase exists

Seven defects, each fatal to the feature in a real browser and **each invisible
to every non-browser test**:

1. `tip_dialog()` sat after `{% endblock %}`, so Jinja discarded it — the page
   shipped a Tip button that opened nothing.
2. The quote route repeated its blueprint prefix and was published at
   `/profile/profile/<slug>/tip/quote` — unreachable for as long as it existed.
3. The quote carried no `volunteer_endpoint`, so the mailbox fallback had
   nowhere to send anything.
4. The mailbox answered **405** to the browser's CORS preflight, so no browser
   could ever deliver to it.
5. `queueWithVolunteer` wrapped two operations in one `try`, reporting a
   chain-read failure as "the mailbox refused the message".
6. The quote never converted whole ANON to base units — a browser tip of "5"
   signed a state moving **5 wei**.
7. The dashboard depends on the ethers bundle and the settings page never loads
   it, so collection dies before its first request.

The lesson is one rule: **assert against the assembled page.** A component that
works in isolation and is never reached is still broken. Defects 1, 2 and 7
passed macro-level, route-level and file-level tests respectively.

## P15.6 — Repeat-tip recovery / cumulative continuation  COMPLETE

A contributor's second mailbox tip must continue from what the recipient
**already accepted**. The recovery machinery existed and tested clean; the
shipped call site simply never passed the recovered state as `base`, so a second
tip rebuilt from the chain and reused the first tip's update number.

Two invariants were established while closing it:

- **A base must be agreed, not merely signed.** `selectLatest` gained
  `coSignedOnly`, because a contributor's own queued-but-unaccepted proposal is
  a unilateral claim and must not advance their chain.
- **A failed mailbox lookup fails the repeat tip.** Falling back to the chain
  would build at an update number the recipient already holds and report it as
  queued — a tip that can never be accepted, described as waiting.

The final clean Firefox run, with the recipient offline for the entire
contributor sequence:

```text
baseline (recorded)   nonce 3 · 485 / 15 · total 500
tip 1 → QUEUED        nonce 4 · 480 / 20   via the real HTTPS volunteer
                      contributor sig present; recipient + volunteer sigs ABSENT
recipient accepts     Pool.View() 20 ANON
recovery              highest CO-SIGNED state (nonce 4); bare proposals ignored
tip 2 → QUEUED        nonce 5 · 475 / 25 · total 500 = the original deposit
recipient accepts     the cumulative state, through its own console
Pool.View()           25 ANON, re-read from authoritative node state
publish               no EVM transaction (block 231 → 231)
duplicates            idempotent; superseded refused without regression
```

Two wallet prompts per repeat tip, both expected: the mailbox read proof signs a
per-read challenge carrying no channel, nonce or amount and cannot authorize a
payment. The channel-state signature stays separate.

**Privacy is not part of P15** — see "Outstanding work".

## Outstanding work — NOT part of P15

P15 is closed. The tipping system is **not** production-ready on that basis;
these gates sit outside it and are tracked separately.

1. **Broader production / deployment gates.** Deployment, operational,
   security, infrastructure, configuration and monitoring work outside this
   phase. P15's completion says nothing about any of them.

2. **Delegated UI.** The contract side (P15.2) is done and devnet-proven, but
   the browser experience for authorising and managing a delegate is not built
   or validated. Kept separate from P15's completed protocol and browser work.

3. **Privacy layer.** A volunteer is **not anonymous and must not be described
   as one**: a bilateral frame names a channel and a channel names both parties,
   so a mailbox sees who tips whom and how often. The mitigation is
   onion-wrapping the terminal hop (`hub.go`, `onion.go`). This was explicitly
   outside P15 and does not get pulled back into it.

4. **P12-8 reorg / finality gate.** An independent gate. It is not satisfied by
   anything P15 proved, and must not be marked complete on P15's evidence.
   Current observation status, unchanged: **17/30 observations · max depth 1 ·
   56h · 16,865 blocks · observed depths [1]**.

## What P15 deliberately did not do

- **No N-party channel.** Unnecessary.
- **No pool operator or coordinator.** "What if the operator disappears" has no
  subject: the pool is the recipient's view of their own store.
- **No stored aggregate.** It is a sum, computed on read.
- **No batched checkpoints.** `checkpoint()` takes one channel and both
  signatures, so N contributors is N transactions. The honest cost of
  non-custodial pooling, stated rather than engineered away.
- **No `OP_CHECKPOINT` delegation.** Withheld deliberately.
- **No server-side ledger, balance, or per-payment history.**

## Remaining work

1. Load the ethers bundle on the settings page; make a failed `pending()` show a
   real status instead of a stuck placeholder. **Add an assembled test that
   EXECUTES the binding** — reading the file missed this.
2. Expect the operator API's cross-origin boundary to surface next. **It is not
   to be solved with CORS on `/v1/*`.** The node serving its own console (the P7
   pattern) is the shape that fits.
3. Browser: collection → recovery → second tip → Case B → multi-contributor →
   checkpoint.
4. Delegated-mode authorization from the browser.
5. Channel opening from the UI.
6. Then P15.6.

# Final architecture

The finished system should look like this:

```text
                              USER
                               │
                               │ TIP
                               ▼
                     ┌──────────────────┐
                     │ Payment Selector │
                     └────────┬─────────┘
                              │
             ┌────────────────┼────────────────┐
             │                │                │
             ▼                ▼                ▼
       DIRECT CHANNEL      ROUTED HTLC      ERC-20
             │                │                │
             │                ▼                │
             │          ┌───────────┐          │
             │          │   HUB(S)  │          │
             │          └─────┬─────┘          │
             │                │                │
             └────────────────┼────────────────┘
                              ▼
                    ┌──────────────────┐
                    │ Recipient Node   │
                    │                  │
                    │ Channels         │
                    │ HTLC Engine      │
                    │ Router           │
                    │ State Storage    │
                    │ Settlement       │
                    │ Watchtower       │
                    └────────┬─────────┘
                             │
                      recipient policy
                             │
                 ┌───────────┴───────────┐
                 ▼                       ▼
             INTERVAL                 ON CLOSE
                 │                       │
                 └───────────┬───────────┘
                             ▼
                         BLOCKCHAIN
```

---

# Recommended implementation order

The implementation order should therefore be:

```text
P1  V2 state model                         ✓
P2  V2 contract + HTLC + checkpoint        ✓  built, NOT deployed
P3  Persistent V2 store                    ✓
P4  SCPP/1 protocol                        ✓
P5  Payment node                           ✓
P6  Settlement                             ✓
 ↓
P7  Receiving / recipient operations       ✓
      ├── a  channel opening                  ✓
      ├── b  multi-hop routing                ✓
      ├── c  pending HTLC visibility          ✓
      └── d  payment history                  ← last item
 ↓
P8  Browser / wallet integration           COMPLETE
      +-- a  wallet connection
      +-- b  channel opening / funding
      +-- c  MetaMask signing
      +-- d  tip initiation
      +-- e  off-chain state signing
      +-- f  crash / recovery behaviour
 ↓
P9  Award integration
      bronze/silver/gold over a channel
 ↓
P10 Watchtower ────────────┐  production gate
      │                    │  its worst-case response time
 ↓    │                    │  IS challengePeriod
P11 Backup / recovery ─────┘  production gate
 ↓                            monotonic across restore
P12 V2 deployment + migration              ← gated on P10
      deploy → regenerate vectors →
      verify Go against the deployed EVM →
      migrate.  V1 stays live until proven
 ↓
P13 Full security testing
 ↓
P14 Economic / load testing
 ↓
P15 Many-to-one tipping pools                          COMPLETE
      a recipient CHOOSES pooling;
      the phase is still built
 ↓
Remaining before production:
      broader production / deployment gates
      delegated-signing UI
      privacy layer
      P12-8 finality gate (independent)
 ↓
Production
```

**Nothing is marked complete until every item in its phase is implemented and
tested.** A dependency can decide the order work happens in; it cannot make a
requirement disappear, and a phase does not finish because a later one happens
to need the same machinery.

**P15 — many-to-one tipping pools** follows P14. "Optional" there describes a
recipient's choice to enable pooling, not whether the phase is built: it is
required work, held to the same completion bar, and simply sits after the
phases that do not depend on it.

That rule is why routing moved into P7 rather than staying "unscheduled": P7
needs routed payments to be distinguishable from direct ones, so routing gets
built here.

**Why deployment comes last rather than next.** `challengePeriod` is
`immutable`, and it cannot be chosen responsibly until P10 has measured what
response window a watchtower actually needs. Deploying first would freeze a
security parameter before the number that determines it exists:

```text
P6 Settlement
      │
      ▼
P10 Watchtower ────┐
      │            │
      ▼            │
 derive challengePeriod
      │            │
      └────────────┘
             │
             ▼
   P11 V2 deployment gate
             │
      ┌──────┴──────┐
      ▼             ▼
 regenerate     live integration
 vectors        + migration
             │
             ▼
      V1 stays live
      until proven
```

The gate is not being avoided. It is waiting on information one of its
irreversible inputs requires.

**P10 is where "works" becomes "safe to put real money in."** A watchtower and
a recovery design exist for the same failure — an old state treated as current.
The watchtower stops somebody else doing that to you; recovery stops you doing
it to yourself. Neither is deferrable past first real money.

**Routed and multi-hop execution is not in this list**, and the section on it is
marked unscheduled. Everything it needs is built — HTLCs in the contract, locks
in the state machine, `LOCK_ADD`/`LOCK_SETTLE`/`LOCK_REFUND` over SCPP/1 — so it
is a matter of when it is wanted, not what it depends on.

**P10 and P11 are both production gates**, not enhancements. They exist for the
same failure: an old state being treated as current. A watchtower stops somebody
else doing that to you; recovery stops you doing it to yourself. Neither can be
deferred past first real money.

**Deploying V2 does not go where it looks like it goes.** It comes after P4 and
its integration tests, not now — hardhat's chain id 31337 and local deploy
address are not production vectors, and the digest includes both deliberately.
V1 stays untouched until the migration completes, which is the rollback path.

The important difference from the previous plan is that **P6 is not a future feature**. The routing architecture is implemented as part of the same payment system.

A direct tip simply takes the shortest possible route:

```text
Tipper ───────── Recipient
```

while a routed payment takes:

```text
Tipper → Hub → Recipient
```

and uses HTLCs.

The direct and routed paths therefore share the same underlying channel, state, persistence, settlement, and security infrastructure from day one.

---

# Outstanding decisions

### D1. Who is allowed to operate a recipient node?

The cleanest model is:

```text
recipient operates their own node
```

but not every author or creator will have a machine capable of doing so.

Possible models:

```text
self-hosted
platform-hosted
third-party hosted
```

This must be decided explicitly because platform hosting creates a materially different custody/trust model.

### D2. How does the website authenticate to the payment node?

> **This stopped being hypothetical in P15.5.** The recipient dashboard is
> served by Flask on one origin and must read the recipient's own node on
> another. `/v1/*` is loopback-only, token-gated and deliberately has no CORS,
> so the browser cannot reach it — and that boundary is not to be relaxed to
> make a page work. The shape that fits is the P7 one: **the node serves its own
> console**, same origin, and the website links to it. Decide this before more
> dashboard work.

The payment node controls money-bearing state, so the website needs narrowly
scoped authorisation rather than unrestricted control over it.

**What ships today is a placeholder, deliberately labelled as one.** A single
shared bearer token, required on every route, with the API refusing to be
constructed without it. That is an acceptable development boundary because it is
mandatory, consistent, and not pretending to be the answer — but it proves only
possession of one global secret.

Two things the real design needs that the placeholder does not have:

- **Separate read and write permission.** Reading balances, channel status and
  payment status is a different capability from creating a payment, recovering,
  settling or closing. Today one token does all of it.
- **Identity, not just possession.** The mechanism should say *which*
  application or user is authorised, so a compromised credential has a blast
  radius and an audit trail rather than being indistinguishable from every other
  caller.

Deliberately not solved inside P5 — it is a security-design task, and doing it
badly under time pressure is worse than doing it after.

### D3. Who pays which blockchain costs?

Current intended model:

**Tipper:**

* channel funding/deposit when entering a direct channel.

**Recipient:**

* settlement;
* close-related transactions;
* recipient-side blockchain operations.

**Routing hubs:**

* their own channel liquidity and associated costs;
* potentially a routing fee.

The exact fee model remains to be decided.

### D4. How should first-time tipping work?

The system should not force:

```text
first-time user
    ↓
fund channel
    ↓
5 ANON tip
```

if that costs more than simply transferring 5 ANON.

The permanent fallback is:

```text
ERC-20
```

The UI should make channel funding attractive when repeated tipping makes the economics favorable.

### D5. What does a routed tip disclose?

Direct channels inherently reveal the two channel participants.

Routed payments may use:

* onion routing;
* blinded paths;
* multipath;
* other privacy mechanisms already represented in the codebase.

The final privacy model needs to be specified rather than assumed.

### D6. How do other tipping systems use this?

Article tipping, newsroom tipping, streams, posts, and other tip implementations should eventually use this same payment layer rather than creating separate payment mechanisms.

---

# Traps

* **Never settle an older state.** This can destroy money while appearing to succeed.
* **Never accept a state without verifying the counterparty signature.**
* **Never accept a state that does not conserve channel funds.**
* **Never allow an HTLC to be claimed twice.**
* **Never allow an expired HTLC to be claimed.**
* **Never flip `Capabilities()` simply to make routing execute.**
* **Never treat the recipient's node as automatically trusted.**
* **Never make the website the holder of the tipper's signing key.**
* **Never synthesize a fake `tx_hash` for channel payments.**
* **Never assume a recipient's channel applies to every tipper.**
* **Never require a first-time tipper to open a channel when an ordinary ERC-20 payment is economically superior.**
* **Never put real money into production until stale-state protection/watchtower behavior has been tested.**
* **Treat persisted channel state as money. Losing the latest state is equivalent to losing the latest proof of the balance.**

---

# End state

The system is not:

> "A basic tipping system that we might turn into Lightning later."

It is:

> **A Lightning-style payment network from the beginning, with direct bilateral channels as the simplest payment route and HTLC-mediated routing available through the same underlying infrastructure.**

The recipient operates the payment endpoint.

The tipper operates only their wallet/browser.

The recipient chooses when accumulated value is committed to the blockchain.

And the existing ERC-20 transfer remains available whenever opening or routing through a channel does not make economic sense.
