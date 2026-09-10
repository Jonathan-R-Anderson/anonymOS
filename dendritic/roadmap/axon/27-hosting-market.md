# Part VIII — Decentralized Dynamic Hosting and the Provider Market

**Paying the nodes that carry the burden, and only for work that can be proved.**

---

## 64. The Finding That Shapes Part VIII

**The hard part is not the marketplace. It is proving that work happened.**

Advertising prices, matching buyers to sellers, and settling in escrow are
well-understood mechanism design, and Part VIII specifies them in a few
sections. The problem that decides whether any of it is worth building is one
line long:

```text
   Provider says:  "I served 100 TB and stayed up 99.99%."
   Network says:   "Here is $500."
```

Every other decision in this Part is downstream of refusing that exchange. §69
is therefore the longest section and the one to read first; §66–§68 are the
market that sits on top of it, and they are comparatively easy.

Three consequences bind the rest of Part VIII:

1. **Static and dynamic hosting are different products and must not share a
   payment model.** Part VII's content layer is *verifiable by construction*: an
   object either hashes to its CID or it does not, so a storage provider's claim
   is checkable by anyone holding the manifest. Dynamic execution has no such
   property — the output of `POST /api/login` is whatever the code says it is,
   and a second provider running the same code need not produce the same bytes.
   **Content-addressing does not extend to computation**, and pretending it does
   is the trap this Part exists to avoid.

2. **The unit of trust is the request receipt, not the provider's report.** §69
   builds usage from artifacts the *client* co-signs, so a provider cannot
   manufacture demand that no one made. What remains manufacturable — a
   colluding client — is bounded, priced and stated rather than solved.

3. **This is the accounting plane, not a new network.** Discovery is §7's DHT,
   settlement is §14's channels and the deployed PoF contracts, staking is
   `StakeVault`, and identity is §5's taxonomy with one addition (§65.3). Part
   VIII adds a market and a meter; it adds no transport, no naming and no
   consensus.

### 64.1 What already exists

| Capability | Where | What Part VIII does with it |
|---|---|---|
| Compute execution on nodes | `internal/compute`, `internal/computeworker`, `internal/computeimage`, `internal/microvm` | The execution substrate. Providers already run isolated workloads; this Part prices and meters them |
| Docker/microVM isolation | `internal/microvm`, `dcs` deploy paths | The runtime sandbox for untrusted third-party code (§65.2) |
| Capability advertisement | `NodeRegistry.sol` capability bitmap; relay descriptors (§5.2) | Extended with a `ProviderAd` record (§66) |
| Bonded stake + slashing | `StakeVault.sol`, `DisputeManager.sol` | Provider collateral (§72) — no new contract needed for v1 |
| Epoch settlement | `EpochManager.sol`, `RewardDistributor.sol` | Batch payout rail (§71) |
| Payment channels + HTLCs | `internal/channel`, SCPP/1, `doc/p13-multipath-security-table.md` | Off-chain metered payment (§71.2) |
| Audit/challenge machinery | `internal/p2p/challenge.go`, `recall_lying_holder_test.go` | The pattern §69.3's audits follow |
| Traffic accounting | `internal/traffic/traffic.go` | Bandwidth metering input |

**What must be built:** the provider advertisement and its DHT record class, the
hosting contract, the receipt format and its verification, the metering
aggregator, the scheduler, and the failover controller. **What must not be
built:** a new VM, a new payment rail, or a consensus layer.

---

## 65. The Hosting Model

### 65.1 Three resource classes, three different economics

```text
   STATIC          content-addressed, verifiable by hash, cacheable by anyone
     │             → Part VII. Paid per GB-month stored + GB served.
     │               Fraud is bounded by §10.9's storage audits.
     │
   DYNAMIC         executed on a provider, output not reproducible
     │             → this Part. Paid per CPU-second, GB-hour RAM, request.
     │               Fraud is bounded by §69's receipts. THIS IS THE HARD ONE.
     │
   STATE           mutable, must survive provider churn
                   → §57's distributed state layer, NOT the provider's disk.
                     Paid as storage. A provider holding the only copy of a
                     site's state is a hostage situation, not a hosting product.
```

The third row is a ruling, not an observation: **a dynamic provider is a compute
rental, never a system of record.** State lives in the network's own storage
(§57) so a provider can be replaced mid-contract without the site losing data.
A design where the provider owns the database recreates the single origin this
whole programme exists to remove, and adds an economic lock-in on top of it.

### 65.2 The runtime, and why the choice is narrow

A provider executes code it did not write, on behalf of someone it cannot
identify, for money. The runtime must therefore be sandboxable, resource-
meterable and deterministic enough to audit.

| Runtime | Isolation | Meterable | Auditable | Verdict |
|---|---|---|---|---|
| **WASM** (wasmtime/wasmer) | Strong, in-process | CPU fuel, memory pages — precise | **Deterministic** given the same inputs, if host calls are constrained | **v1 default** |
| microVM (Firecracker) | Strong, kernel-level | cgroup counters | No — full OS nondeterminism | v2, for workloads WASM cannot host; `internal/microvm` exists |
| Container (Docker) | Namespace-level | cgroup counters | No | Available (`internal/compute`) but weakest isolation; opt-in per provider |
| Native process | None worth the name | Coarse | No | **Rejected.** Running arbitrary native code for pay is a compromise vector, not a product |

**WASM first is the ruling**, and its determinism is why: §69.4's redundant
execution can only compare outputs when the same input reproducibly yields the
same bytes. A nondeterministic runtime forfeits the single strongest fraud check
available, so it is a v2 capability that pays a higher audit cost.

### 65.3 One new identity class

Constitution §3's taxonomy gains exactly one member, and it is deliberately
*not* the node's own identity:

```text
   ProviderIdentity   Ed25519. Signs advertisements, receipts and usage
                      reports. Bonded via StakeVault, so it carries economic
                      weight. Distinct from NodeIdentity so that a node can
                      sell compute without exposing its relay/storage identity
                      to customers, and so that losing a provider bond does not
                      slash a relay's standing.
```

Everything else reuses §3: the customer is a `DomainIdentity` (they are buying
hosting *for a name*), settlement uses `PaymentIdentity`, and the workload's
service endpoint is a `ServiceIdentity` published exactly as in §9.

---

## 66. Provider Advertisements

### 66.1 The record

Published to the DHT under its own record class (§7.1), signed by
`ProviderIdentity`, short-lived so a dead provider ages out rather than being
garbage-collected by hand:

```text
  ProviderAd
    version            u8
    provider           32   ProviderIdentity pubkey
    bond_ref           32   StakeVault position; 0 is legal and means "unbonded"
    runtimes           u16  bitmap: WASM | MICROVM | CONTAINER
    capacity           { cpu_millis, mem_mb, storage_gb, bw_mbps, max_replicas }
    price              { per_cpu_second, per_mem_gb_hour, per_storage_gb_month,
                         per_gb_egress, per_million_requests }   all u64, in
                         the smallest unit of the settlement asset
    price_lock_until   u64  unix seconds; see §66.3
    sla                { availability_ppm, p99_latency_ms, durability_ppm }
    regions            []u16  coarse region codes; NOT an address (§66.4)
    issued_at, expires_at   u64   expires_at − issued_at ≤ 6 h
    signature          64
```

Prices are quoted per unit of *measured* resource, never per month. A monthly
figure is a derived estimate shown in the UI (§74); the contract meters actual
use, because a flat monthly price paid to an unverified provider is precisely
the exchange §64 refuses.

### 66.2 Discovery

Ads live in a dedicated keyspace so a customer can range-scan by capability
without walking every record in the DHT:

```text
   ad_key = H("AXON-provider-ad-v1" ‖ 0x00 ‖ runtime_class ‖ region ‖ provider)
```

A customer's query is a bounded scan over `(runtime, region)` prefixes, returning
signed ads it then filters locally. **Selection happens on the client**, not in
any index a party could bias — there is no matching service, and there must not
be one, because whoever ranks the market controls it.

### 66.3 Price locks, and why they are mandatory

An advertised price that can change after a contract is signed is not a price.
`price_lock_until` is the provider's commitment that quoted rates hold for
contracts signed before that instant; the contract records the rates it was
signed at (§67.1), and metering settles against *those*, not against whatever
the provider advertises later. A provider may re-price freely for *new*
contracts. This is the whole of §13's "dynamic pricing" requirement, and it
needs no mechanism beyond writing the rate into the contract.

### 66.4 What an ad must never contain

No IP address, no hostname, no port. A provider is reached the same way every
other service is (§9's rendezvous), so publishing a market of priced,
capability-tagged, geographically-labelled endpoints would hand an attacker a
target list sorted by value. `regions` is coarse (continent-scale) and exists
only for latency and diversity selection; §73 carries the residual that even
coarse region plus capacity is a fingerprint.

---

## 67. Hosting Contracts

### 67.1 The contract

```text
  HostingContract
    contract_id        32   H(customer ‖ provider ‖ nonce)
    customer           32   DomainIdentity of the site being hosted
    provider           32   ProviderIdentity
    workload_cid       32   the deployable (WASM module + manifest), §68
    rates              {…}  COPIED from the ad at signing time (§66.3)
    caps               { max_cpu_seconds, max_mem_gb_hours, max_egress_gb,
                         max_requests }        the customer's spend ceiling
    sla                {…}  copied from the ad
    replicas           { min, preferred, max }
    escrow_ref         32   funding position (§71)
    starts_at, ends_at u64
    sig_customer       64
    sig_provider       64
```

Both sign: the customer commits funds, the provider commits capacity. A contract
with one signature is an offer, not an agreement.

**`caps` is the customer's protection against a metering bug or a hostile
provider**: metered usage beyond the cap is unpaid and the contract is
terminable. Without it, "pay for measured use" is an unbounded liability, which
no sane customer accepts and no honest provider needs.

### 67.2 The lifecycle

```text
   ADVERTISED → OFFERED → SIGNED → FUNDED → ACTIVE ⇄ DEGRADED → SETTLING → CLOSED
                                                │                    ▲
                                                └── VIOLATED ─────────┘
```

`DEGRADED` is a first-class state, not an error: a provider missing its SLA is
still serving, and the correct response is reduced payment (§70) plus scheduler
pressure toward a replacement (§72), not an immediate cutoff that takes the
customer's site down to punish the provider.

---

## 68. Deployment and the Scheduler

### 68.1 The deployable

A workload is a content-addressed bundle — the same object model as Part VII, so
it replicates, verifies and caches with no new machinery:

```text
   workload_cid → { module.wasm, manifest.json, static_root_cid, state_ref }
```

`manifest.json` declares the routes that require execution, so the resolver can
split a request between the static DAG and a provider without asking anyone:

```text
   GET  /            → static (Part VII)
   GET  /assets/*    → static
   POST /api/login   → dynamic  (provider)
   GET  /api/feed    → dynamic, cacheable 30s
   WS   /socket      → dynamic, sticky session
```

### 68.2 Selection

The customer's client scores candidate ads locally. Price is one term and
deliberately not the dominant one:

```text
   score = w_price · normalised_price
         + w_sla   · (advertised_availability × historical_delivery)   ← §72
         + w_lat   · measured_latency
         + w_div   · diversity_bonus(region, operator, ASN)
         + w_bond  · min(1, bond / bond_reference)
```

with a hard constraint that no two selected providers for one contract set may
share an operator or region — **ten replicas from one operator are one replica**,
which is §56.2's finding restated for compute, and it inherits §56.2's
unsolved half: operator distinctness is only as real as §15's Sybil resistance.

### 68.3 Failover

```text
   replicas ≥ min          → steady state
   replica dies            → traffic re-routed to survivors within one
                             rendezvous rotation (§9.2), no customer action
   replicas < min          → scheduler signs a contract with a fresh provider
                             from the same ad set, funds it from the same
                             escrow, and pulls state from §57 (NOT from the
                             dead provider, which may be dead because it is
                             hostile)
   replicas < min for > T  → contract enters DEGRADED; customer notified
```

The property this buys is the one the brief asks for — always-online without
owner intervention — and the reason it works is §65.1's third ruling: because
state never lived on the provider, replacing one is a scheduling action rather
than a data migration.

---

## 69. Metering, and the Problem That Decides Everything

### 69.1 Why a provider's own report is worthless

Self-reported usage is a request for payment, not evidence. §35.1 established
this for bandwidth — two colluding relays sign each other's receipts at the cost
of two signatures — and dynamic hosting is worse, because a provider can
manufacture *requests* as well as attest to them. The design therefore never
pays on a provider's assertion.

### 69.2 The request receipt

The unit of account is a receipt the **client** co-signs. A provider cannot mint
demand that nobody made, because it cannot forge the client's signature:

```text
  Receipt
    contract_id     32
    request_hash    32   H(method ‖ path ‖ body_hash ‖ nonce)
    response_hash   32   H(status ‖ body_hash)
    usage           { cpu_micros, mem_mb_millis, egress_bytes }
    served_at       u64
    sig_provider    64
    sig_client      64   ← the load-bearing signature
```

The client is anonymous (§4), so a receipt naming a client identity would be a
deanonymisation channel. Receipts are therefore signed with **blind-issued
tokens** — the same primitive as §14's relay payment and §35's bandwidth
attestation, specified once and shared (§73 carries the linkage risk that
sharing creates).

**What this bounds and what it does not.** It bounds fabricated volume: usage
must correspond to real requests from real token-holding clients. It does *not*
bound a provider that colludes with clients it controls — those are real requests
by real tokens, and the only defences are the token's issuance cost (§14) and
the pattern analysis in §69.5. That residual is stated in §73 and priced, not
solved.

### 69.3 Probabilistic audit

Independent nodes issue unannounced requests indistinguishable from ordinary
traffic and check the response, the latency and the receipt. This follows the
existing lying-holder pattern (`recall_lying_holder_test.go`), with the same
caveat §35.5 raised: **audits work only while they are indistinguishable from
real traffic.** A provider that can recognise an audit serves it perfectly and
everything else badly. Making audit traffic indistinguishable is `[NEEDS
RESEARCH]` and is the weakest link in this section.

### 69.4 Redundant execution

For contracts that opt in, `n` providers execute the same request and the
responses are compared. This is the strongest available check and it is only
available under a deterministic runtime (§65.2) — which is the concrete reason
WASM is the default. It costs `n×` the compute, so it is a per-route policy
("compare `/api/transfer`, not `/api/feed`"), never a global mode.

### 69.5 Aggregation and settlement input

```text
   receipts (per request)
        │  batched, deduplicated by request_hash
        ▼
   usage report (per provider, per epoch)   ← signed by provider AND
        │                                     supported by client receipts
        ▼
   aggregator scores against SLA (§70)
        │
        ▼
   EpochManager settlement (§71)
```

Aggregators are bonded and their output is challengeable, exactly as
`EpochManager` already works for PoF — no new trust role is introduced.

---

## 70. SLA Scoring and Payment Adjustment

Measured availability, not claimed, and the tiers are in the contract so neither
side argues afterwards:

| Delivered availability | Payment | Rationale |
|---|---|---|
| ≥ contracted | 100 % | Met the deal |
| ≥ 99 % of contracted | 90 % | Missed slightly; still served |
| ≥ 95 % of contracted | 50 % | Materially failed |
| < 95 % of contracted | 0 % + slash eligible (§72) | Contract violation |

Availability is measured by the same distributed probes that drive the public
status board (§21's monitors), from multiple vantage points — a provider is not
asked whether it was up, and neither is any single observer.

**The honest limit:** availability is measurable; *correctness* largely is not.
A provider that returns fast, well-formed, wrong answers scores 100 % on this
table. Redundant execution (§69.4) is the only defence, it applies only to
deterministic workloads, and it costs `n×`. §73 records this as the residual
that most limits what dynamic hosting can promise.

---

## 71. Escrow, Settlement, and Keeping It Off-Chain

### 71.1 The flow

```text
   customer funds escrow  ──────────────► on-chain, once per contract period
        │
        ├─ per-request receipts ────────► off-chain, high frequency
        ├─ per-epoch usage reports ─────► off-chain, aggregated + challenged
        │
        └─ epoch settlement ────────────► on-chain, batched via EpochManager
                                          → RewardDistributor Merkle claim
```

The rule from §14 stands unchanged: **high-frequency activity never touches the
chain.** A hosting contract is one funding transaction and one settlement claim
per epoch, regardless of whether it served ten requests or ten million.

### 71.2 Which rail

Payment channels (SCPP/1, `internal/channel`) already exist and already handle
HTLCs and multipath, so a long-lived customer↔provider relationship uses a
channel and settles on close. Short or one-off contracts use escrow plus epoch
settlement, avoiding a channel open/close for a week's hosting. Both rails
exist; Part VIII adds none.

### 71.3 Refunds

Unused escrow returns to the customer at contract close — metered payment means
a site with no traffic costs almost nothing, which is the correct incentive and
the opposite of a monthly subscription's. §74's UI must therefore quote an
*estimate*, never a bill.

---

## 72. Reputation and Staking

Reputation is **measured delivery**, never self-description:

```text
   ProviderRecord (derived, not published by the provider)
     epochs_active, contracts_completed, contracts_violated
     delivered_availability   ← from §70's probes
     receipt_volume           ← client-attested (§69.2)
     audit_pass_rate          ← §69.3
     disputes_upheld          ← DisputeManager
     bond, bond_age
```

Stake makes the numbers cost something. A provider bonds via `StakeVault`;
violation (§70's bottom tier) or proven fraud makes the bond slashable through
the existing `DisputeManager`. The calibration question — how large a bond must
be for the market to mean anything — is **exactly §33's unresolved problem** and
is not re-derived here: it inherits §33's answer, including that the answer is a
price rather than a guarantee.

**Unbonded providers are permitted and are marked as such.** Refusing them makes
the market a capital club on day one; the selection score (§68.2) already weights
bond, so the market prices the difference instead of the protocol banning it.

---

## 73. Security Model

| Attack | Component | Mitigation | Residual risk |
|---|---|---|---|
| Fabricated usage | Metering | Client-co-signed receipts (§69.2) | **A provider colluding with clients it controls generates real receipts.** Bounded by token issuance cost and §69.5 pattern analysis; not eliminated |
| Fake capacity / SLA claims | Ads | Delivered-availability scoring (§70,§72); bond at risk | A new provider has no history; the market's cold-start is genuinely exploitable |
| Audit evasion | Auditing | Unannounced, traffic-shaped audits (§69.3) | `[NEEDS RESEARCH]` — a provider that distinguishes audits defeats them entirely |
| Wrong-but-fast responses | Execution | Redundant execution (§69.4) where deterministic | **Largely unmitigated.** Nondeterministic runtimes and non-opted routes have no correctness check (§70) |
| Malicious workload attacking the provider | Runtime | WASM sandbox; microVM for v2; per-contract resource caps | A sandbox escape is a full host compromise. This is the provider's largest risk and the reason native execution is rejected outright |
| Provider reads customer data | Execution | State lives in §57's store, encrypted; provider holds no system of record | **A provider executing code necessarily sees the plaintext it processes.** Confidential compute is out of scope; customers must treat providers as able to read live request data |
| Customer refuses to pay | Escrow | Funds locked before ACTIVE (§67.2) | Escrow exhaustion mid-period; caps (§67.1) bound it |
| Provider disappears mid-contract | Failover | §68.3, state from the network not the provider | Requests in flight are lost; sticky WebSocket sessions break |
| Market manipulation via ad spam | Discovery | Ads are bonded-or-marked, short-lived, client-ranked (§66.2) | An unbonded flood still costs scan effort; no central index exists to police it |
| Provider deanonymisation via ads | Discovery | No address in ads (§66.4); reached via rendezvous | Coarse region + capacity + price is a fingerprint; a distinctive provider is identifiable |
| Token linkage across subsystems | Receipts | Shared blind-token primitive with §14/§35 | **If issuance epochs are shared, redemption may correlate a payer with an attester.** Must be separated and tested (§35.3's E8.5 applies here too) |

---

## 74. Phases HM1–HM9

| Phase | Prereqs | Deliverables | Effort | Conf. | Exit criterion | Does NOT establish |
|---|---|---|---|---|---|---|
| **HM1** Runtime + sandbox `[BUILD NOW]` | `internal/compute` | WASM host with CPU-fuel and memory metering; per-contract resource caps; deterministic host-call surface | 3–5 em | **High** | A workload runs, is metered to within a stated error, and cannot exceed its caps or escape the sandbox in a red-team pass | Anything economic |
| **HM2** Provider ads `[BUILD NOW]` | HM1, §7 | `ProviderAd` record, DHT keyspace, signing, expiry, client-side scan + local ranking | 2–3 em | **High** | A customer discovers and ranks providers with no index and no address disclosed | That prices are honest |
| **HM3** Contracts + escrow `[BUILD NOW]` | HM2, §14 | `HostingContract`, dual signing, escrow funding, caps, lifecycle state machine | 3–4 em | Medium | A funded contract moves ADVERTISED→ACTIVE and refunds unused escrow at close | Metering correctness |
| **HM4** Receipts + metering `[NEEDS RESEARCH]` | HM3, §14 blind tokens | Receipt format, blind client co-signing, batching, dedup, aggregation | 5–8 em | **Low** | A provider cannot inflate billed usage without colluding clients — falsified by any inflation from provider-side action alone | The colluding-client residual (§73) |
| **HM5** SLA + probes `[BUILD NOW]` | HM3, §21 monitors | Availability measurement from ≥3 vantage points; §70 payment tiers | 2–3 em | Medium | A provider throttled to 97 % availability is paid the 50 % tier automatically | Correctness of responses |
| **HM6** Scheduler + failover `[BUILD NOW]` | HM3, §57 state | Selection scoring, diversity constraints, replica manager, automatic replacement | 4–6 em | Medium | Killing a provider mid-contract restores `min` replicas with no customer action and no state loss | That replicas are independent (§56.2) |
| **HM7** Audits + redundant execution `[NEEDS RESEARCH]` | HM4, HM1 | Indistinguishable audit traffic; n-way comparison for deterministic routes | 4–8 em | **Low** | A provider serving audits well and traffic badly is detected within a stated window — **failure here is a legitimate reported outcome** | Detection under a provider that fingerprints audits |
| **HM8** Reputation + staking `[BUILD NOW]` on existing rails | HM5, `StakeVault` | Derived provider record; bond weighting in selection; slashing via `DisputeManager` | 2–4 em | Medium | A violating provider is slashed and drops in ranking without manual action | Bond sizing — inherits §33 |
| **HM9** Deployment UX | HM6 | `dendritic deploy`: declare requirements, auto-select, fund, deploy, monitor | 2–3 em | Medium | One command takes a site from source to served, and prints the providers and estimated cost | That the estimate matches the bill |

**Total: 27–44 engineer-months.** HM1–HM3 (8–12 em) produce a working market on
trusted metering; **HM4 is what makes it honest**, and it is the phase to fund or
not fund — without it the market pays on assertion, which §64 rejects.

### 74.1 Sequencing

```text
   §57 state ──┐
   internal/   ├──► HM1 ──► HM2 ──► HM3 ──┬──► HM5 ──► HM8
   compute ────┘                          │
                                          ├──► HM4 ──► HM7   ← the honest half
                                          │
                                          └──► HM6 ──► HM9
```

HM4 and HM7 gate every claim that a provider was paid for work it did. HM6/HM9
can ship first and deliver a usable product on *trusted* metering, provided the
documentation says so plainly and the UI does not imply verification that does
not exist.

---

## 75. What Part VIII Does NOT Establish

- **That dynamic hosting can be made trustless.** It cannot, on these
  assumptions. Receipts bound provider-side fabrication; colluding clients,
  wrong-but-fast responses, and audit fingerprinting all survive (§73).
- **That providers cannot read customer data.** They execute the code; they see
  the data. Confidential computing is out of scope and customers must be told
  this in the product, not in a footnote.
- **That the market resists capture.** Selection is client-side and bonds are
  weighted, but §33's plutocracy result applies unchanged: a well-capitalised
  operator can be the cheapest and the most bonded simultaneously.
- **That replicas are independent.** Inherits §56.2 — operator distinctness is
  unverifiable while the transport hides addresses.
- **That the estimate matches the bill.** Metered pricing means a traffic spike
  costs money; the caps in §67.1 bound it, and §74's HM9 exit criterion
  deliberately refuses to claim otherwise.
- **Any of it is implemented.** §64–§75 are a design over an existing compute
  substrate; every artifact named in HM1–HM9 is unwritten.
