# AXON — A Decentralized Anonymous Internet Overlay

**An engineering roadmap.**

> A decentralized, cryptographically addressed Internet overlay combining
> Tor-style anonymous routing, I2P-style tunnel-oriented services, Freenet-style
> distributed content, and blockchain-backed, community-governed domain
> ownership.

---

## About this document

This is an engineering specification and a build plan, not a concept paper. It
specifies byte layouts, key schedules, state machines, algorithms, contract
interfaces, storage slots, test invariants, and a phased plan with falsifiable
exit criteria. Where a problem is unsolved it says so, and says what the best
partial answer is. It never claims perfect anonymity; every anonymity property in
it is scoped to a stated adversary class.

**AXON is a placeholder name.** So is the `axon` root suffix. Exactly one string
in the system is a compile-time constant (`ROOT_SUFFIX`), and §11.0.2 explains
why that one is not up for a vote when everything above it is.

**The scope ends at the infrastructure API.** Applications — forums, chat, media,
social, marketplaces — are explicitly out of scope. This document builds the
network they would run on and stops there.

**The network runs over the ordinary Internet.** No radio, no LoRa, no mesh
transports. It uses no Tor, I2P or Freenet code, network, or infrastructure; it
borrows their architecture and, where they contradict each other, rules between
them (§2).

### The three things to read first

**This is not a greenfield project.** A substantial Go node already exists —
libp2p and Kademlia, an erasure-coded content store with audit challenges, a
mainnet-verified Ethereum light client, payment channels, and staking contracts —
and it currently **outsources anonymity to I2P over SAM**. §1 inventories what
exists and measures how deeply the I2P dependency is wired in. §2 resolves the
twenty-one architectural contradictions that make "combine Tor, I2P and Freenet"
harder than it sounds. §23 is the phased plan.

### The naming model in one paragraph

There is no single TLD. There is a fixed, unvotable **root suffix**, and beneath
it a governed set of **namespaces** — `lab`, `corp`, `research` — each created by
on-chain vote and each with its own registrar and its own admission policy, so a
name is `alice.lab.axon`. Approving a namespace creates an empty namespace, not a
set of names: nothing is auto-assigned to anyone, registration is per-name and
gated by that namespace's registrar, and a service may hold zero names or many
(§11.0.3). Underneath all of it, every service also has a permanent,
self-certifying, ungoverned **Layer 1 address** that can be vanity-mined and that
no vote can take away (§11.9).

### Conventions

| Marker | Meaning |
|---|---|
| `[BUILD NOW]` | Well-understood engineering. No research risk. |
| `[NEEDS RESEARCH]` | The design is not settled; prototyping or literature work is required before committing. |
| `[UNSOLVED]` | No deployed system has a good answer. AXON will not either. The document says what it does instead. |
| `R1`…`R24`, `C15`…`C21` | The rulings that resolve conflicts between the source architectures (§2, §11.0). |
| §N.M | Cross-reference within this document. |

Every section ends with **"What this section does NOT establish"**. Those
paragraphs are the most important prose in the document; they are where the
design is honest about its limits.

---

## Contents

**Part I — Foundations**

| § | Title |
|---|---|
| 1 | Scope, objective, and what already exists |
| 2 | Where Tor, I2P, Freenet, DHTs and blockchains contradict each other |
| 3 | System architecture |
| 4 | Adversary model and anonymity assumptions |

**Part II — Subsystems**

| § | Title |
|---|---|
| 5 | Cryptographic identity system |
| 6 | Secure transport and NAT traversal |
| 7 | The DHT |
| 8 | Anonymous routing — circuits, cells, and onion cryptography |
| 9 | Tunnel pools, rendezvous, and anonymous services |
| 10 | Distributed content storage |
| 11 | The governed namespace system |
| 12 | Ethereum root registry, registrars, and governance |
| 13 | The resolver |
| 14 | Payments, accounting, and incentives |
| 15 | Sybil resistance and admission control |
| 16 | Traffic analysis resistance |
| 17 | Node roles, gateways, and deployment topologies |

**Part III — Engineering**

| § | Title |
|---|---|
| 18 | Threat model |
| 19 | Implementation architecture |
| 20 | Infrastructure APIs and CLI |
| 21 | Testing strategy |
| 22 | Deployment, monitoring, versioning, and migration |

**Part IV — Plan**

| § | Title |
|---|---|
| 23 | Phased development plan (P0–P16, plus P9b) |
| 24 | The minimal viable network (M1–M6) |
| 25 | Practicality triage |

**Part V — The Eight Hard Problems** *(a research-and-engineering programme to convert §25's `[UNSOLVED]` list into measured outcomes)*

| § | Title |
|---|---|
| 26 | The eight problems: definitions and measurable properties |
| 27 | Status matrix and how this programme is judged |
| 28 | WS1 — Long-term intersection resistance |
| 29 | WS2 — Abuse handling without re-centralisation |
| 30 | WS3 — Eclipse resistance and network-view consistency |
| 31 | WS4 — Decentralized blockchain access |
| 32 | WS5 — Traffic-analysis resistance |
| 33 | WS6 — Economic and Sybil calibration |
| 34 | WS7 — Anonymity-set size and effective anonymity |
| 35 | WS8 — Bandwidth measurement without a central authority |
| 36 | The unified adversarial simulator |
| 37 | Quantitative security targets |
| 38 | Phases P17–P26 |
| 39 | Risk register and new attacks introduced |
| 40 | Updated threat model, readiness criteria, and the answer |

**Part VI — Multipath Transport and Traffic Aggregation** *(distributing one logical connection across independent overlay paths, and what that costs)*

| § | Title |
|---|---|
| 41 | The finding that shapes Part VI |
| 42 | Architecture and layer placement (L4.5) |
| 43 | The multipath transport substrate |
| 44 | Packet scheduling |
| 45 | Congestion control and fairness |
| 46 | Path lifecycle and diversity |
| 47 | Path-level cryptography |
| 48 | Privacy analysis of multipath |
| 49 | Performance modes, clearnet aggregation, and the virtual interface |
| 50 | Multipath phases MP1–MP6 |
| 51 | Adjacent primitive — time-triggered dead drops |

**Part VII — Distributed Website State and Self-Replicating Hosting** *(turning a website from something a server hosts into a distributed, self-replicating network object)*

| § | Title |
|---|---|
| 52 | The finding that shapes Part VII |
| 53 | Website as a distributed object |
| 54 | Publisher identity and the chain binding |
| 55 | Self-replicating cache-on-read |
| 56 | Replication factor, diversity, and self-healing |
| 57 | Immutable vs mutable — the distributed state layer |
| 58 | Retrieval: privacy routing and multipath, composed |
| 59 | Storage economics |
| 60 | Security model for distributed websites |
| 61 | Phased plan DW1–DW11 |
| 62 | The origin-import path and the live deployment |
| 63 | What Part VII changes in the rest of the document |

**Part VIII — Decentralized Dynamic Hosting and the Provider Market** *(paying the nodes that carry the burden, and only for work that can be proved)*

| § | Title |
|---|---|
| 64 | The finding that shapes Part VIII |
| 65 | The hosting model |
| 66 | Provider advertisements |
| 67 | Hosting contracts |
| 68 | Deployment and the scheduler |
| 69 | Metering, and the problem that decides everything |
| 70 | SLA scoring and payment adjustment |
| 71 | Escrow, settlement, and keeping it off-chain |
| 72 | Reputation and staking |
| 73 | Security model |
| 74 | Phases HM1–HM9 |
| 75 | What Part VIII does not establish |

---

## The system in one diagram

```text
                        APPLICATIONS  (out of scope)
                              │
        ══════════════════════╪══════════════════════  L8 INFRASTRUCTURE API
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
        LIVE SERVICES                 DISTRIBUTED CONTENT      L6 SERVICE/CONTENT
              │                               │
              ▼                               │
         RENDEZVOUS                           │                 L5 RENDEZVOUS
              │                               │
              ▼                               ▼
       MULTIPATH TRANSPORT ─── split · schedule · reassemble    L4.5 MULTIPATH
              │                               │
              ▼                               ▼
      ANONYMOUS TUNNELS  ◄─── carries ───►  RETRIEVAL           L4 TUNNEL/CIRCUIT
              │                               │
              └───────────────┬───────────────┘
                              ▼
                             DHT                                L3 DHT
                    discovery · signed records
                              │
                              ▼
                    PEER / MEMBERSHIP                           L2 PEER
                              │
                              ▼
                    SECURE TRANSPORT                            L1 QUIC / TLS 1.3
                              │
                              ▼
                          INTERNET                              L0

   ┌──────────────────────────────────────────────────────────────────┐
   │ CHAIN PLANE      namespaces · ownership · bonds · anchors         │
   │                  slow · expensive · authoritative · OFF-PATH      │
   ├──────────────────────────────────────────────────────────────────┤
   │ ACCOUNTING PLANE receipts · unlinkable tokens · epoch settlement  │
   │                  a control plane, never on the request path       │
   └──────────────────────────────────────────────────────────────────┘
```

The division of responsibility the whole design rests on:

```text
The vote answers       "Which namespaces exist?"        — slowly, with a timelock
The chain answers      "Who owns this name?"            — slowly, authoritatively
The DHT answers        "Where is it reachable now?"     — quickly, dynamically
The tunnels answer     "How do bytes get there without
                        either end learning the other's
                        address?"
The storage answers    "Where is this content when the
                        publisher is offline?"
The Layer 1 address    answers all of it when every one of the above fails
```

---

## Provenance

Sections 1–25 were drafted by sixteen parallel authors working against a shared
design constitution that fixed the cryptographic primitives, the identity
taxonomy, the layer stack, the numeric parameters, and the rulings on
architectural conflicts, so that independently written chapters would compose.
Every claim about the existing codebase was required to come from reading the
named file.

**Three adversarial review passes — consistency, security, and factual
grounding — were commissioned and did not complete.** They are the obvious next
step and the document should be read as a strong first draft rather than a
reviewed specification. §25 is the author's own triage of what is solid and what
is not.
