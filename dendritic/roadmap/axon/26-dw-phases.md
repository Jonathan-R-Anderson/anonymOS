## 61. Phased Plan DW1–DW11

Effort in engineer-months with a confidence rating. The striking feature of this
table is how much is `[BUILD NOW]`: the storage substrate exists, so seven of
eleven phases are integration rather than invention. The two that are not — DW9
(mutable state) and the diversity dependency running through DW4/DW8 — carry
almost all the risk.

| Phase | Prerequisites | Deliverables | Effort | Conf. | Exit criterion | Does NOT establish |
|---|---|---|---|---|---|---|
| **DW1** Content-addressed objects `[BUILD NOW]` | §10 store | Object IDs as BLAKE3 Bao roots; directory objects (§53.1); canonical encoding; verify-on-read | 1–2 em | **High** | A node retrieves an object from an untrusted peer and independently verifies it; a single flipped byte is rejected at its chunk | Anything about websites; this is the object layer only |
| **DW2** Website manifests `[BUILD NOW]` | DW1, §5 identity | `WebsiteManifest` (§53.2) with canonical bytes + Ed25519 signature; publisher keygen; asset DAG builder | 1–2 em | **High** | A complete static site is one signed manifest over a verifiable DAG; a manifest signed by the wrong key is rejected | Distribution — the manifest may still be fetched from one place |
| **DW3** DHT integration `[BUILD NOW]` | DW2, §7 | Provider records per CID; publish/expire; provider lookup; record signing | 2–3 em | **High** | A site is retrieved knowing only its name — no publisher IP anywhere in the path | That providers are diverse or honest |
| **DW4** Cache-on-read `[BUILD NOW]` | DW3 | Verified-only caching (§55.2); provider advertisement; admission + eviction policy (§55.3); last-copy protection | 2–4 em | Medium | A node that fetched a site serves it to a third node while the publisher is offline; an unrequested or altered object is never cached | That replicas are independent (§56.2) |
| **DW5** Domain integration `[BUILD NOW]` | DW2, §11–§13 | `name → DomainIdentity → manifest CID` resolution (§53.3); manifest pointer in the DomainRecord; hybrid path rule (§53.4) | 1–2 em | **High** | `alice.lab.axon` resolves to a verified manifest and serves static paths with no centralised DNS in the path | Live-service paths, which are §9's problem |
| **DW6** Multi-provider retrieval `[BUILD NOW]` | DW3, Part VI | Chunk-level provider scheduling; parallel fetch; reassembly; failed/lying-provider eviction (§58.2) | 2–4 em | Medium | A large object is fetched from ≥3 providers concurrently; killing one mid-transfer does not fail the fetch | Throughput gains — that is DW11's measurement |
| **DW7** Privacy-routing integration `[BUILD NOW]` | DW6, §8–§9, Part VI | Retrieval over circuits; per-provider path diversity; storage node never sees client identity | 2–3 em | Medium | Multiple overlay paths concurrently retrieve parts of one object; the provider logs no client address | Anonymity strength — that is Part V's programme |
| **DW8** Erasure coding + diversity `[NEEDS RESEARCH]` | DW4, §6 transport | Whole-vs-coded crossover measurement (§56.1); failure-domain diversity once addresses are observable (§56.2) | 3–6 em | **Low** | The crossover size is measured, not assumed; site survives loss of `n−k` holders | **Diversity is unavailable under I2P** — this phase is gated on the native transport existing |
| **DW9** Mutable state `[NEEDS RESEARCH]` | DW2 | Signed causal logs; version vectors; CRDT types where lawful; the §57.3 scoring re-run against real workloads | 4–8 em | **Low** | An application maintains verifiable multi-writer state with no central database, and concurrent writes surface as concurrent rather than silently lost | Strong consistency; ordering without the §57.4 chain anchor |
| **DW10** Storage economics `[BUILD NOW]` on existing rails | DW4, §14, PoF | Storage/bandwidth compensation via PoF epochs; pinning payment; audit-bounded payout (§59.2) | 2–4 em | Medium | An operator is paid for verified stored bytes and served bytes; a node claiming storage it lacks is caught and slashed | Proof-of-storage-over-time (§59.2 gap) |
| **DW11** Scale measurement | DW6–DW8 | Simulation + testbed at 10²–10⁶ nodes; availability, convergence, lookup latency, throughput, replica diversity, recovery time | 3–5 em | Medium | The measured curves are published, including the ones that look bad | Real-network behaviour; a simulated population is not a real one (§38.3) |

**Total: 23–43 engineer-months.** DW1–DW5 (5–11 em) deliver the headline
property — a website that survives its publisher going offline — and are all
high-confidence integration work over the existing store. Everything after DW7
is either gated on the native transport (DW8) or genuinely open (DW9).

### 61.1 Sequencing against the rest of the programme

```text
   §10 store (EXISTS) ──► DW1 ──► DW2 ──► DW3 ──► DW4  ── the core property
                                    │       │       │      "publisher can leave"
                                    ▼       │       │
                          §11–13  DW5 ◄─────┘       │
                                                    ▼
                          Part VI ──────────────► DW6 ──► DW7
                                                    │
                          §6 native transport ──► DW8   ← gated, not schedulable yet
                          §14 PoF ─────────────► DW10
                                                  DW9   ← independent, open-ended
                                                    │
                                                  DW11
```

DW8 must not be scheduled before §6 replaces I2P: failure-domain diversity is
unmeasurable while no node observes another's address (§56.2), and building
diversity policy against an unobservable property produces a mechanism that
reports success and delivers nothing.

---

## 62. The Origin-Import Path and the Live Deployment

Concrete milestones on the local testbed, each with a pass condition and an
explicit statement of what it does not prove.

| # | Demonstration | Pass condition | Does not prove |
|---|---|---|---|
| **W1** | Publish a static site to the store; fetch one asset by CID from a second node and verify it | Byte-identical, and a corrupted copy is rejected at the failing chunk | Nothing about naming or distribution |
| **W2** | Resolve `alice.lab.axon` → manifest → `index.html`, rendering the page from the DAG | Page renders; every object verified against the signed manifest | That it survives publisher loss — the publisher is still up |
| **W3** | **Kill the publisher**, then fetch the site from a node that never contacted it | Site serves fully; no publisher process alive; no publisher address in any request path | Durability — minutes of uptime say nothing about months |
| **W4** | A third node fetches the site through a second node, then serves it to a fourth (cache-on-read) | The fourth node's bytes came from a node that was never the publisher, and verify | That caching is safe at scale, or that abuse is bounded (§60) |
| **W5** | Kill holders until only `k` of `n` shards remain; fetch | Reconstruction succeeds at `k`, fails *cleanly* (stated error, no silent partial) below `k` | Real-world availability; the holders were healthy and local |
| **W6** | Publish version N+1; confirm clients converge and rollback to N−1 is refused | New version served; a replayed older manifest is rejected on `site_version` | Revocation propagation (§13.5's bounded latency stands) |

**W3 is the phase's whole thesis** and should be the first thing demonstrated
publicly: a website serving correctly with its origin provably dead.

---

## 63. What Part VII Changes in the Rest of the Document

**`[BUILD NOW]` — well-understood integration over the existing store**
DW1 object model and directory objects; DW2 manifests and signing; DW3 provider
records; DW4 cache-on-read policy; DW5 name→manifest resolution; DW6/DW7
retrieval over multipath circuits; DW10 payment on existing PoF rails. This is
the majority, and it is unusual for this document to be able to say so — the
reason is that Freenet-style storage was built first and this Part is the
website object model on top of it.

**`[NEEDS RESEARCH]`**
The whole-object-versus-erasure crossover (DW8, a measurement, not a design
question); proof-of-storage-over-time (§59.2), without which storage payment is
bounded to audit-confirmable work; multi-writer state semantics for real
application workloads (DW9's first half — which CRDT types actually cover what
sites need).

**`[UNSOLVED]` — inherited, and made larger by this Part**

| Problem | Why Part VII makes it worse | What we do instead |
|---|---|---|
| Failure-domain diversity | Every availability claim rests on replica independence, which I2P makes unmeasurable (§56.2) | OPERATOR diversity via bonds; state the limit; gate DW8 on §6 |
| Abuse amplification | Cache-on-read spreads popular content *including abuse*, and §29 offers no global takedown | Local operator policy (§29); encrypted-shard neutrality; say plainly that the network cannot un-publish |
| Sybil-controlled replicas | 10 replicas from one adversary look like 10 replicas (§15) | Bonds raise the price; §33 prices it; not solved |
| Permanence | Users will read "the publisher can leave" as "it is forever" | Contracted redundancy with a stated decay model (§56.3); never claim permanence |
| Ordering of multi-writer state | Signatures prove authorship, not sequence (§57.4) | Causal metadata; chain anchor only where contention is adversarial and funded |

**The honest summary.** Part VII delivers a real and unusual property — a website
that outlives its origin — on a substrate that mostly already exists, for
5–11 engineer-months to the core demonstration. What it does not deliver, and
should never be marketed as delivering, is permanence, diverse-by-default
replication, or a distributed database. The first is a decay curve, the second is
gated on replacing I2P, and the third is DW9's open research.

### 63.1 What this Part does NOT establish

- That any of it is deployed. §52–§63 are a design over an existing store; the
  code named in DW1–DW11 is unwritten.
- That the effort estimates survive contact with DW9, whose range is wide
  because the requirement ("distributed application state") is not yet pinned to
  concrete workloads.
- That cache-on-read is legally settled for node operators. §55.2's two node
  classes bound the exposure; they do not eliminate it, and §29.6's boundary
  between technical enforcement and governance applies unchanged.
- That the demonstration ladder in §62 measures anonymity, throughput, or
  durability. It measures function.
