## 11. The Governed Namespace System

> **AS BUILT (2026-08-16).** `internal/axon/name` (P8, 12 tests) and
> `internal/axon/registry` + `contracts/AxonRegistry.sol` (P9, 11 Go tests + 10
> contract tests).
>
> **Done:** §11.3.1's grammar, §11.3.2's total and idempotent normalisation, the
> ASCII-only confusable policy stated per pair, `zone_id` (SHA-256) and on-chain
> `nameHash` (keccak namehash). **E8.2 verified** by running the whole suite
> unmodified under six different root suffixes including `"test"`. The registry
> contract **compiles** (54 ABI entries, 7 667 B) and its storage layout is
> **confirmed by `solc`** — see §12.5, where it differs from the original sketch.
>
> **E8.3 now holds.** A second implementation written from §11.3 alone
> (`dendritic-node/scripts/e83/`, Python, with its own keccak-256) agrees with
> `internal/axon/name` on all 10⁴ corpus inputs — accept/reject, canonical form,
> parse, `zone_id`, `nameHash`, skeleton, and reported error kind. **It did not
> agree on the first run, which is the point**: it found one code defect
> (skeleton skipped §11.3.3's hyphen elision, so `mybank` did not block
> `my-bank` and the stated consequence 1 was false), one wrong formula in this
> document (`nameHash` omitted the namespace label, colliding
> `alice.lab.axon` with `alice.corp.axon`), and five under-specified points now
> written down above. See `scripts/e83/FINDINGS.md`. **The independence is
> weaker than E8.3 asks for** — one author, two languages, spec-only, not two
> authors — and that caveat is recorded rather than rounded off.
>
> **Nothing is deployed**: the registrar is unwritten, and every
> policy number in §12.4a is `[NEEDS RESEARCH]`, the levy decay curve above all.

**The finding that shapes this section: the namespace is optional.** Every
destination AXON can address is reachable without a name, through the
self-certifying address of §11.9 — 56 base32 characters that *are* the public key.
Names are a memorability and delegation layer on top of that substrate,
designed so a failure of the chain, the registry contract, the snapshot anchor,
the resolver, or **the governance process itself** degrades to the substrate
rather than to nothing.

**The second finding: there is not one namespace, there are many, and the set is
governed.** AXON does not have a single hardcoded TLD. It has a root registry
contract holding a set of **namespaces** — `lab`, `corp`, `research` — each
created by on-chain vote, each with its own registrar contract and its own
admission policy. What is *not* votable is the **root suffix**: one fixed
trailing label that marks a name as AXON's and bounds the collision surface with
the public DNS to exactly one label, permanently, no matter how many namespaces
the vote creates (§11.0, R15–R17).

```text
LAYER 3   HUMAN NAME       alice.lab.axon    governed · optional · revocable
             │              registered under a DAO-approved namespace
             │              many names may point at one service
             ▼
LAYER 2   DOMAIN IDENTITY  Ed25519, committed on-chain by the name's owner
             │              signs every record under that name
             ▼
LAYER 1   SERVICE ADDRESS  nzt4f…q7d.key.axon   self-certifying · permanent ·
                            ungoverned · vanity-mineable · 56 base32 chars
```

`key` is a permanently reserved namespace label (§11.3.1) that no vote can
allocate, which is what lets Layer 1 sit inside the same grammar as Layer 3
without ever being shadowed by it (§11.9).

**Layer 1 is the guarantee. Layer 3 is the convenience.** If every namespace were
retired tomorrow and the governor were captured the day after, every service
would still be reachable at its Layer 1 address. No text in this document may
imply that a service depends on a name in order to exist.

Today's system has the opposite property. A Syndichan gateway is reachable at
`gw-<24 hex>.syndichan.org`, a lease held from three authorities in series — a
registrar (Name.com), a CA (Let's Encrypt), and a controller process holding the
only API token. Any one of them removes the node unilaterally, and there is no
fallback because TLS will not complete without the name.

The second finding follows from §4's layer rule, **no layer above L4 may see an
IP address**. Today, being reachable by name *requires* publishing your IP in a
global public database, because ACME will not issue for a name that does not
resolve to you — `WaitForReservedDNS` in `internal/gateway/registry.go` exists
purely to block until that publication propagates. A `.axon` name resolves to a
`ServiceIdentity`, never to an address. That is not an improvement on DNS; it is
a different contract.

---

### 11.0 The root, the namespaces, and what governance may touch `[BUILD NOW]`

#### Terminology, fixed

| Term | Meaning |
|---|---|
| **root suffix** | The single fixed trailing label marking a name as AXON's. **Not votable.** Constant `ROOT_SUFFIX`, default `axon`. |
| **namespace** | A governed label such as `lab`, `corp`. Created by vote. Never a compile-time constant — read from chain. |
| **canonical form** | `alice.lab.axon`. What appears on the wire, in records, and under every signature. Always. |
| **flat form** | `alice.lab` — the root suffix elided for display. A resolver *presentation* choice, never a wire format (§11.0.2). |
| **registrar** | The per-namespace contract implementing `IRegistrar`, deciding who may register what and at what price. |
| **root registry** | `TLDRegistry` — the root zone, as a contract (§12.0). |
| **governor** | The DAO contract that may mutate the root registry, under quorum and timelock (§12.0a). |
| **steward** | An optional per-namespace address with enumerated powers over *its own namespace only*. Never over the root. |

Throughout this document "TLD" means a governed namespace label, not a DNS
top-level domain. The difference is the entire subject of §11.0.2.

#### 11.0.1 R15 — the root is a contract, not an authority

DNS answers "who owns the root" with ICANN: an authority. A DAO that votes on
namespaces is also an authority *unless its powers are enumerated and its actions
are deterministic*. The ruling makes it the latter.

Resolution is a pure function of chain state. Given a block, every resolver
derives the same answer; there is no discretionary decision at resolution time.
Governance acts only by changing that state, only through the powers enumerated
in §12.0a, and only after a timelock. One root registry, pluggable per-namespace
registrars — the ENS architectural idea, kept, because it lets `lab` be
first-come-first-served at a flat fee while `corp` is auctioned and `research` is
invite-only, without the root knowing anything about either policy.

#### 11.0.2 R16 — collision with the public DNS root, which is the sharp edge

If the vote approves a namespace whose label ICANN has delegated, or later
delegates, a resolver must choose between AXON and the ordinary Internet.
Whichever it picks, something a user depends on breaks. This is not hypothetical:
the IANA root grows, and a label free today may be delegated tomorrow. Every
alternative-root project in the history of the Internet has hit this and none has
solved it.

Three parts, all mandatory:

**1. The root suffix is not votable.** Every AXON name ends in `ROOT_SUFFIX`, so
the canonical form is `alice.lab.axon`. The governed labels sit at the *second*
level. However many namespaces exist, the collision surface with the IANA root
stays exactly one label wide, forever. This is the single most important
structural decision in the naming design and it is the reason a votable root is
survivable at all.

**2. The flat form is a display alias with a precedence rule that is not
configurable.**

```text
resolver sees "alice.lab"
   │
   ├── does "lab" resolve in the public DNS root?
   │        YES → the public DNS wins. AXON does not answer.
   │               The user is told why. No shadowing, ever.
   │        NO  → rewrite to alice.lab.axon and resolve on AXON
```

A user's ordinary browsing must not change because they installed a resolver.
A resolver that lets an operator invert this rule is non-conformant.

**3. The registry enforces an eligibility predicate at proposal time.** A label
is ineligible if it is in the IANA root-zone snapshot the contract was
initialised with, if it is an IETF special-use name, if it is one or two
characters (reserved for ccTLDs), or if it is on the governor-maintained reserved
list. The contract checks at proposal; resolvers re-check against a periodically
anchored IANA snapshot, **because the contract's view goes stale and the real
root does not stop moving.** `[NEEDS RESEARCH]` — the re-check cadence and the
behaviour when a live namespace becomes colliding are not settled. The least-bad
answer is: freeze new registrations immediately, keep resolving existing names,
and start a retirement vote.

> **The standards-safe deployment, stated once and not buried.** `.alt` is the
> IETF-reserved pseudo-TLD for alternative, non-DNS namespaces. Setting
> `ROOT_SUFFIX = alt` makes names `alice.lab.alt`, collision-free by construction
> and standards-conformant permanently. Setting `ROOT_SUFFIX = axon` is prettier,
> is what this document uses, and carries the residual risk that ICANN delegates
> `.axon`. It is a one-constant change and the trade should be made deliberately
> rather than inherited. Note that the RFC 7686 route `.onion` took — a
> special-use registration obliging conformant resolvers not to forward the
> name — is available for `.axon` and is the correct long-term move (§11.3).

#### 11.0.3 R18 — namespaces are independent, names are many-to-one, binding is mutual

Four rules. Together they answer the question "does approving a namespace hand
every existing service a name in it?" — no, and here is exactly why not.

**1. No implicit cross-namespace rights.** Registering `alice.lab.axon` grants no
claim whatever on `alice.corp.axon`. There is no global reservation, no automatic
mirroring, no cross-namespace trademark mechanism at the root. A registrar MAY
implement a sunrise or priority policy *inside its own namespace*; the root
neither knows nor cares.

**2. Approving a namespace creates an empty namespace, not a set of names.**
Registration is per-name, per-namespace, and gated by that namespace's registrar.
Some namespaces will be open to anyone; others will refuse most applicants by
policy. A service may hold zero names, one, or many.

**3. Names are many-to-one onto services.** N names across M namespaces may point
at one `ServiceIdentity`. The Layer 1 address is the identity; names are aliases
to it. There is no requirement that a service have a name at all.

**4. Binding is mutual, and this is a security requirement, not bookkeeping.**
A name record pointing at a `ServiceIdentity` is only half a binding. The service
also publishes the set of names it answers for, signed under its own
`ServiceIdentity` (the `NameAcceptance` record, §11.6.3). A resolver presents a
name as canonical only when **both directions agree**.

```text
      NameRecord:  alice.lab.axon ──── points at ────►  ServiceIdentity S
                                                              │
      NameAcceptance (signed by S): { alice.lab.axon, … } ◄────┘

      both present   →  resolve, present "alice.lab.axon" as canonical
      only forward   →  MISMATCH: connect only on explicit user override,
                        never render the name as the service's identity
      only backward  →  the service claims a name it does not hold: ignore
```

Without rule 4, anyone may register `free-money.corp.axon → your service` and
make your service appear to answer for it — a defamation and phishing primitive
handed out for the price of a registration. With it, an unauthorised name
resolves to a service that refuses it, and the resolver reports the mismatch
instead of rendering the page (§13.9).

---

### 11.1 What already exists

| File | What it does | Fate |
|---|---|---|
| `gateway-controller/backend/namecom.py` (at `HEAD`; deleted in the working tree) | Name.com Core API client. `A`/`AAAA` plus a separate SRV path. HTTP Basic auth with an account username + API token. Treats 429 as a quota signal, not packet loss | Replaced |
| `gateway-controller/backend/dns_sync.py` | The reconciler. Computes a `DNSPlan` of create/update/delete/**conflict** against a `managed_dns_records` ownership table keyed by the exact Name.com record id, so an unowned record can never enter a destructive diff. Publishes at most `max_answers` (default 8) answers at the shared public hostname, ordered by measured latency | Replaced |
| `gateway-controller/backend/security.py` | `gateway_hostname(node_id)` = `f"{subdomain_prefix}-{sha256(node_id).hexdigest()[:24]}.{domain}"`; `validate_managed_hostname` refuses anything outside the `gw-` prefix or the managed domain | Replaced by §11.3 |
| `gateway-controller/backend/srv.py` | `_syndichan-bootstrap._tcp` SRV, priority 10 / weight 10 / port 443, TTL 300, at most 5 targets. A separate maintainer from `DNSSynchronizer` so an SRV bug cannot delete an address record. Dry-run by default | Replaced by `SVC` (§11.6) |
| `gateway-controller/backend/config.py` | `ttl: 300`, `dns_sync_interval: 900`, `max_answers: 8`, `subdomain_prefix: "gw"` | Starting point for §11.7 |
| `storage-client/internal/gateway/registry.go` | The client half. `ReserveHostname`, `WaitForReservedDNS`, `PublishGatewayRegistration` with an Ed25519-signed envelope. Endpoint must be a credential-free HTTPS URL; redirects forbidden | Signing discipline kept, authority replaced |
| `storage-client/internal/gateway/acme.go` | Let's Encrypt issuance | Out of scope — clearnet ingress is not AXON |

Two properties of that code carry forward because they were learned the hard
way: **ownership-scoped mutation** (`build_plan` refuses to touch a record it did
not create and reports it as a `conflict` for a human — the AXON analogue is the
`version`/`serial` monotonicity of §11.7 and §12.3), and **separation of
destructive planners** (SRV and address reconciliation never share a code path —
the analogue is that revocation is a separate monotone record type no other
planner can emit).

**What must be replaced:** the whole chain of authority — registrar, CA,
controller database, API token. Not replaced: the clearnet gateway itself, which
remains an ingress for users not running `axond` and is out of scope.

**A gap worth naming:** `grep -rn 'idna\|punycode\|unicode'` over
`internal/gateway/` and `internal/dcs/` returns nothing. The existing system is
ASCII-only by accident, not policy, with no confusable handling at all. §11.3
makes it policy and states the cost.

---

### 11.2 DNS, today's system, and AXON side by side

The middle column is what the code above actually does — not generic DNS, the
specific deployment.

| Property | Traditional DNS | Today: Name.com + Let's Encrypt + `gateway-controller` | AXON `.axon` |
|---|---|---|---|
| **Root of trust** | 13 root letters, the IANA root zone, a DNSSEC anchor operated by ICANN/Verisign | Same, *plus* the Name.com account, *plus* the Let's Encrypt chain in every browser | A registry contract on Ethereum L1, verified through the sync-committee light client already built (`doc/trust-anchor.md`). The anchor is a weak-subjectivity checkpoint obtained out of band — subjective once, then self-sustaining |
| **Delegation** | `NS` records; a parent points at nameservers it does not control | One flat zone; every `gw-*` label created by one process against one API token | On chain only for the second-level label. Everything below is a signed `DLG` record (§11.6) — no transaction, no fee, no chain latency |
| **Cache poisoning** | The historical failure mode: off-path spoofing, fragmentation, resolver bugs. DNSSEC fixes it where deployed; deployment is partial | Inherits all of it; mitigated only because ACME re-checks and TLS catches endpoint substitution afterwards | Structurally absent. Every record carries an Ed25519 signature by a key committed on chain. An unsigned answer is not a cache entry, it is a discarded byte string. The residual is *rollback*, not poisoning — §11.7 |
| **Ownership** | A contract with a registrar; the registrar's database row is the fact | A contract with Name.com, held by whoever holds the token in `/secret/.env` | `OwnerIdentity`, a secp256k1 account, in contract storage. No counterparty, no database row |
| **Transfer** | Auth-code handoff between registrars; days; registrar-reversible | Not modelled — transfer means handing over the API token | One transaction, atomic, final at L1 finality, and it zeroes `domainKey` so the seller cannot keep signing (§12.3) |
| **Censorship point** | Registrar, registry operator, or whichever recursive resolver the user happens to use. All three are routinely used | Three in series: Name.com deletes the zone, Let's Encrypt refuses or revokes, the controller refuses to register | Registration and transfer need one Ethereum transaction, censorable at the mempool or by a builder — bounded, escapable by resubmission. *Resolution* needs nothing but the DHT and no permission from anyone |
| **Privacy of queries** | Every lookup seen by the recursive resolver, historically in cleartext. DoH/DoT move the observer rather than remove it | Same, plus the gateway ingress logs | Lookups traverse a circuit (R4b) and hit blinded DHT keys (R4c), so the storing node learns neither name nor querier. Residual: timing, and the resolver itself — §13 |
| **Revocation** | CRL/OCSP for certs; for names, delete and wait out the TTL. Revocation is *absence*, which a stale cache cannot tell from a network fault | Delete the A record, wait 300 s | An explicit monotone `RVK` record (§11.6) plus on-chain `revokeDomainKey`. Revocation is a *positive assertion* a resolver must remember |
| **Cost** | ~$10/yr registrar fee plus a CA relationship | Same, plus one Postgres and one always-on controller | One registration transaction + annual renewal, priced in gas, plus the ~45k gas/hour anchoring cost (§12.6) shared across the whole namespace |
| **Uniqueness model** | Globally unique via a hierarchy of registries | Globally unique via one registrar | Globally unique via contract state. I2P chose the opposite — per-router addressbooks, no global agreement, no consensus needed. We take a chain dependency precisely to buy global uniqueness; §12.2 itemises that bill |

The row that decides the architecture is **cache poisoning**. DNS spent thirty
years trying to make an unsigned, cached, hierarchically-delegated answer
trustworthy and produced DNSSEC, which is correct and roughly half-deployed. If
every answer is signed by a key the client verifies independently, the class
disappears and the resolver stops being a trusted party. That is why naming is a
layer and not an addressbook.

---

### 11.3 Name grammar and normalization `[BUILD NOW]`

**Exactly one string is a compile-time constant, stated here once.**
`ROOT_SUFFIX = "axon"`. No other part of this specification contains that
literal; every construction takes it as a parameter. **Namespace labels are not
constants at all** — they are read from `TLDRegistry` at runtime, and a client
that hardcodes the set of namespaces is non-conformant, because the set changes
by vote (§12.0a).

`.axon` is not delegated in the IANA root, so it collides with nothing today and
is protected by nothing. The correct long-term move is a special-use registration
of the kind `.onion` obtained in RFC 7686, obliging conformant resolvers not to
send the suffix to the public DNS. We have not done it, so a misconfigured stub
leaks lookups as NXDOMAIN queries to whichever recursive it is pointed at. That
leak is real and unmitigated in v1 `[NEEDS RESEARCH]`, and it is now *worse* than
before: under §11.0.2 the flat form invites a resolver to test labels against the
public DNS deliberately, so the leak must be engineered rather than merely
avoided (§13.7).

#### 11.3.1 Grammar

```text
name          := subordinate* registrable "." namespace "." ROOT_SUFFIX
subordinate   := label "."
registrable   := label            ← the only label held on chain
namespace     := label            ← governed; created by vote (§12.0a)
label         := ldh-label
ldh-label     := ALPHA-LOWER / DIGIT ( ( ALPHA-LOWER / DIGIT / "-" )* ( ALPHA-LOWER / DIGIT ) )?
ALPHA-LOWER   := %x61-7A      DIGIT := %x30-39

namespace label:                          3 <= len <= 24
registrable label:                        3 <= len <= 63   (registrar MAY raise the floor)
subordinate labels (delegated off chain): 1 <= len <= 63
full name: <= 253 bytes; <= 8 labels total, i.e. at most 5 levels below the
           registrable label once the namespace and root suffix are counted
```

Namespace labels are held to a tighter range than registrable labels: at most 24
characters because they are typed constantly and appear in every name beneath
them, and at least 3 because one- and two-character labels are ineligible under
§11.0.2 part 3 regardless.

**The two-level scarcity problem.** `alice.lab.axon` and `alice.corp.axon` are
different names owned by potentially different people, and users will read the
`alice` and stop. Namespaces multiply the confusable surface rather than dividing
it (§11.3.3), and they do it in a way a single registrar cannot police because
each namespace polices only itself. This is a genuine cost of the governed
multi-namespace design and §11.3.3 states what is and is not done about it.

Further refusals, all enforced **in `AxonRegistry.register`** (§12.3) so they are
rules rather than client conventions:

| Refused | Reason |
|---|---|
| Any byte outside `[a-z0-9-]` after normalization | Removes every non-ASCII homograph class at once. §11.3.3 states the cost |
| Leading or trailing `-` | Ambiguous rendering; standard LDH rule |
| `-` at both positions 3 and 4 (`xx--…`) | Reserves the IDNA A-label prefix. Stops a punycode-looking label being smuggled past an ASCII registry into a client that helpfully decodes it |
| Length < 3 | Pure scarcity. Reserved; release is `[UNSOLVED]`, §12.4 |
| A reserved label | `key`, `srv`, `local`, `test`, `invalid`, `example`, `axon`, and any label beginning `_`. Held in a `mapping(bytes32 => bool)` populated in the constructor with no setter, so the set is immutable and verifiable from storage |
| A label whose confusable skeleton is held by another owner | §11.3.3 |

#### 11.3.2 Normalization

A total function from input to a canonical name or an error. It never guesses.

```text
normalize(input) -> canonical | ERROR
 1. Reject any byte >= 0x80.                     ERROR non-ascii
 2. Reject any control byte < 0x20 or 0x7F.      ERROR control
 3. Strip at most one trailing ".".
 4. Reject a leading "." or any empty label.     ERROR empty-label
 5. Map A-Z to a-z.  The ONLY character mapping performed.
 6. Reject any remaining byte outside [a-z0-9.-]. ERROR charset
 7. Apply 11.3.1.                                ERROR grammar
 8. Require the last label == TLD.               ERROR not-axon
```

**The step numbers are the order, and three refinements inside them are fixed
here** because two implementations agreeing on accept/reject while disagreeing
on the reason is a difference a caller can act on wrongly (E8.3 found all
three, on 4 921 of 10⁴ corpus inputs):

* **Steps 1 and 2 are separate passes.** An input carrying both a non-ASCII
  byte and a control byte reports the non-ASCII one, whichever comes first in
  the string. One combined loop makes the reason depend on byte order.
* **Step 8 is last.** A name that is both ungrammatical and not ours is
  reported as ungrammatical; checking the suffix earlier masks every other
  refusal. The trailing element is `ROOT_SUFFIX`, a **constant, not an instance
  of the `label` production** — so the LDH rules do not apply to it and step 8's
  equality check is the whole of its validation.
* **`too-long` is the 253-byte whole-name cap only.** A per-label bound
  violation in either direction is a grammar refusal, because §11.3.1's
  production is where the bound is stated; and the label-count bound is checked
  before the byte-count bound.

Deliberately absent, because a mapping that "helps" is a mapping an attacker
exploits: no Unicode normalization (there is no Unicode); no whitespace trimming
(`"alice .axon"` is an error, not `alice.lab.axon` — silent trimming lets the first
be planted where the second is expected); no mapping of full-stop lookalikes
(U+3002, U+FF0E, U+FF61), which step 1 rejects, which is why step 1 is first.

The canonical form is what is hashed. Two hashes, not interchangeable:

```text
on chain   nameHash = namehash(canonical_name), the ENS-style chain, folded
           from the root inward so every label above the registrable one is
           bound into the result:

               namehash("")            = 0x00 * 32
               namehash(TLD)           = keccak256( 0x00*32 ‖ keccak256(TLD) )
               namehash(ns.TLD)        = keccak256( namehash(TLD) ‖ keccak256(ns) )
               nameHash                = keccak256( namehash(ns.TLD) ‖ keccak256(label) )

           THE NAMESPACE LABEL IS PART OF THE CHAIN. An earlier form of this
           block stopped at namehash(TLD) ‖ keccak256(label), which is the
           pre-namespace two-level shape: read literally it gives
           alice.lab.axon and alice.corp.axon the SAME on-chain identifier,
           contradicting §11.3.1's statement that they are different names
           owned by potentially different people. E8.3's second implementation
           caught it on 538 of 10⁴ corpus names. This is the class of error
           E8.3 exists to find and the reason a formula a contract must
           recompute is not safe to state once.

           keccak because §2 fixes it for Ethereum interop and the contract
           must recompute it.

off chain  zone_id = SHA-256( "AXON-zone-v1" ‖ 0x00 ‖ canonical_name )
           SHA-256 because §2 fixes it for protocol hashing; the overlay
           never needs keccak and should not carry it.
```

Only the registrable label is on chain, so `nameHash` exists only for
`label.namespace.axon` — the whole of a canonical name with nothing delegated
below it. Subordinate names have a `zone_id` and no `nameHash`.

#### 11.3.3 Homographs and confusables — a real attack, not a hypothetical

Restricting to ASCII removes the interesting cases (Cyrillic `а`, Greek `ο`, the
several hundred code points that render as a Latin `a`) at a cost that must be
stated plainly: **`.axon` is a Latin-script-only namespace in v1.** A user whose
language is not written in ASCII cannot register in their own script. That is a
real exclusion, not defensible as "good enough", and lifting it is
`[NEEDS RESEARCH]` — the honest options are per-script single-script restriction
with per-script confusable tables, or forced escaped rendering of mixed-script
names. Shipping partial Unicode is worse than shipping none.

ASCII is not safe either. In common sans-serif rendering: `rn`~`m`, `vv`~`w`,
`cl`~`d`, `0`~`o`, `1`~`l`, and hyphen elision (`my-bank` ~ `mybank`). The
uppercase confusables (`I`/`l`, `O`/`0`) are already gone because canonical form
is lowercase. The rest are handled by a **skeleton index** — a second uniqueness
constraint over an equivalence class rather than over exact bytes.

```text
skeleton(label):
    s := label
    s := replace(s, "-", "")        ; hyphen elision: my-bank ~ mybank
    s := replace(s, "rn", "m")      ; multi-character first, left to right,
    s := replace(s, "vv", "w")      ; or the pair folds apart and is lost
    s := replace(s, "cl", "d")
    s := map(s, per-pair table)     ; folded ONTO THE DIGIT:
                                    ;   o -> 0    l -> 1    i -> 1
                                    ;   s -> 5    b -> 6    g -> 9   z -> 2
    return keccak256(s)
```

The per-pair table is normative and is stated here rather than delegated to a
library default (T8.4): a library's notion of "confusable" is revised faster
than a registry can re-police names it has already issued. The fold direction
is arbitrary for class membership — `{o,0}` is the same class whichever
representative is stored — but it is not arbitrary for the stored bytes, so it
is fixed here. **Hyphen elision is the first step, not a character fold**:
reading it as a fold over hyphen-lookalike codepoints concludes there is
nothing to do, since step 1 of §11.3.2 has already removed every non-ASCII
hyphen, and consequence 1 below then silently does not hold. E8.3's second
implementation caught exactly that.

`AxonRegistry` stores `classHolder[skeleton] -> nameHash` and refuses a
registration whose class is held by a different owner. The function runs **in the
contract**, over the label revealed at reveal time, as a bounded loop over at
most 63 bytes. A rule enforced only by clients is not a rule.

Three uncomfortable consequences, stated rather than hidden:

1. **First registrant owns the class.** `mybank.axon` blocks `my-bank.axon`,
   `rnybank.axon` and the digit-one variant. Intended against an attacker;
   an annoyance to an honest latecomer.
2. **The class holder gets siblings cheaply.** `registerSibling(heldName, label)`
   adds another class member to the same owner on the same expiry at a nominal
   fee. Without it, defensive registration costs full price per variant and
   nobody does it.
3. **The fold is conservative on purpose.** Adding `5→s`, `2→z`, `8→b` catches
   more attacks and collapses far more legitimate names into shared classes.
   Aggressive folding turns a namespace into a lottery, and moving the line later
   requires a registry migration — which is itself an argument for drawing it
   carefully now.

It does nothing about names that are merely *similar* (`rnybank-support.axon`),
and there is no trademark process and no dispute forum — there is no authority to
appeal to. That is the cost of the ownership model; §12.4 restates it.

---

### 11.4 Subdomains without a chain transaction `[BUILD NOW]`

Only `label.axon` is on chain. Everything below is delegated by a signed record:
zero gas, overlay speed, no mempool to censor.

```text
   ON CHAIN   alice.lab.axon -> OwnerIdentity, DomainIdentity K_a, expiresAt
                  │ K_a signs a DLG record naming K_b
   OFF CHAIN  files.alice.lab.axon -> K_b, max_depth 2, constraints "*"
                  │ K_b signs a DLG record naming K_c
              eu.files.alice.lab.axon -> K_c, max_depth 1, may_further_delegate 0
```

| Rule | Statement |
|---|---|
| Depth | At most 6 levels below the registrable label. `max_depth` decrements down the chain; a record exceeding it is invalid |
| Constraints | Each `DLG` carries an ASCII allow-list of label patterns (`*`, or comma-separated exact labels and one trailing-`*` prefix). A child signing outside its constraint produces an invalid record |
| Chain carried inline | Every record signed by a delegated key carries the full `DLG` chain in `dlg_chain`. A resolver never fetches to verify. Cost: up to 960 bytes per record |
| No re-delegation by default | `may_further_delegate` defaults to 0. Explicit beats implicit for the field controlling how much authority you gave away |
| Revocation flows down | Revoking `DomainIdentity` on chain kills the whole subtree. An `RVK` with `scope = 2` kills one branch |
| Delegation is not transfer | A `DLG` conveys signing authority only — no ownership, no renewal right, no ability to change on-chain state. The parent revokes unilaterally at any time |

This is Freenet's signed-subspace idea — a keypair owns a namespace and signs
everything under it — constrained by an explicit policy language and rooted in a
chain commitment rather than in the key alone.

---

### 11.5 Multiple services under one name, and aliases `[BUILD NOW]`

A domain is a *zone*, not an endpoint. Records are keyed by `(name, rtype)`
inside the zone, which is where the DNS analogy holds.

```text
alice.lab.axon
  ├─ ZONE   apex: set_root, record_count, domain_key, chain_version
  ├─ SVC    prio 10 weight 100  BULK         service S1
  ├─ SVC    prio 10 weight  50  BULK         service S2
  ├─ SVC    prio 20 weight 100  INTERACTIVE  service S3
  ├─ CNT    blake3 root of the current manifest
  ├─ META   "availability" = "tier2"
  └─ DLG    files.alice.lab.axon -> K_b
files.alice.lab.axon   (signed by K_b, DLG chain inline)
  ├─ ZONE
  └─ CNT    blake3 root of a large object
```

`SVC.priority`/`weight` carry DNS SRV semantics, because they are well understood
and `srv.py` already relies on them (equal weight so a resolver shuffles).
`SVC.vport` is a 16-bit selector *inside* the destination — never a TCP port,
never visible on L0 — which is the I2P destination-with-ports idea and lets one
`ServiceIdentity` host several logical services without several descriptors.
`SVC.traffic_class` lets the publisher declare which of R2's classes a service
actually supports, so a client does not open an `INTERACTIVE` session against a
service that only batches.

Aliases come in two modes and the distinction matters:

| Mode | Behaviour | Use | Hazard |
|---|---|---|---|
| `strict` (0) | The resolver re-resolves the target from scratch including its on-chain check. Authority does **not** transfer | `www.alice.lab.axon -> alice.lab.axon`; pointing at a name you do not control | Alias loops. Bounded at 4 hops, then fail |
| `merge` (1) | Import the target's record set at this name, only if the target is in the **same zone or a descendant** and signed by a key in the same `DLG` chain | One record set at several names inside your own tree | None beyond the same-zone constraint, which is why it is not optional |

A cross-zone `merge` is rejected unconditionally: it would let one owner make
another owner's key authoritative under their name, which is a phishing primitive
or a blame-shifting primitive depending on the direction you read it.

---

### 11.6 The `DomainRecord` set `[BUILD NOW]`

Analogous to DNS RRs and deliberately not the same. No `A`/`AAAA` — no record
here ever names an address. No `NS` — delegation is `DLG` and carries a key. No
`MX` or anything application-shaped, per §8.

#### 11.6.1 Common envelope

All integers big-endian, all sizes in bytes.

```text
off   size  field           notes
  0     4   magic           "AXNR"
  4     1   version         1
  5     1   rtype           11.6.2
  6     2   flags           bit0 authoritative-negative; 1-15 reserved MBZ
  8    32   zone_id         SHA-256("AXON-zone-v1" ‖ 0x00 ‖ zone_name)
 40     8   serial          monotone per (zone_id, name, rtype). Anti-rollback
 48     8   not_before      unix seconds
 56     8   not_after       unix seconds; hard expiry, inside the signature
 64     4   ttl_hint        seconds; a suggestion, capped by the resolver
 68     2   name_len   N
 70     2   rdata_len  M
 72     N   name            canonical ASCII, no trailing dot
72+N    M   rdata           11.6.3
72+N+M  2   dlg_len    C
74+N+M  C   dlg_chain       zero-length when signed by DomainIdentity directly
74+N+M+C
       64   signature       Ed25519

total = 138 + N + M + C, hard cap 4096 B; N <= 253, M <= 2048, C <= 960
```

The cap is not cosmetic: an unbounded record is a storage-amplification attack on
every DHT node that accepts it.

#### 11.6.2 Record types

| rtype | Name | Purpose | Multiple per name? |
|---|---|---|---|
| `0x01` | `SVC` | Service pointer | Yes |
| `0x02` | `CNT` | Content pointer, immutable object | Yes |
| `0x03` | `ALIAS` | Name-to-name redirect | One |
| `0x04` | `DLG` | Delegate a subtree to a child key | One per child label |
| `0x05` | `KEYROT` | Announce a `DomainIdentity` rotation | One live |
| `0x06` | `RVK` | Revoke key / record / delegation / zone | Yes, monotone |
| `0x07` | `META` | TXT-equivalent structured metadata | Yes |
| `0x08` | `ZONE` | Zone apex: the record-set commitment | Exactly one |

#### 11.6.3 `rdata` schemas

```text
SVC (0x01)                                          73 + A bytes
  0   2  priority        lower first
  2   2  weight          within a priority band
  4   1  proto           1 = AXON stream, 2 = AXON datagram
  5   1  traffic_class   0 = INTERACTIVE, 1 = BULK               (R2)
  6   2  vport           overlay-internal selector
  8  32  service_id      Ed25519 ServiceIdentity public key
 40  32  descriptor_hint SHA-256 of the blinded descriptor key for the
                         CURRENT time period; all-zero if omitted
 72   1  alpn_len   A
 73   A  alpn            ASCII protocol label

CNT (0x02)                                          45 + M bytes
  0   1  cid_kind        1 = BLAKE3 Bao root
  1   1  availability_tier   R8; 0 = best-effort, 1..3 = contracted
  2   2  reserved        MBZ
  4   8  size            octets
 12  32  blake3_root
 44   1  manifest_len M
 45   M  manifest_cid    multihash bytes, for the existing go-cid path

ALIAS (0x03)                                        4 + T bytes
  0   1  mode            0 = strict, 1 = merge (same-zone only)
  1   1  reserved        MBZ
  2   2  target_len   T
  4   T  target          canonical AXON name

DLG (0x04)                                          36 + C bytes
  0  32  child_key       Ed25519, authoritative for the subtree
 32   1  max_depth       1..6, decrements down the chain
 33   1  flags           bit0 = may_further_delegate (default 0)
 34   2  constraint_len C
 36   C  constraints     "*" or comma-separated labels / one "pfx*"

KEYROT (0x05)                                       108 bytes
  0  32  new_domain_key
 32   8  effective_at    old key valid until this instant
 40   1  chain_state     0 = not yet on chain, 1 = committed
 41   3  reserved        MBZ
 44  64  countersignature by new_domain_key over
         "AXON-rot-v1" ‖ 0x00 ‖ zone_id ‖ old_key ‖ new_key ‖ effective_at
  Signed by the OLD key, countersigned by the NEW. Old alone lets you rotate
  to a key nobody holds (a self-DoS an attacker inflicts with a stolen key);
  new alone is a takeover. Both are required.

RVK (0x06)                                          48 bytes
  0   1  scope   0 = zone, 1 = record (target = record digest),
                 2 = delegation (target = child_key), 3 = service (service_id)
  1   1  reason  0 unspecified, 1 key compromise, 2 superseded, 3 operator
  2   6  reserved MBZ
  8   8  revoked_at
 16  32  target  all-zero for scope 0

META (0x07)                                         1 + sum(pairs)
  0   1  pair_count <= 16
  1  ..  pairs: [1 key_len][key ASCII <=32][1 val_len][val <=255]
  Reserved keys, infrastructure only: "policy", "availability",
  "abuse-policy", "min-client-version". Application semantics are out of
  scope (§8); a resolver MUST NOT interpret an unreserved key.

ZONE (0x08)                                         80 bytes
  0  32  set_root        RFC 6962 Merkle Tree Hash (SHA-256) over the SORTED
                         record digests of this zone
 32   4  record_count
 36   4  reserved        MBZ
 40  32  domain_key      the DomainIdentity this zone asserts
 72   8  chain_version   the registry `version` (§12.5) it was published against

  record digest = SHA-256("AXON-rdigest-v1" ‖ 0x00 ‖ full record incl. sig)
  Merkle per RFC 6962 §2.1: leaf prefix 0x00, interior prefix 0x01, split at
  the largest power of two below n — NOT duplicate-last-leaf, which admits
  two trees with one root.
```

**Negative answers, and the privacy cost we accept.** `set_root` makes absence
provable: fetch the `ZONE` record plus a Merkle path and you have a signed "this
zone contains no `SVC` for that name". DNS needed NSEC for this, then NSEC3 to
stop NSEC leaking the zone, and NSEC3 was walked anyway. We do not attempt zone
privacy: **an AXON zone is fully enumerable to anyone holding its record set, by
design.** A publisher needing an unenumerable endpoint publishes no record and
distributes a self-certifying address (§11.9).

---

### 11.7 TTL and freshness semantics `[BUILD NOW]`

Four independent clocks; confusing them is how naming systems get rollback bugs.

| Clock | Owner | Meaning | On exceed |
|---|---|---|---|
| `ttl_hint` | Publisher | "Re-fetch after this" | Soft: serve stale, mark stale |
| `not_after` | Publisher, inside the signature | "No longer valid" | **Hard**: invalid, not stale. Discard |
| Snapshot age | Resolver | Age of the chain view (§12.6) | Declared to the caller; hard-fail past a bound |
| `serial` | Publisher, enforced by storing nodes | Version of this `(zone, name, rtype)` | A lower serial never wins over a higher one |

```text
ttl_hint       min    60 s   below this the DHT is the bottleneck
               max 86400 s
resolver cap   SVC   3600 s  descriptors live 3 h (§5), so a longer SVC cache
                             outlives what it points at
               CNT  86400 s  content is immutable; the pointer is not
               ALIAS 3600 s   DLG 86400 s   META 86400 s   ZONE 3600 s
record life    not_after - not_before <= 7 days. A 7-day record must be
               re-signed weekly, bounding the damage from a detected key
               compromise whose on-chain revocation is being censored.
clock skew     not_before accepted up to 300 s in the resolver's future
```

**Anti-rollback**, in increasing strength. A DHT storing node cannot be trusted
to serve the newest record; a hostile one serves the newest record it liked.

1. **Storing-node monotonicity.** A node MUST reject a `PUT` for `(zone_id, name,
   rtype)` with a lower or equal `serial` unless the bytes are identical. Cheap;
   stops accidental regression, not a lying node.
2. **`ZONE.set_root`.** Fetching the apex yields the digest of every record at
   that serial, so a stale individual record fails to match the set — converting
   "I was served an old record" from undetectable to detectable, provided the
   apex is fresh.
3. **`ZONE.chain_version`.** The apex names the registry `version` it was
   published against; a resolver that has seen version `v` refuses a zone
   claiming less. This is what makes a rotation or transfer *stick*.

Mechanism 3 has a hole worth naming: a resolver that has not yet seen version `v`
is still rollback-able. That is exactly the freshness bound of §12.6, and why the
bound is declared to the caller rather than hidden.

---

### 11.8 Signing rules `[BUILD NOW]`

```text
SR-1  Every DomainRecord is Ed25519-signed by DomainIdentity or by a key at
      the end of a valid DLG chain rooted at DomainIdentity.

SR-2  The signed message is
          "AXON-record-v1" ‖ 0x00 ‖ rtype ‖ record_bytes[0 .. len-65]
      — everything but the 64-byte signature, with the rtype hoisted into
      the prefix so a record can never be reinterpreted as another type.

SR-3  The signature covers zone_id, name, serial, not_before, not_after and
      the full dlg_chain. There is no field a relay can change.

SR-4  A resolver MUST verify the DLG chain root-to-leaf BEFORE the record
      signature, rejecting on: depth exceeded, constraint violated,
      may_further_delegate = 0 at a non-terminal link, or a link signed by a
      key that is not the previous link's child_key.

SR-5  DomainIdentity is authoritative only if it equals the on-chain
      domainKey (§12.3), OR is the old key of a KEYROT whose effective_at has
      not passed, OR is the new key of a KEYROT whose effective_at has passed
      and whose chain_state is 1.

SR-6  An off-chain-only KEYROT (chain_state = 0) is accepted for at most 48 h
      from effective_at, after which the resolver demands the on-chain
      commitment. R7 applied to keys: rotate at overlay speed, settle on
      chain, never let the fast path become permanent.

SR-7  ALIAS never transfers signing authority. A merge-mode alias imports
      records that must independently satisfy SR-1..SR-5 in the TARGET zone.

SR-8  No wildcards — not "*.alice.lab.axon", not a DLG constraint matching a dot.
      Wildcards × delegation × aliasing is the region of DNS resolver code
      that generates CVEs, and v1 does not go there.  [NEEDS RESEARCH]

SR-9  Records are published to the DHT under a key BLINDED per time period
      from DomainIdentity, as service descriptors are (R4c), so a storing
      node learns neither zone nor querier. The blinding construction is the
      Ed25519 scalar blinding fixed in §2 and specified at L6; this section
      fixes only that naming uses it.

SR-10 Revocation is monotone and sticky. A resolver that has verified an RVK
      MUST persist it and MUST NOT accept any later record it covers,
      regardless of serial and regardless of any later chain state that
      appears to un-revoke. Un-revocation is not supported; the recovery path
      is a new key and a new version.
```

---

### 11.9 The fallback self-certifying address `[BUILD NOW]`

§5.8 establishes that every `DomainIdentity` and `ServiceIdentity` is directly
addressable by its public key. This fixes the encoding the naming layer accepts.

```text
body     = pubkey(32) ‖ checksum(2) ‖ version(1)            = 35 bytes
checksum = SHA-256( "AXON-selfcert-v1" ‖ 0x00 ‖ pubkey ‖ version )[0..1]
version  = 0x01
address  = base32-lower-nopad(body)                         = 56 characters
form     = <address>.key.axon
URI      = axon://<address>.key.axon/<vport>/<path>
```

56 characters fits a 63-byte label, so the form is syntactically a name and
string handling needs no second code path. `key` is reserved (§11.3.1), so
`key.axon` can never be registered and the namespace can never be shadowed. A
resolver seeing a second-level label of `key` short-circuits: verify checksum,
decode key, go straight to the descriptor lookup. **No chain, no registry, no
snapshot, no `DomainRecord`.** This is the Tor v3 onion-address construction —
key ‖ checksum ‖ version, base32 — with the checksum domain-separated to our
label and the address placed under the TLD rather than beside it.

| Situation | Why the name fails | Why the address works |
|---|---|---|
| Snapshot older than the freshness bound; the resolver refuses (R7, §12.6) | It will not assert a binding it cannot date | The key *is* the binding |
| Ethereum unreachable, reorging, or every reachable RPC censoring | The slow path has no answer | Never consulted |
| Name expired, transferred, or revoked, but the operator still runs the service | The chain says the binding is gone, correctly | The service key is unchanged |
| Registry migration to a new contract or chain (§12.2) | The binding is in flight between authorities | Unaffected by either |
| The operator deliberately never registers | Registration is an on-chain event linkable to a funding graph (R6) — for some publishers, buying a name is the deanonymising act | No transaction, no payer, no trace |
| First contact / bootstrap | Nothing is resolved yet | Self-verifying from the first byte |
| The user was handed the key out of band and wants to pin it | A name adds a trusted binding they did not ask for | No binding to trust |

The cost, honestly: not memorable, not transferable, not revocable by anyone but
the keyholder (destroying the key is the only revocation), no delegation, and it
cannot be rotated — rotating changes the address, which is the definition of a
self-certifying identifier and the reason the naming layer exists. A publisher
needing both properties publishes both and accepts that the two are linkable.

#### 11.9.1 Vanity addresses `[BUILD NOW]`

The first characters of the address are the base32 encoding of the first bytes of
the public key, so a publisher may **grind keypairs until the encoding begins
with a chosen prefix** — `alice7k2m…q7d.key.axon`. This costs nothing but CPU,
requires no registration, no chain, no namespace and no vote, and it is the only
form of memorability available at Layer 1.

The arithmetic is exact. base32 carries 5 bits per character, so an `n`-character
prefix costs `32ⁿ` expected attempts:

| Prefix | Expected attempts (`32ⁿ`) | Shape of the search |
|---|---|---|
| 4 | 1.05 × 10⁶ | seconds |
| 5 | 3.36 × 10⁷ | seconds to a minute |
| 6 | 1.07 × 10⁹ | minutes |
| 7 | 3.44 × 10¹⁰ | a machine-hour or so |
| 8 | 1.10 × 10¹² | a machine-day, order of magnitude |
| 10 | 1.13 × 10¹⁵ | a machine-year, order of magnitude |
| 12 | 1.15 × 10¹⁸ | out of reach |

The attempt counts are exact; the wall-clock column is an order-of-magnitude
shape for a commodity multi-core search at roughly 10⁶–10⁷ candidate keys per
second per machine, **not a measurement**. Anyone quoting a schedule should
benchmark the actual grinder. The qualitative answer is what matters: short
prefixes are free, the middle is a machine-day, and past about ten characters it
stops being reachable — which is the same curve that makes an 8-character prefix
*forgeable by an attacker* (§11.9.2).

**Key hygiene, and it is a real requirement.** Fast grinders derive candidates by
incrementing a scalar rather than regenerating a seed, which makes candidate keys
related by a known offset. Either generate a fresh full-entropy seed per
candidate, or — if the incremental method is used for speed — require that the
base seed has full entropy and that the base and every non-selected offset are
destroyed. **Vanity mining must never reduce the entropy of the key that is
kept.** A grinder that seeds from a timestamp, a counter, or a weak PRNG produces
addresses an attacker can re-derive, and that failure mode has appeared in
deployed vanity tooling for other systems more than once.

#### 11.9.2 Vanity prefixes are a phishing surface — the real risk

Users compare the first few characters and stop reading. An attacker who grinds
the *same* 8-character prefix — a machine-day, from the table above — produces an
address that passes casual inspection against the genuine one. This is not
theoretical; prefix-collision phishing has been used against onion services.

The mitigations are unglamorous and all of them are required:

| Mitigation | Where | Effect |
|---|---|---|
| Never abbreviate an address in any UI, ever | §13.7, §20 | Removes the "compare the ends" habit that the attack depends on |
| Render a checksum-derived fingerprint beside it — colour block, or a word list over the full 35-byte body | §13.7 | Gives a comparison target that a prefix grind does not control |
| Prefer a verified name over an address for human display, address secondary | §13.7, §13.9 | Moves humans off Layer 1 identifiers for routine use |
| Treat a full-address paste as the only trustworthy transfer of an address | §20 | Removes transcription entirely |

**A ground prefix carries no authority.** It is not a registration, it is not a
namespace, it is not endorsed, and it means nothing except that someone spent
CPU. `paypal7x…key.axon` is available to anyone with a machine-day. The naming
layer exists precisely because Layer 1 cannot express "this is really them", and
vanity mining is a memorability trick that must never be presented as an identity
claim.

#### 11.9.3 The two layers, side by side

| | Service address (Layer 1) | Registered name (Layer 3) |
|---|---|---|
| Needs a chain | No | Yes, to establish ownership |
| Needs governance | No | Yes — the namespace must have been approved |
| Can be revoked | No — only by destroying the key | Yes, by expiry or registrar policy |
| Human-memorable | Only via a ground prefix | Yes |
| Survives governor capture | Yes | No (§12.0a, the fork right) |
| Survives chain outage | Yes | Only within the snapshot freshness bound (§12.6) |
| Deanonymisation surface | None — no transaction, no payer | Registration is an on-chain event linkable to a funding graph (R6) |
| Phishing surface | Prefix collision (§11.9.2) | Homograph and cross-namespace confusion (§11.3.3) |
| Cost | CPU, once | Registration + renewal, forever |

---

### 11.10 Decisions

| Decision | Problem it solves | Derived from Tor / I2P / Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Human name as a thin layer over a self-certifying address | Onion/I2P addresses are unusable by humans; DNS names are unverifiable | Tor v3 `.onion`; I2P destinations + addressbook | The human layer is *optional* and every failure degrades to the key, rather than the two being alternatives | Addressbook-only (I2P): no global uniqueness, so two users can disagree about who `alice` is. Petnames-only: no shared reference | A name is a linkable on-chain artifact (R6); publishing one is a deanonymising act the key-only path does not require |
| ASCII LDH labels only, no Unicode in v1 | Homograph attacks, the dominant real-world naming attack | None — none of the three has a human namespace with this problem | Enforced on chain, not in clients | Full IDNA2008 + UTS-46 (large confusable surface; partial deployment is worse than none). Per-script restriction (correct, deferred) | Excludes every non-Latin script. Real and unmitigated |
| On-chain confusable skeleton index | ASCII confusables `rn`/`m`, `1`/`l`, hyphen elision | None | A second uniqueness constraint over an equivalence class, computed in the contract | Client-side warnings (not a rule); a dispute process (no authority to run one) | First registrant owns a whole class; honest latecomers blocked. Class boundaries cannot change without a migration |
| Subdomains by signed `DLG`, no transaction | Chain latency and fee per subdomain would make hierarchy unusable | Freenet signed subspaces | Explicit constraint language, bounded depth, chain inline so verification needs no fetch | Every subdomain on chain (cost, latency, per-subdomain censorship surface); unconstrained delegation (a child key becomes indistinguishable from the parent) | A leaked child key is authoritative over its subtree until revoked, and propagation is bounded by §11.7, not instant |
| `ZONE` apex with an RFC 6962 set root | Provable negative answers without querying an authority per name | DNS NSEC adopted; NSEC3 rejected | We do not attempt zone privacy at all, and say so | NSEC3-style hashed denial (walked in practice); no negative answers (a resolver cannot tell "absent" from "withheld") | Zones are fully enumerable; an unenumerable endpoint must use §11.9 |
| `serial` monotonicity + `chain_version` in the apex | Rollback by a hostile storing node | Tor descriptor revision counters | Tied to the on-chain version so a rotation or transfer cannot be replayed away | Timestamps alone (clock skew; a hostile node picks the timestamp it likes) | A resolver that has not yet seen version `v` is still rollback-able inside the freshness bound |
| No wildcards | Wildcard × delegation × alias is where DNS resolvers generate CVEs | DNS, deliberately not adopted | Omission | Wildcards with a depth cap (still interacts with `merge` aliases in ways we could not enumerate) | Operational friction: a large flat subtree needs many records or a delegation |
| Records under blinded DHT keys | A storing node learning which zones it holds is a map of the namespace | Tor v3 descriptor key blinding | Applied to naming records, not only service descriptors | Plain `zone_id` keys (a storing node enumerates the namespace and selectively drops) | Uncorrelatable to us as well: a resolver cannot tell a censored zone from an unpublished one |
| `.axon` with `TLD` as one constant | Rename risk | — | — | Hard-coding the string everywhere | Not IANA special-use, so misconfigured stubs leak lookups to public recursives |

---

### 11.11 What this section does NOT establish

- **That ASCII-only is acceptable.** It is a v1 expedient with a stated
  exclusion. A namespace that cannot express most of the world's writing systems
  is a defect; the per-script confusable work is real and unscheduled.
- **Any measurement.** No record size, resolution latency, DHT round trip or
  storage cost here is measured. The byte layouts are exact because they are
  specifications; the operational numbers are not.
- **A solution to phishing.** The skeleton index handles confusables and nothing
  else. There is no dispute process, no trademark mechanism, and no authority to
  create one.
- **The resolver.** Cache structure, negative caching, query scheduling, circuit
  isolation per lookup and the API surface are §13. This section fixes only the
  data and the rules a resolver must obey.
- **The blinding construction.** SR-9 says naming uses the same Ed25519 blinding
  as descriptors; the construction is fixed at L6 and assumed here.
- **Containment of `.axon` query leakage.** Without a special-use registration, a
  misconfigured stub publishes the fact that a user is looking up an AXON name.

---

## 12. Ethereum Root Registry, Registrars, and Governance

**The finding that decides the chain question: the light client that already
exists verifies L1, and only L1.** `doc/trust-anchor.md` records a native
sync-committee implementation that verified a 512/512 mainnet signature at
attested slot 14994657 and established finality — thousands of lines, a BLS
dependency on the security path, ongoing maintenance against Ethereum's fork
schedule. Every alternative in §12.2 either has no light client we can verify or
requires a *second* verification path on top of the one we already maintain.
Against an asset that expensive, cost per registration is a rounding error.

Second finding: **the registry is on the read path almost never.** R7 puts the
chain behind a locally-verified snapshot; §11 puts day-to-day records entirely
off chain, signed by `DomainIdentity`. What the registry actually is, then, is a
five-slot-per-name ownership table proved against roughly once a day, plus a
periodic Merkle commitment that lets a resolver not do even that. Design it for
*provability*, not throughput.

---

### 12.1 What already exists

This is an extension of existing practice, not a new capability.

| Asset | Path | What it gives us |
|---|---|---|
| Solidity + Hardhat toolchain | `proof-of-facilitation/hardhat.config.ts`, `package.json` | solc 0.8.24, optimizer runs 200, OpenZeppelin 5.1, mainnet + Sepolia configured, `npm test` on the plain-EVM hardhat network |
| Deployed mainnet contract | `ChannelManagerV2` at `0x2a2a1b58d5cdb1e89b385e51681658e663a1a03c`, block 25757314 (`doc/trust-anchor.md` §6) | Proof the deploy path works end to end, and a live example of storage-layout discipline |
| Registry pattern | `proof-of-facilitation/contracts/NodeRegistry.sol` | Nearly every primitive `AxonRegistry` needs, written and tested: identity binding, uniqueness (`p2pKeyUsed`), key rotation with old-retire/new-activate, `endpointCommitment` instead of a raw endpoint, and `registerWithSig` — a meta-tx where the owner is **recovered** from the signature so the relayer can never name the owner |
| Bond / slash / dispute machinery | `StakeVault.sol`, `DisputeManager.sol`, `EpochManager.sol` (optimistic challenge window, freeze/invalidate, finalize-after-window) | The snapshot anchorer of §12.6 is the same shape as the epoch aggregator and reuses the bond and challenge pattern |
| Merkle-proof claims | `RewardDistributor.sol` — claims against a finalized `rewardRoot`, once per `(epoch, nodeId)` | Prior art for "commit a root, prove a leaf" inside this repo |
| MPT state-proof verifier | `storage-client/internal/ethproof/proof.go` — `VerifyProof`, `StorageSlotKey(k, position) = keccak256(k ‖ uint256(position))`, `SlotAt(base, n)`, `AccountStorageRoot` | The §12.5 read path already exists and is root-agnostic. Absence is an answer: `(nil, nil)` for a proven-absent slot |
| Measured proof sizes | `doc/ethereum-data-layer.md` §6b, mainnet block 25,737,778 | account proof **3879 B** (9 nodes), populated slot **2989 B** (7–9 nodes), absent slot **160 B**, verified read **~210–290 ms** |
| Light client | `internal/ethproof/{lightclient,rotation,finality,ssz,bls}.go` | The trust anchor. L1 only |

**What must be replaced:** nothing. No existing contract does naming;
`AxonRegistry` is additive. **What must be re-measured:** the WETH-derived proof
sizes above are an upper bound from a trie with millions of entries. §12.5
derives registry figures from them and says where they will be smaller.

---

### 12.0 The root registry and the registrar interface `[BUILD NOW]`

The root zone is a contract holding namespaces, not names. It knows nothing about
`alice`; it knows that `lab` exists, that it is ACTIVE, and which contract decides
who may register beneath it.

```solidity
enum NsStatus   { NONE, PROPOSED, ACTIVE, FROZEN, RETIRING, RETIRED }
enum RegClass   { IMMUTABLE, UPGRADEABLE, STEWARDED }   // surfaced to users, §13.7

struct Namespace {
    address  registrar;       // implements IRegistrar
    RegClass registrarClass;  // what the registrar may do to a name later
    NsStatus status;
    address  steward;         // may be address(0); powers are namespace-local only
    bytes32  charter;         // ContentIdentity of the human-readable policy (§10)
    uint256  bond;            // posted by the proposer, slashable
    uint64   activatedAt;
    uint64   retiresAt;       // 0 unless RETIRING; >= activatedAt + 90 days
    uint16   recordSchema;    // lets namespaces evolve record formats independently
}

interface ITLDRegistry {
    function namespaceOf(bytes32 labelHash) external view returns (Namespace memory);
    function isEligible(string calldata label) external view returns (bool);
    // mutations are callable ONLY by the governor (§12.0a), never by an EOA
}

/// Every namespace's registrar implements this. The root calls nothing on it;
/// resolvers and clients do. A registrar is free to be an auction, a flat fee,
/// an allowlist, or a closed set — the root neither knows nor cares (§11.0.3).
interface IRegistrar {
    function ownerOf(bytes32 nameHash)     external view returns (address);
    function domainKeyOf(bytes32 nameHash) external view returns (bytes32, uint64);
    function expiresAt(bytes32 nameHash)   external view returns (uint64);
    function available(string calldata label) external view returns (bool);
    function schemaVersion()               external view returns (uint16);
}
```

`registrarClass` exists because **a namespace is only as safe as its registrar**,
and a user deciding whether to build on `corp.axon` needs to know that before
registering, not after. It is displayed at registration time and in resolver
diagnostics (§13.7):

| Class | Meaning | What the holder is exposed to |
|---|---|---|
| `IMMUTABLE` | No upgrade path, no steward, no admin function that touches a name | Registrar bugs are permanent, but nobody can seize a name |
| `UPGRADEABLE` | Proxy or migration function exists | The upgrade key can rewrite the rules under existing holders |
| `STEWARDED` | A named address holds enumerated powers within the namespace | The steward can act on names, per the charter |

`AxonRegistry` (§12.3) is the **reference `IRegistrar` implementation** and the
registrar for the first namespace. It is `IMMUTABLE`. Nothing in §12.3 changes;
it is simply no longer the only registrar, and its five-slot layout becomes the
shape a resolver expects by default rather than the only shape it can read.

### 12.0a Governance: what the vote may and may not do `[NEEDS RESEARCH]`

**The invariant that matters most, stated before anything else:**

> Governance acts on the root. It never acts on a name, a key, a service, or a
> byte of traffic. There is no governance path that seizes `alice.lab.axon`,
> changes its `DomainIdentity`, reads its records, or affects its routing.

This invariant is what separates a namespace that has governance from a network
that has a landlord. It is enforced by the absence of any such function on
`ITLDRegistry`, and it is restated in §18 as a property to be tested, not
assumed.

#### Enumerated powers

| Power | Threshold | Timelock | Notes |
|---|---|---|---|
| Create a namespace | supermajority | 14 days | Proposer posts a slashable bond; returned on activation |
| Freeze a registrar (emergency) | guardian, or vote | 0 / 7 days | Blocks **new registrations only**. Existing names keep resolving, unchanged |
| Begin retiring a namespace | supermajority | 90 days minimum | Existing names grandfathered for the full notice; see below |
| Update the reserved-label list | simple majority | 30 days | Cannot retroactively invalidate an active namespace |
| Set root parameters (bond, deposit, timelock lengths) | supermajority | 30 days | |
| Register a new `recordSchema` version | simple majority | 30 days | Additive only |

**Absent by construction:** transfer a name, revoke a name, alter a
`DomainIdentity` binding, mint names, redirect a resolver reference for a name it
does not own, upgrade a registrar marked `IMMUTABLE`, or shorten a retirement
notice.

**Retirement does not confiscate.** A retiring namespace keeps resolving for the
full 90-day notice; at retirement the names stop resolving but the services
behind them are untouched and remain reachable at Layer 1 (§11.9). Retirement
costs holders their memorability, never their service. That asymmetry is the
whole reason Layer 1 is the guarantee.

#### Voting power, and the objection to it

This is where governance designs fail into plutocracy, so the construction is
argued rather than asserted:

```text
weight = f( bonded stake in StakeVault × time-lock multiplier ,
            measured contribution from the PoF epoch record )
```

The second term is the reason this is worth building at all. **Proof of
Facilitation already produces a verified, per-epoch, per-node record of
contributed bandwidth, storage and uptime** (`EpochManager`, `RewardDistributor`,
§14). Weight accrues to the people who actually run the network, measured by
machinery that exists and is already adversarially checked. Reuse `StakeVault`
and `EpochManager`; do not mint a governance token.

The objections, which belong in the text and not in a footnote:

| Objection | Status |
|---|---|
| Contribution can be bought by renting servers, so the second term is wealth-adjacent, not wealth-free | **Conceded.** It raises the cost of buying influence; it does not remove the possibility |
| Stake weighting is plutocratic by construction | **Conceded.** The time-lock multiplier converts wealth into *committed* wealth, which is a different and slower thing, but it is still wealth |
| Time-locking reduces liquidity and therefore participation | Real. Low participation is the attack surface below |
| Low turnout makes any quorum cheap to capture | **The dominant practical risk.** Mitigated only by the timelock and the fork right, both of which are reactive |

`[NEEDS RESEARCH]` — the weighting function, the quorum floor, and the turnout
assumption are not settled and should not be frozen before a governance
simulation exists (§21). Shipping the root registry with governance stubbed to a
multisig and a published migration path is a legitimate v1, and is what §23 P9b
schedules.

#### Process, and why the timelock is not a formality

```text
propose (slashable deposit)
   │
   ├─ eligibility predicate: IANA snapshot, special-use, length, reserved (§11.0.2)
   ▼
discussion window
   ▼
vote  →  quorum + supermajority
   ▼
TIMELOCK  ← the window in which a capture attempt is visible and resolvers
   │         can pin away from it before it takes effect
   ▼
activate
```

**The guardian.** A veto-only security council: it may block, never enact; it
expires and must be re-authorised. It is an acknowledged centralisation point and
a standing target, and it exists because a 14-day timelock cannot respond to a
live exploit. Anyone claiming the system is trustless while a guardian exists is
wrong, and the document says so here rather than letting a reader discover it.

**Where authority actually lives — the fork right.** A resolver is configured
with a `TLDRegistry` address. If governance is captured, resolvers repoint, and
the captured root governs an empty set. The namespace is canonical exactly to the
extent that resolvers agree it is. That is the honest bottom of the system: not
the contract, not the vote, but the configuration of the people running
resolvers. §13.3 makes the pinned root address explicit configuration for that
reason.

---

### 12.2 Chain selection

Scored 1–5, higher better. Engineering judgement, not measurement; the decisive
column is **light-client verifiability**.

| Criterion | A. Ethereum L1 | B. Optimistic rollup | C. Validity (zk) rollup | D. Other EVM L1 | E. App-chain / sidechain | F. Hybrid: L1 + snapshot |
|---|---|---|---|---|---|---|
| Cost per registration | 2 | 5 | 5 | 4 | 5 | 2 |
| Security / finality | 5 | 3 | 4 | 2 | 1 | 5 |
| Data availability | 5 | 4 | 4 | 3 | 1 | 5 |
| **Light-client verifiability** | **5** | **2** | **3** | **1** | **1** | **5** |
| Censorship resistance | 4 | 3 | 3 | 3 | 1 | 4 |
| Sequencer / dependency risk | 5 | 2 | 2 | 3 | 1 | 5 |
| Migration risk | 5 | 3 | 3 | 2 | 2 | 4 |
| **Total** | **31** | **22** | **24** | **18** | **12** | **30** |

- **A — Ethereum L1.** The light client exists and verifies it; finality is 2
  epochs (~12.8 min). The cost objection is weaker than it was: the project's own
  recorded reasoning in `hardhat.config.ts` states that post-Dencun average
  mainnet fees run roughly $0.16–0.22, a simple transfer is under a cent, and
  that this is the same order of magnitude as the L2s. **That is a code comment,
  not a measurement we made** — treat it as the basis the project already
  accepted, and re-measure before publishing a fee schedule. A registration is
  not a simple transfer; §12.5 costs it at five cold `SSTORE`s.
- **B — Optimistic rollup.** Cheap, inherits L1 data availability, and fatally
  slow to *verify*. See below.
- **C — Validity rollup.** The right L2 if one is ever needed, for the finality
  reason below.
- **D — Another EVM L1.** Cheaper, and the light client is worthless there. We
  would write and maintain a second consensus verifier against a second fork
  schedule — exactly the cost `doc/trust-anchor.md` §2 itemises — for a chain
  with less security. No version of this is a good trade.
- **E — App-chain / sidechain.** Scores 1 on everything that matters: a chain
  whose validator set we bootstrap is a directory authority with extra steps. R14
  refuses a consensus document for the relay set; accepting one for the namespace
  would be inconsistent, and it is the re-centralisation R5 refuses elsewhere.
- **F — Hybrid.** Not an alternative to A; it is A's read path. Registration and
  transfer are L1 transactions, resolution is a snapshot proof (§12.6). This is
  what R7 mandates and what makes A's cost acceptable, because the cost is paid
  once per name-year rather than once per lookup.

#### The L2 verification problem, worked through

An L2 name is only trust-minimisingly verifiable by following the L2 output root
posted to L1, which the existing L1 light client can anchor:

```text
  weak-subjectivity checkpoint
        │  (existing: internal/ethproof)
        ▼
  sync-committee updates ──▶ verified beacon header
        │  execution_branch (SSZ)
        ▼
  L1 execution stateRoot                     ← the light client stops here
        │  eth_getProof(rollup output contract, slot of output[i])
        ▼
  L2 output root                             ← NEW: stack-specific storage layout
        │  the output root commits to (stateRoot_L2, storageRoot, blockHash)
        ▼
  L2 state root                              ← NEW: stack-specific preimage
        │  eth_getProof against the L2 registry, verified against stateRoot_L2
        ▼
  AxonRegistry storage slot on L2
```

What that requires: **no new proof code** (`VerifyProof` takes a root and a key
and does not care where the root came from, so the second MPT walk is free);
**new chain-specific code** for the output contract's storage layout, the output
root's preimage structure, and which proposal index is current — a per-stack
integration with a per-stack upgrade schedule, maintained *alongside* Ethereum's
fork schedule rather than instead of it; and **new failure modes**, notably a
proposer that stops proposing, which stalls the read path without stalling the
chain.

| | Optimistic rollup | Validity rollup |
|---|---|---|
| Output root posted to L1 | Minutes to ~1 h after the L2 block, stack-dependent | With, or shortly after, the proof |
| Root *unchallengeable* | After the fault-proof window — canonically **7 days** | Immediately: L1 verified the validity proof at posting time |
| Trust-minimised finality for a new name | L1 finality **+ 7 days** | L1 finality (~12.8 min) **+ proving/batch latency** (stack-dependent, tens of minutes to hours today) |
| Before that | The proposed root can be replaced. Believing it is trusting the proposer — the assumption `doc/trust-anchor.md` §1 refuses for headers | n/a |

For a name **just registered or transferred**, an optimistic rollup leaves three
options: tell the user their name does not resolve trust-minimisingly for a week;
accept the proposer's word for a week, which is exactly the trust the light
client was built to remove; or run two resolution modes with different security
properties and hope users know which one they are in. None is acceptable for a
transfer, where the seven-day window is precisely the window in which the seller
still appears to own the name. A validity rollup collapses this to L1 finality
plus proving latency. **If AXON ever moves the registry off L1, it moves to a
validity rollup and never to an optimistic one** — independent of cost.

#### Recommendation

**Deploy `AxonRegistry` on Ethereum L1 mainnet. Resolve from the
`RegistrySnapshot` (§12.6), never from an RPC on the hot path.** Because: (1) the
light client is the most valuable existing asset for this layer and it verifies
L1, so anything else discards or duplicates it; (2) registration volume is
inherently low — a namespace is not a payment system, and optimising the chain
for a cost paid once per name-year at the expense of the verification path
exercised on every resolution is the wrong trade; (3) R7 already puts the chain
off the request path, so L1's per-transaction cost is an acquisition cost the
registrant pays knowingly; (4) Sepolia first, always, per the existing practice
in `hardhat.config.ts` — and with more force here, because a registry accumulates
state a redeploy cannot abandon.

**Migration risk, not assumed away.** A registry that must move is worse than a
payment contract that must move: names are long-lived and owners are not all
reachable. `AxonRegistry` ships `freeze()` (timelocked; halts registration and
transfer, leaves reads working), a write-once `migrationTarget`, and the guarantee
that a frozen registry is fully reconstructible from `RegistrySnapshot` leaves
plus the event log. `[NEEDS RESEARCH]` — the *social* half, getting resolvers to
switch without that switch being a takeover vector, is not solved by any of this.

---

### 12.3 The registry contract `[BUILD NOW]`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title AxonRegistry — the reference IRegistrar (§12.0): ownership of the
/// names in ONE namespace, and nothing else. Deployed once per namespace; the
/// root registry holds only the label -> registrar mapping. RegClass IMMUTABLE.
/// Knows a name, its owner, its expiry, and a 32-byte Ed25519 DomainIdentity.
/// It does not know endpoints, services, content, users, or lookups (§12.7).
/// Five packed slots per name, because every extra slot is ~2989 B of proof
/// (measured, doc/ethereum-data-layer.md §6b) on the resolver's slow path.
/// The layout is part of the interface, not an implementation detail — §12.5.
interface IAxonRegistry {
    struct Name {
        address owner;         // OwnerIdentity (secp256k1). Never on the overlay.
        uint64  expiresAt;
        uint32  version;       // bumped on EVERY mutation. Anti-rollback (§11.7).
        bytes32 domainKey;     // DomainIdentity, Ed25519 public key, verbatim.
        bytes32 resolver;      // resolverId; 0 = DHT records only (the default).
        bytes32 skeleton;      // confusable class (§11.3.3).
        uint64  registeredAt;
        uint64  keyValidFrom;  // rotation effective time; old key dead after.
        uint64  mutatedAt;     // block number of last mutation (§12.6 challenge).
        uint8   flags;         // bit0 transferLocked, bit1 revoked
    }

    struct Snapshot {
        bytes32 root;          // sparse Merkle root over nameHash -> leaf
        uint64  blockNumber;   // anchor block; MUST be finalized when posted
        uint64  timestamp;
        uint32  nameCount;
        uint32  sequence;
        address poster;
        uint64  postedAt;
        uint32  challengeState; // 0 open, 1 accepted, 2 invalidated
    }

    event Committed       (bytes32 indexed commitment, uint256 timestamp);
    event Registered      (bytes32 indexed nameHash, address indexed owner,
                           bytes32 skeleton, uint64 expiresAt, uint32 version);
    event Renewed         (bytes32 indexed nameHash, uint64 expiresAt, uint32 version);
    event Transferred     (bytes32 indexed nameHash, address indexed from,
                           address indexed to, uint32 version);
    event DomainKeySet    (bytes32 indexed nameHash, bytes32 domainKey,
                           uint64 keyValidFrom, uint32 version);
    event DomainKeyRevoked(bytes32 indexed nameHash, bytes32 revokedKey,
                           uint8 reason, uint32 version);
    event ResolverSet     (bytes32 indexed nameHash, bytes32 resolverId, uint32 version);
    event Released        (bytes32 indexed nameHash, uint32 version);
    event SnapshotCommitted  (uint32 indexed sequence, bytes32 root,
                           uint64 blockNumber, uint32 nameCount, address poster);
    event SnapshotInvalidated(uint32 indexed sequence, bytes32 nameHash,
                           address challenger);
    event Frozen          (address migrationTarget);

    error BadLabel();   error Reserved();     error ClassHeld();   error NotOwner();
    error NotAvailable(); error InGrace();    error CommitTooNew(); error CommitTooOld();
    error NoCommit();   error BadPayment();   error Locked();      error KeyRevoked();
    error ResolverBound(); error NotFinalized(); error BadProof();  error IsFrozen();

    // --- registration -----------------------------------------------------
    /// commitment = keccak256(abi.encode(label, owner, secret, domainKey, resolverId))
    function commit(bytes32 commitment) external;

    function register(string calldata label, address owner, bytes32 secret,
                      bytes32 domainKey, bytes32 resolverId, uint64 durationYears)
        external payable returns (bytes32 nameHash);

    /// Meta-tx form. The owner is RECOVERED from the signature, exactly as
    /// NodeRegistry.registerWithSig does, so a relayer/paymaster pays the gas
    /// without being trusted to name the owner and without being able to pay
    /// itself. Also the R6 mechanism: the funding account need not be the
    /// owning account.
    function registerWithSig(string calldata label, bytes32 secret,
                      bytes32 domainKey, bytes32 resolverId, uint64 durationYears,
                      uint256 nonce, uint8 v, bytes32 r, bytes32 s)
        external payable returns (bytes32 nameHash);

    function registrationDigest(string calldata label, bytes32 domainKey,
                      bytes32 resolverId, uint64 durationYears, uint256 nonce)
        external view returns (bytes32);

    /// Another member of a skeleton class already held by msg.sender, at the
    /// sibling price, expiring with the class holder (§11.3.3).
    function registerSibling(bytes32 heldName, string calldata label)
        external payable returns (bytes32 nameHash);

    // --- lifecycle --------------------------------------------------------
    function renew(bytes32 nameHash, uint64 durationYears) external payable;
    function transfer(bytes32 nameHash, address to) external;  // zeroes domainKey
    function setTransferLock(bytes32 nameHash, bool locked) external;
    function setDomainKey(bytes32 nameHash, bytes32 key, uint64 validFrom) external;
    function revokeDomainKey(bytes32 nameHash, uint8 reason) external;
    function setResolver(bytes32 nameHash, bytes32 resolverId) external;
    /// Anyone may release a name past grace+premium for a bounty from feePool,
    /// keeping nameCount and the snapshot honest without a privileged sweeper.
    function release(bytes32 nameHash) external;

    // --- resolver indirection (append-only) --------------------------------
    /// id = keccak256(abi.encode(chainid, address(this), impl, salt)).
    /// Reverts if already bound: an id is an immutable pointer, so a name
    /// pointing at one cannot be repointed by whoever set it.
    function bindResolver(address impl, bytes32 salt) external returns (bytes32 id);

    // --- snapshot ---------------------------------------------------------
    function commitSnapshot(bytes32 root, uint64 blockNumber, uint32 nameCount)
        external payable;                                  // requires ANCHOR_BOND
    /// Fraud proof: supply the sparse-Merkle path for nameHash under the posted
    /// root. The contract recomputes the leaf FROM ITS OWN STORAGE and walks the
    /// path. Equal root -> challenge fails; different -> poster slashed and the
    /// snapshot invalidated. Admissible only while
    /// names[nameHash].mutatedAt <= snapshot.blockNumber.
    function challengeSnapshot(bytes32 nameHash, bytes32[] calldata siblings,
                               bytes32 bitmap) external;
    function finalizeSnapshot(uint32 sequence) external;    // after SNAPSHOT_WINDOW

    // --- views ------------------------------------------------------------
    function nameOf(bytes32 nameHash) external view returns (Name memory);
    function available(bytes32 label) external view returns (bool);
    function skeletonOf(string calldata label) external pure returns (bytes32);
    function priceOf(string calldata label, uint64 durationYears)
        external view returns (uint256);
    function snapshot() external view returns (Snapshot memory);
}
```

Immutables — no storage, unchangeable under live registrations, the same
reasoning `ChannelManagerV2` gives for its `challengePeriod`:

```text
TLD_NODE bytes32 = namehash("axon"), computed at deploy
GRACE_PERIOD 90 d   PREMIUM_PERIOD 21 d   MIN_COMMIT_AGE 60 s
MAX_COMMIT_AGE 24 h  KEY_OVERLAP_MAX 48 h  SNAPSHOT_WINDOW 24 h
ANCHOR_BOND uint256  TREASURY address
```

#### Commit–reveal, and the two reasons for it

```text
t0                       commit(keccak256(label, owner, secret, domainKey, resolverId))
                         -> only a hash is public: no label, no key, no owner
t0+60s .. t0+24h         register(label, owner, secret, domainKey, resolverId, years)
                         -> label revealed, commitment checked, registered atomically
```

**Front-running:** without it, a `register(label, …)` in the mempool invites a
searcher to take the same label with more gas. **The R6 reason:** the commitment
comes from one account while the registration may be *submitted* by a relayer via
`registerWithSig` with the owner recovered from the signature, so payer and owner
differ; and the 60 s – 24 h window means commit timing does not pin reveal
timing. `MIN_COMMIT_AGE` is 60 s rather than one block because a one-block gap is
vulnerable to a reorg that reorders commit and reveal; `MAX_COMMIT_AGE` bounds
the commitment set.

**What it does not do,** because it is routinely oversold: it does not stop bulk
speculative registration — an attacker commits a dictionary and reveals what they
want. It protects a *revealed intent*, not *scarcity*.

**And it does not make ownership anonymous.** R6 is explicit. The transaction is
paid by an account, that account was funded by something, and §7(d)'s adversary
observes the chain completely and walks the funding graph. `registerWithSig`
moves the payer away from the owner and the overlay never sees either, but
**name-to-funding-graph linkage is a residual risk we do not solve.** The
recommendation is registration through an account with no other history. Do not
claim anonymous ownership.

#### Expiry, grace, and what happens to a name

```text
                    expiresAt         +90d                +111d
  ───────ACTIVE────────┤───GRACE────────┤────PREMIUM────────┤───FREE───▶
  resolves             │ does NOT       │ does NOT resolve  │
  renew/transfer/      │ resolve        │ anyone registers  │ anyone
  rotate allowed       │ ONLY the owner │ at a price        │ registers at
                       │ may renew      │ decaying to base  │ the base price
```

| At | Rule |
|---|---|
| `t >= expiresAt` | The on-chain binding stops being authoritative. A resolver MUST refuse every `DomainRecord` for the zone **regardless of that record's own `not_after`**. A signed record does not outlive the name it was signed under |
| Grace (90 d) | Only `renew`, by the current owner. `transfer`, `setDomainKey`, `setResolver` revert. Neither usable nor takeable. 90 d exceeds the plausible "the key was in a safe / I was unreachable" window |
| Premium (21 d) | Registrable by anyone; `priceOf` returns `base + P_max · 2^(-elapsed/1 day)`, so the premium falls ~2 million-fold over 21 days. Converts a race for the block after expiry into a three-week one-sided auction |
| Re-registration | `register` in PREMIUM or FREE **overwrites `domainKey`** and bumps `version`, instantly invalidating every outstanding record at any resolver that has seen the new version (§11.7 mechanism 3) |
| `release()` | Anyone may zero a fully-expired entry for a bounty, keeping `nameCount` and the snapshot clean without a privileged sweeper |

**Expiry needs no freshness, and that is load-bearing.** `expiresAt` is in the
snapshot leaf, so a resolver on a six-hour-old snapshot still expires names at
exactly the right instant. Only *transfers*, *rotations* and *revocations* are
freshness-sensitive, because only those are unpredictable from past state. That
is why the bound in §12.6 is tolerable.

#### Transfer, rotation, revocation

```text
transfer(nameHash, to):
    require owner == msg.sender, !transferLocked, ACTIVE
    domainKey := 0; keyValidFrom := 0; resolver := 0   <-- ATOMIC
    version += 1; owner := to

setDomainKey(nameHash, key, validFrom):
    require owner == msg.sender, ACTIVE, validFrom <= now + KEY_OVERLAP_MAX
    domainKey := key; keyValidFrom := validFrom; version += 1

revokeDomainKey(nameHash, reason):
    require owner == msg.sender
    domainKey := 0; flags |= REVOKED; version += 1
    emit DomainKeyRevoked(nameHash, previousKey, reason, version)
```

**Zeroing `domainKey` on transfer is not optional.** Otherwise a seller hands
over the on-chain row while keeping the Ed25519 key that signs every record under
it — the buyer owns the name, the seller controls what it says. The buyer's first
act is `setDomainKey`, and the name is dark in between. That gap is correct: a
name resolving to a key nobody has verified control of is worse than a name that
does not resolve.

`setTransferLock` addresses the opposite hazard — a compromised `OwnerIdentity`
transferring the name away irreversibly. A locked name needs unlock, then a wait,
then transfer, which is enough for a watching owner to notice. It is not a
recovery mechanism, and there is none, because there is no authority to run one.

Rotation pairs with the off-chain `KEYROT` of §11.6: the record rotates at
overlay speed and is honoured for at most 48 h (SR-6); the transaction makes it
durable. Revocation sets `domainKey = 0`, which every resolver reads as "does not
resolve", and emits the revoked key so a resolver following the verified header
chain (`doc/ethereum-data-layer.md` §5) sees it through the bloom filter without
a storage read. **Limitation:** the struct keeps no revoked-key history — a
resolver wanting "never accept this key again" must persist the event. An
on-chain revocation set would be unbounded state for a case the log covers.

#### Resolver indirection

`Name.resolver` is a `bytes32` id and `resolvers[id]` is **write-once**;
rebinding reverts. Indirection lets a name point at a resolution mechanism
without the registry knowing its ABI, and keeps 32 bytes in the packed struct.
Write-once matters because a mutable id would let whoever controls it repoint
every name using it — a single-point takeover of an arbitrary fraction of the
namespace, reintroducing exactly the authority this layer removes. **The default
is 0**, meaning "records live in the DHT, signed by `domainKey`", and that is the
expected case; on-chain resolvers exist for tooling interop and each one is
another thing §12.7's rule must be enforced against.

---

### 12.4 Registrar and pricing policy `[NEEDS RESEARCH]`

| Question | Decision | Reasoning |
|---|---|---|
| Denomination | **The network token.** Superseded — see §12.4a | *(Former ruling, retained because its objection survives the override:* pricing in the network token makes the namespace's cost depend on the token whose value depends on the network the names are for — circular, and a governance surface. An ETH/USD oracle would be a new trusted input on the registration path.*)* |
| Structure | By length, annual renewal | 3 chars 100× base, 4 chars 20×, 5 chars 5×, 6+ base. Renewal at the registration rate, so holding is not cheaper than acquiring |
| 1–2 char labels | **Not registrable.** Reserved | Pure scarcity with no good allocation mechanism. Release is `[UNSOLVED]` |
| Auctions | Rejected for the general case | An auction is a public bidding record, strictly worse under R6 than a fixed price paid once, and it adds a multi-day flow to every registration. The PREMIUM decay is a one-sided auction that costs nothing when nobody competes |
| Where fees go | A `feePool` in the registry, paying the anchorer's reward and the `release` bounty; surplus to `TREASURY` | Makes §12.6 self-funding rather than a volunteer subsidy |

**Squatting is `[UNSOLVED]`.** Annual renewal turns squatting from a one-time
cost into a rent, but not below the expected resale value. Length pricing makes
short names expensive but does nothing about the case that matters — a squatter
registering a specific name a specific project needs. PREMIUM decay stops
expiry-sniping only. The class right-of-first-refusal makes defensive
registration affordable only for a legitimate holder. The two mechanisms that
would actually work — a use requirement and a proof of personhood — are both
rejected: a use requirement is unverifiable without an oracle deciding what
counts as use, and a personhood requirement contradicts the entire project.
**There is no dispute process, no trademark mechanism, no arbitration.** That is
a consequence of having no authority, and it is a cost, not a feature.

---

### 12.4a Acquisition, denomination, and the bulk-squatting guard `[BUILD NOW]`

**RULING, superseding §12.4's denomination row.** A domain under any TLD this
network facilitates is **paid for in the network's own token**, and there are
exactly two ways to acquire one:

```text
PRIMARY    from the DAO          first issuance of a name nobody holds
SECONDARY  from the current owner  transfer of a name somebody holds
```

There is no third path. A name is never free, never granted, and never issued
outside those two.

**What this costs, stated because §12.4 argued it and the argument still holds.**
Pricing in the network's own token makes the namespace's cost depend on the token
whose value depends on the network the names are for. That circularity is real
and is now an accepted cost rather than a reason not to do it: the alternative —
ETH plus an oracle, or ETH at a fixed nominal price — puts either a trusted price
feed or a slowly-wrong number on the registration path. The decision is that a
network with its own token should transact in it, and the circularity is priced
in rather than argued away.

**Dependency, stated plainly:** the token is **written but undeployed** —
`proof-of-facilitation/contracts/AxonToken.sol`, an ERC20 (ticker ANON) mintable
only by a Treasury address. The registry and registrar are **unwritten**. The
Proof-of-Facilitation set is written, unit-tested and **deployed nowhere**
(`proof-of-facilitation/README.md`'s go-live checklist, item 1: a funded deployer
key). Every sentence in §12 that reads as though a contract were available is
describing unbuilt infrastructure. P9 cannot be finished without a deployment,
and no phase downstream of it may claim an on-chain check works.

#### The bulk-squatting guard `[BUILD NOW]`

§12.4 marks squatting `[UNSOLVED]` and §12.3 concedes that commit–reveal "does
not stop bulk speculative registration — an attacker commits a dictionary and
reveals what they want." **That concession is no longer an acceptable resting
place.** A registry that can be dictionary-swept by one funded actor has no
namespace worth resolving, and the guard is a requirement rather than an open
research question.

What the document has already ruled out, with reasons that still hold and should
not be re-proposed without new argument:

| Rejected | Why it stays rejected |
|---|---|
| A **use requirement** | Unverifiable without an oracle deciding what counts as use, which is an authority over the namespace |
| **Proof of personhood** | Contradicts the entire project |
| **Length pricing / annual renewal alone** | Raises the cost of holding, does nothing against a squatter targeting the one name a specific project needs |
| **Auctions for the general case** | A public bidding record, strictly worse under R6 |

So the guard must come from the acquisition path itself. The design space, none
of which is settled and all of which is `[NEEDS RESEARCH]` for parameters:

- **Escalating cost per acquirer.** The *n*-th name costs a superlinear multiple
  of the first. Prices a dictionary sweep out without pricing a first name out.
  Defeated by fresh accounts, so it needs to be bound to something scarcer than
  an address — which is where it meets the bond below.
- **Bonded registration.** A registration locks a bond, released on transfer or
  expiry. Turns a sweep into locked capital rather than a fee, and reuses
  `StakeVault`'s existing `withdrawDelay` so recycling is slow.
- **Rate limiting per epoch.** A hard cap on registrations per acquirer per
  epoch. Blunt, trivially defeated alone, useful in combination.
- **Reveal-rate limiting.** Commit–reveal already forces intent to be committed
  ahead of time; capping *reveals* per acquirer per block turns a dictionary into
  a queue.

> **What must NOT be claimed.** None of these stops a sufficiently funded
> adversary, and the honest framing is the one §7.7 uses for bonds generally:
> **this is a price, not a barrier.** The requirement is that bulk registration
> be made expensive and slow enough that it is not the default strategy — not
> that it be made impossible, which nothing here can do.

#### 12.4a.1 The reset problem, which is the whole difficulty

Every mechanism in the table above is a counter attached to an acquirer, and
**every counter attached to an acquirer is defeated by acquiring a new acquirer.**
Working the obvious candidates through:

| Bind escalation to | Cost to reset | Verdict |
|---|---|---|
| An address | one transaction | Free. Useless alone. |
| A bond | posting another bond | Splitting into *n* bonds makes cost **linear in names again** — the adversary's total locked capital is the same either way. |
| A bonded `NodeIdentity` | a bond **and** running a node | Better, but it makes naming conditional on operating infrastructure, which excludes the person who only wants a name. Rejected. |
| Account age | waiting | Defeats a *reactive* sweep; an adversary who plans ahead ages *n* accounts in parallel and pays the wait once. |

The pattern: **capital and identity both split; only time does not, and time
splits in parallel.** So no per-acquirer counter produces superlinear cost
against a prepared adversary. Any design resting on one is resting on the
adversary being unprepared.

That is a real negative result and it is the reason this section does not simply
pick "escalating cost per acquirer" and declare the problem solved.

#### 12.4a.2 What actually asymmetrises, and why

Two things do not split, and both come from the structure of the problem rather
than from the identity of the actor.

**(1) The squatter must act on speculation; the user acts on knowledge.** A
legitimate registrant knows which name they want. A squatter must take many names
hoping one is wanted. That asymmetry is in the *portfolio*, not the identity, so
splitting across addresses does not remove it — the adversary still holds *n*
names, whoever appears to hold them.

**(2) The squatter must eventually SELL, and §12.4a made selling a registry
operation.** Because the only two acquisition routes are the DAO and the current
owner, **every resale is a transfer the registry executes and can price.** The
squatter's entire business is the spread between acquisition and resale, and a
transfer levy taken by the DAO takes that spread directly.

This is the mechanism the earlier table missed, and it is qualitatively different
from everything in it:

```text
per-acquirer counters   price the ACT of registering   → split to defeat
a transfer levy         prices the EXIT                → nothing to split;
                                                          the name itself is
                                                          the thing being taxed
```

It needs no oracle, no personhood, no notion of "use", and it cannot be Sybilled,
because it attaches to the *name's* transfer rather than to anyone's identity.
And it is close to free for the legitimate holder, who rarely sells — which is
exactly the discrimination every other mechanism failed to achieve.

> **RULING.** The guard is a composite, and the transfer levy is its load-bearing
> member:
>
> | Mechanism | Prices | Splits? |
> |---|---|---|
> | **Transfer levy to the DAO**, decaying with holding time | the exit | **no** |
> | **Bonded registration**, released on transfer or expiry | the capital | yes, but stays linear-in-capital and slow to unwind through `StakeVault.withdrawDelay` |
> | **Reveal-rate limit per block** | the burst | yes, but turns a dictionary into a queue |
> | **Superlinear cost per acquirer within one epoch** | the reactive sweep | yes — kept only because it costs an unprepared adversary something and costs an honest registrant nothing |
>
> The levy **decays with holding time** so that a squatter selling within months
> forfeits most of the spread while a genuine holder selling after years does
> not. The decay curve is `[NEEDS RESEARCH]`: it is the parameter that decides
> whether this is a squatting deterrent or a tax on ordinary transfer, and it
> cannot be picked from an armchair.

**What this still does not stop, stated because it is the case that matters
most.** An adversary who wants to *deny* a name rather than profit from it is
unaffected by a levy on selling — they never sell. Against that adversary only
cost applies, and cost is a price. **A well-funded actor who simply wants a
namespace to be unusable can make it so**, and no mechanism in this document
prevents it. What the composite achieves is narrower and worth stating exactly:
it removes the *profitable* squat, which is the common case, and leaves the
*malicious* squat priced but possible.

---

### 12.5 Storage layout `[BUILD NOW]` — the interface to §13

Stated in the style of `doc/ethereum-data-layer.md` §2, and like that section it
must be **confirmed with `solc --storage-layout` before anything depends on it**.
The layout below is design intent; the compiler is the authority.

**CONFIRMED BY `solc --storage-layout` (2026-08-16), and it differs from the
design intent this section previously carried.** `Ownable` occupies **slot 0**,
so every mapping sits one slot lower than the sketch assumed. That is not
cosmetic: §12.5 makes the layout part of the interface because the resolver
proves against it, and a proof computed for the documented slot would have
proven the wrong one.

```text
slot  0 +0  _owner          address                                        (Ownable)
slot  1 +0  _names          mapping(bytes32 => Name)
slot  2 +0  classHolder     mapping(bytes32 => address)
slot  3 +0  commitments     mapping(bytes32 => uint256)
slot  4 +0  reservedLabel   mapping(bytes32 => bool)
slot  5 +0  epochTakes      mapping(address => mapping(uint64 => uint16))
slot  6 +0  blockReveals    mapping(address => mapping(uint256 => uint16))
slot  7 +0  governor        address                              (Part X §93)
slot  8 +0  stateOf         mapping(bytes32 => NameState)        (Part X §93)
slot  9 +0  seizedAt        mapping(bytes32 => uint64)           (Part X §93)
slot 10 +0  _history        mapping(bytes32 => StateChange[])    (Part X §93)
slot 11 +0  levyPool        uint256
slot 12 +0  feePool         uint256
```

**RE-CONFIRMED (2026-08-16) after Part X §93's seizure machine landed, and it
MOVED TWO SLOTS.** `levyPool` was slot 7 and is now 11; `feePool` was 8 and is
now 12. The four governance mappings were appended *before* them because Solidity
lays storage out in declaration order and they were declared with the rest of the
mappings.

That is exactly the failure this subsection exists to catch, arriving a second
time: the layout is part of the interface because the resolver proves against it,
and any proof written for the previous slots now proves the wrong word. Nothing
had been deployed, so nothing broke — which is the only reason this is a note
rather than an incident.

**The rule that follows, and it is now load-bearing:** new storage is appended at
the END of the declaration list, never interleaved with existing declarations,
however much tidier the grouping looks. `stateOf` belongs next to `_names`
conceptually and must not be placed there.

Immutables occupy no storage and live in the code, which is why `TLD_NODE`,
`GRACE_PERIOD`, the price and levy parameters and the rest do not appear above.

The `Snapshot` fields, `registrationCount`, `resolvers` and `migrationTarget`
from the original sketch are **not in the deployed layout** because §12.6's
anchoring and §12.7's migration path are not implemented yet. They append at
**slot 13** and beyond; nothing may be inserted before slot 13 without
invalidating every proof written against the layout above.

```text
nameHash = keccak256( TLD_NODE ‖ keccak256(label) )
           TLD_NODE = keccak256( 0x00*32 ‖ keccak256("axon") )
base     = keccak256( nameHash ‖ uint256(0) )   == StorageSlotKey(nameHash, 0)

base+0   owner | expiresAt | version                       (packed)
base+1   domainKey
base+2   resolver
base+3   skeleton
base+4   registeredAt | keyValidFrom | mutatedAt | flags | reserved  (packed)

classHolder[s]    = keccak256( s            ‖ uint256(1) )
commitments[c]    = keccak256( c            ‖ uint256(2) )
resolvers[id]     = keccak256( id           ‖ uint256(3) )
reservedLabel[l]  = keccak256( keccak256(l) ‖ uint256(4) )
_snapshot.root                                       = slot 5
_snapshot.{blockNumber,timestamp,nameCount,sequence} = slot 6  (packed)
_snapshot.{poster,postedAt,challengeState}           = slot 7  (packed)
registrationCount = slot 8   feePool = slot 9   migrationTarget = slot 10
```

`keccak256(k ‖ uint256(position))` is exactly `ethproof.StorageSlotKey(k,
position)`, already exercised against mainnet at block 25,737,778; `base+n` is
exactly `ethproof.SlotAt(base, n)`. **§13 needs no new proof code to read this
contract.**

`TLD_NODE` is now per-namespace: `keccak256( 0x00*32 ‖ keccak256(namespace) )`,
supplied as an immutable at registrar deployment. It is the only line of §12.3
that the multi-namespace model changes.

#### The root registry layout, and the second proof it costs

Multi-namespace resolution is **two verified reads, not one**: prove the
namespace's registrar out of the root, then prove the name out of that registrar.

```solidity
contract TLDRegistry {
    mapping(bytes32 => Namespace) private _ns;          // slot 0
    mapping(bytes32 => bool)      public  ineligible;   // slot 1  (IANA + special-use)
    address public governor;                            // slot 2
    address public guardian;                            // slot 3
    uint64  public ianaSnapshotAt;                      // slot 3 (packed)
}
```

```text
nsBase = keccak256( keccak256(namespace) ‖ uint256(0) )

nsBase+0   registrar | registrarClass | status | recordSchema   (packed)
nsBase+1   steward | activatedAt | retiresAt                    (packed)
nsBase+2   charter
nsBase+3   bond
```

**The cost, stated so §13 can budget it.** Using the measured mainnet figures in
§12.1 — 3879 B account proof, ~2989 B per populated slot — a namespace read is
one account proof plus two slots, and the name read beneath it is one account
proof plus five. Roughly **8 slots and 2 account proofs, ≈ 32 KB and ~400–550 ms**
for a cold, fully verified resolution, against ≈ 18 KB and ~210–290 ms for the
single-registry design. That is the price of a governed multi-root and it is
charged **only on the slow path**: the namespace → registrar binding changes at
most once per governance action, so it is cached aggressively and pinned by the
snapshot (§12.6), and the common case remains zero chain reads. §13.3's SNAPSHOT
mode covers both levels in one Merkle proof and pays neither.

#### Packing, stated precisely because §13 will get it wrong otherwise

Solidity packs a slot from the **least significant** byte upward in declaration
order. Writing the word big-endian as `w[0..31]` with `w[0]` most significant, a
field of size `s` at LSB-offset `o` occupies `w[32-o-s .. 32-o-1]`.

| Slot | Field | Size | LSB offset | Bytes of the big-endian word |
|---|---|---|---|---|
| `base+0` | `owner` | 20 | 0 | `w[12..31]` |
| `base+0` | `expiresAt` | 8 | 20 | `w[4..11]` |
| `base+0` | `version` | 4 | 28 | `w[0..3]` |
| `base+4` | `registeredAt` | 8 | 0 | `w[24..31]` |
| `base+4` | `keyValidFrom` | 8 | 8 | `w[16..23]` |
| `base+4` | `mutatedAt` | 8 | 16 | `w[8..15]` |
| `base+4` | `flags` | 1 | 24 | `w[7]` |
| `base+4` | reserved MBZ | 7 | 25 | `w[0..6]` |
| slot 6 | `blockNumber`/`timestamp`/`nameCount`/`sequence` | 8/8/4/4 | 0/8/16/20 | `w[24..31]`/`w[16..23]`/`w[12..15]`/`w[8..11]` |
| slot 7 | `poster`/`postedAt`/`challengeState` | 20/8/4 | 0/20/28 | `w[12..31]`/`w[4..11]`/`w[0..3]` |

#### What a verified read costs

Derived from the **measured** figures in `doc/ethereum-data-layer.md` §6b —
account proof 3879 B, populated slot 2989 B, absent slot 160 B:

| Read | Slots | Derived proof size |
|---|---|---|
| Minimum useful (`owner`/`expiresAt`/`version` + `domainKey`) | `base+0`, `base+1` | 3879 + 2×2989 = **9857 B ≈ 9.6 KiB** |
| Full `Name` | `base+0..base+4` | 3879 + 5×2989 = **18 824 B ≈ 18.4 KiB** |
| Proof that a name is unregistered | `base+0` absent | 3879 + 160 = **4039 B ≈ 3.9 KiB** |
| Snapshot header | slots 5,6,7 | 3879 + 3×2989 = **12 846 B ≈ 12.5 KiB** |

The per-slot figure is representative *at scale*: WETH's trie depth is ≈ 5.6, and
1,000,000 names × 5 slots = 5,000,000 entries gives depth ≈ log₁₆(5×10⁶) ≈ 5.6.
Below a million names the registry's proofs are **shallower and smaller**. Above
it, deeper. Re-measure after deployment; do not publish these as measurements.

---

### 12.6 The `RegistrySnapshot` anchor (R7) `[NEEDS RESEARCH]`

A Merkle root over the name → `DomainIdentity` map, committed on chain and
replicated in the DHT, so a resolver can answer with **no RPC access at all.**

#### The tree

A **sparse binary Merkle tree of depth 256**, keyed by `nameHash`, with
precomputed empty-subtree hashes per level.

```text
leaf_body  = domainKey(32) ‖ expiresAt(8) ‖ version(4) ‖ flags(1)     = 45 B
leaf       = SHA-256( "AXON-snap-leaf-v1" ‖ 0x00 ‖ nameHash ‖ leaf_body )
node       = SHA-256( "AXON-snap-node-v1" ‖ 0x00 ‖ left ‖ right )
empty(256) = SHA-256( "AXON-snap-empty-v1" ‖ 0x00 )
empty(l)   = SHA-256( "AXON-snap-node-v1" ‖ 0x00 ‖ empty(l+1) ‖ empty(l+1) )
```

- **SHA-256, not keccak** — §2 fixes SHA-256 for protocol hashing. The root is
  *stored* on chain but computed off chain, and recomputed on chain only during a
  challenge; the `sha256` precompile at 60 + 12/word makes a 256-level walk
  roughly 256 × 72 ≈ **18 400 gas**, affordable for the only time the contract
  hashes.
- **Distinct leaf and node prefixes** close the classic Merkle second-preimage
  bug where an interior node is presented as a leaf.
- **Sparse, not sorted-list**, because it gives **proofs of absence with the same
  shape as proofs of inclusion** — the leaf at `nameHash` is the empty hash. A
  resolver must be able to prove "this name is not registered", and a sorted-list
  tree needs a range proof and a total ordering to do it.

#### Proof format

```text
off  size   field
  0     4   magic "AXNS"
  4     1   version = 1
  5     1   kind: 0 inclusion, 1 absence
  6     2   sibling_count  S
  8    32   snapshot_root
 40    32   name_hash
 72     8   anchor_block_number
 80     8   anchor_block_timestamp
 88    32   present_bitmap  bit i (MSB-first) set = level i has a non-default
                            sibling; cleared bits use empty(i)
120    45   leaf_body       all-zero when kind = 1
165  32·S   siblings        root-ward; index 0 nearest the root

size at S = 20 (~10^6 names):  165 + 640 = 805 bytes
```

**805 bytes against 9857 bytes** for the equivalent verified `eth_getProof` read
— roughly 12× smaller, with no RPC in the path. That ratio is the whole argument
for R7.

#### The anchorer, and why it is not a trusted role

`commitSnapshot` is **permissionless and bonded**, reusing the shape of
`EpochManager`/`DisputeManager`/`StakeVault`:

```text
1. Anyone posts a root for a FINALIZED block at most 64 blocks behind head,
   with ANCHOR_BOND attached.
2. A 24 h challenge window opens.
3. challengeSnapshot(nameHash, siblings, bitmap):
     reject unless names[nameHash].mutatedAt <= snapshot.blockNumber
     recompute the leaf FROM CONTRACT STORAGE, walk the supplied path
     equal root    -> challenge fails, challenger pays
     differing root-> slash the poster, pay the challenger, invalidate the
                      snapshot, revert to the previous finalized one
4. finalizeSnapshot(sequence) after the window; poster reclaims the bond and
   takes a reward from feePool.
```

The contract can do this because **it holds ground truth in the very next slot**:
it recomputes one leaf and walks one path, not the whole tree. A permissioned
anchorer could lie to any resolver that cannot cross-check — and cross-checking
needs the RPC the snapshot exists to avoid. A bonded anchorer with a cheap sound
fraud proof reduces the anchorer's power to **stalling** (a liveness failure a
resolver sees as a stale snapshot) rather than **lying**.

**Residual:** a name mutated between the anchor block and the end of the window
is not challengeable, because legitimate and malicious divergence are
indistinguishable to the contract. That set is exactly the set a resolver already
treats as possibly-stale. Bounded, not closed — and the whole anchorer design is
`[NEEDS RESEARCH]` until adversarially tested in the style of
`recall_lying_holder_test.go`.

#### Cadence and cost

```text
policy: post when ( >= 1 h elapsed AND >= 1 mutation ) OR ( >= 24 h elapsed )

gas per commitSnapshot (ESTIMATED from opcode costs, NOT measured):
  base tx 21 000 | 3 × SSTORE non-zero->non-zero (5 000 + 2 100 cold) = 21 300
  calldata ~72 B ~1 150 | event ~2 000                  total ~45 000 gas

hourly  24 × 45 000 = 1.08 M gas/day  ≈ 394 M gas/year
daily        45 000 = 45 k gas/day    ≈  16 M gas/year
```

Hourly is the recommendation; the mutation predicate means an idle namespace
costs one daily heartbeat rather than 24. The anchorer is reimbursed from
`feePool`, so registrants bear the cost, not volunteers. **These are estimates
from opcode prices. Run `hardhat-gas-reporter` before fixing a cadence.**

#### Replication in the DHT

The tree is not published; the **leaf set** is, because the tree is recomputable
from it and a holder of the leaves can generate any proof.

```text
object    leaves sorted ascending by nameHash: nameHash(32) ‖ leaf_body(45)
          = 77 B per name.  At 10^6 names: 77 MB = 301 chunks of 256 KiB (§5)
DHT key   K = SHA-256( "AXON-snapshot-v1" ‖ 0x00 ‖ chain_id ‖
                       registry_address ‖ uint32 sequence )
delta     a per-sequence delta object of changed leaves only, same encoding;
          typically kilobytes. A resolver holding sequence n-1 fetches the
          delta and verifies the result against the on-chain root.
placement the existing store: r = 8 across distinct /24, /48 and ASN (§5),
          via the existing placement engine
integrity content-addressed (BLAKE3/Bao, §2), and the recomputed root MUST
          equal the on-chain root before use. A leaf set that does not
          reproduce the root is discarded, not quarantined — the rule
          internal/gateway/snapshot.go already applies to site snapshots
```

#### Freshness bound

Worst case for a **transfer, rotation or revocation** to reach a snapshot-only
resolver:

```text
  inclusion in a block                  ~12 s
+ finalisation (2 epochs)               ~12 min 48 s
+ snapshot cadence                       60 min
+ anchorer post + DHT propagation       <= 5 min   (target)
+ resolver snapshot poll interval       <= 15 min
──────────────────────────────────────────────────
  worst case  ~1 h 33 min        typical  ~35 min
```

Rules §13 must implement: report `snapshot.timestamp` and the derived age with
**every** answer (an answer without a stated age is a lie about its own
provenance); `max_snapshot_age` default **6 h**, past which answers carry an
explicit `STALE` flag the caller must handle; **hard refusal at 48 h**, returning
an error rather than an answer, with the caller's remedy being §11.9; and an
**escape hatch** — one verified `eth_getProof` read (§12.5, ~9.6 KiB) for a
disputed name or a caller demanding current state, which is R7's slow path and
must remain available even though it is not the default. Expiry is exempt from
all of it, because `expiresAt` is in the leaf.

---

### 12.7 What must NEVER go on chain

> **Rule C-1. The chain learns names and owners. It never learns users,
> endpoints, content, or lookups.**

The chain is public, permanent, globally replicated and un-deletable, and §7
assumes an adversary who "can observe the blockchain completely". Anything
written there is written for everyone, forever, including for an adversary who
does not exist yet.

| Never on chain | Why | What goes instead |
|---|---|---|
| IP addresses, ports, hostnames, any reachable endpoint of any node | Permanent global deanonymisation of the operator, and a takedown list assembled for free | Nothing. `NodeRegistry.sol` already does this correctly with `endpointCommitment = hash(endpoint ‖ nodeSecret ‖ epoch)` — follow that precedent |
| `ServiceIdentity` public keys | Links name → service → descriptor and makes every service enumerable from one `eth_getLogs` | Only `DomainIdentity` on chain; `ServiceIdentity` in a signed `SVC` record (§11.6) |
| `RoutingIdentity`, `KadID`, guard sets, tunnel membership | Epoch-scoped by design; on chain means permanent, which defeats the rotation | L3 descriptors |
| Content hashes, CIDs, manifests | Permanence plus a global canonical hash-keyed takedown index — the re-centralisation R5 refuses | `CNT` records off chain |
| Any per-resolution or per-lookup event | A public query log with timestamps and payers | Nothing. Resolution never touches the chain (R7) |
| Links between `PaymentIdentity` and `NodeIdentity`/`RoutingIdentity` | R11 — a settlement transaction identifying a relay's payer is a deanonymisation channel | Blind-signed tokens, aggregated off the critical path, settled through the existing PoF epoch machinery |
| Contact details, abuse addresses, operator names, any PII | Irrevocable. A `META` record can be withdrawn; a transaction cannot | `META` off chain, and discouraged even there |
| Blocklists, takedown lists, "verified" flags | R5 refuses a global blocklist as re-centralisation; on chain it becomes canonical and a resolver's refusal to honour it looks like misbehaviour | Local operator policy only |
| Private keys, key shares, recovery material, encrypted-but-recoverable blobs | Stated because "encrypted" is not a defence against a decade of cryptanalysis plus a permanent record | Never |
| Full record sets, TXT metadata, service descriptors | Cost and permanence, and it would make the chain the resolver — the architecture R7 exists to prevent | DHT, signed by `DomainIdentity` |

What **is** on chain is exactly §12.5's five slots. A reviewer's test for any
proposed registry change: *if this field were on a billboard for twenty years,
who is harmed?* If the answer is anyone but the name's owner, it does not go on
chain.

---

### 12.8 Decisions

| Decision | Problem it solves | Derived from Tor / I2P / Freenet | What we changed | Alternatives rejected | New vulnerability introduced |
|---|---|---|---|---|---|
| Registry on Ethereum L1 mainnet | Global uniqueness of names without a registry operator | **None.** None of the three has global name ownership — I2P uses per-router addressbooks, Tor raw keys, Freenet signed subspaces. Nearest prior art is blockchain naming generally | The chain is authoritative for ownership only, and off the resolution path entirely | Optimistic L2 (7-day trust-minimised finality on a transfer); another EVM L1 (a second consensus verifier, less security); an app-chain (a directory authority with extra steps, refused under R14) | A hard dependency on one chain's liveness for acquisition and transfer, and on its fee market for the cost of both |
| Resolve from `RegistrySnapshot`, never from RPC | R7: a chain outage or RPC censorship must not take the namespace down | Freenet's "everything is a signed object you verify locally" instinct | The root is chain-anchored, so a locally-held snapshot is verifiable rather than merely cached | Direct `eth_getProof` per resolution (9.6 KiB and an RPC round trip per name, from an RPC that can refuse); trusting an RPC (refused by `doc/trust-anchor.md` §1) | Every answer is up to ~1 h 33 min stale for transfers, rotations and revocations |
| Sparse binary Merkle tree, SHA-256, domain-separated | Provable absence with the same shape as presence; small proofs | — | SHA-256 rather than keccak so the overlay carries one hash; leaf/node prefixes close the second-preimage case | Ethereum MPT (building an off-chain MPT to prove against a root we control, for no benefit); sorted-list Merkle (absence needs a range proof) | 805-byte proofs are cheap enough to serve without rate limiting, which is a bandwidth-amplification surface |
| Bonded permissionless anchorer + on-chain fraud proof | A permissioned anchorer can lie to any resolver that cannot cross-check — and cross-checking needs the RPC the snapshot avoids | — (reuses `StakeVault`/`DisputeManager` from this repo) | The contract holds ground truth, so the fraud proof is one leaf and one path (~18 400 gas), not a recomputation | Permissioned anchorer (a trusted third party in the resolution path); on-chain incremental SMT update per registration (~300–500 k gas per name) | Names mutated inside the challenge window are unchallengeable. Bounded, not closed |
| Commit–reveal + `registerWithSig` meta-tx | Front-running a revealed registration; and R6's payer/name timing link | — (lifted from `NodeRegistry.registerWithSig`) | Two purposes for one mechanism; the owner is recovered from the signature so a relayer cannot pay itself | Plain `register` (mempool front-running); auctions (a public bidding record, worse under R6) | Does not stop bulk speculative registration and does not make ownership anonymous — the funding graph is a residual risk we do not solve |
| Transfer atomically zeroes `domainKey` | A seller who keeps the signing key controls what the buyer's name says | — | — | Transfer preserving the key (silently broken); a required key handover (unverifiable on chain) | A transferred name is dark until the buyer calls `setDomainKey` — correct, and an availability gap |
| 90-day grace + 21-day decaying premium | Accidental expiry is unrecoverable; expiry-sniping is a race won by whoever runs a bot | — | Grace is long because there is no support desk to appeal to | Immediate release (one missed renewal is permanent loss); permanent ownership (dead names accumulate with no reclamation) | A 111-day window in which a name resolves for nobody, visible to users as an outage |
| Write-once resolver ids | A mutable pointer shared by many names is a takeover of an arbitrary fraction of the namespace | — | Append-only mapping, revert on rebind | Mutable resolver addresses (convenient, and a single-point repoint) | An id bound to a buggy implementation is bound permanently; the remedy is a new id and a per-name update |
| Five packed slots per name | Proof size is the read cost, and every slot is ~2989 B of proof | — | The layout is public interface, not implementation detail | One field per slot (unambiguous, ~2× the proof size); an ABI getter (needs a trusted `eth_call`, not provable) | §13 must implement the packing arithmetic correctly; a byte-offset error yields a plausible wrong value rather than a failure |
| Fixed length-based pricing in ETH | Squatting rent, and denomination without an oracle | — | No auction, no oracle, no token dependency | ANON denomination (circular); an ETH/USD oracle (a new trusted input on the registration path); universal auctions (public bidding, high friction) | A fixed ETH price is a floating USD price, so the anti-squatting rent drifts with the market |

---

### 12.9 What this section does NOT establish

- **No gas figure here is measured.** The ~45 000 gas snapshot commit, the
  ~18 400 gas fraud proof, and the registration cost come from opcode prices.
  `hardhat-gas-reporter` is in the toolchain; run it.
- **The proof sizes are derived, not measured.** They come from the WETH-based
  upper bound in `doc/ethereum-data-layer.md` §6b, which that document is
  explicit is conservative. Re-measure with a real `eth_getProof` against a
  deployed `AxonRegistry`, exactly as P12-2 did for `ChannelManagerV2`.
- **The storage layout is design intent, not compiler output.** `solc
  --storage-layout` is the authority, and §13 must be written against the
  compiler's answer.
- **The anchorer's incentive analysis is incomplete.** Bond size, challenge
  reward, the case where nobody bothers to challenge because the namespace is
  small, and the case where anchorer and challenger are the same party are all
  unmodelled. `[NEEDS RESEARCH]`.
- **Anonymous ownership is not achieved and is not claimed.** Commit–reveal and
  meta-transactions separate payer from owner and keep the wallet off the
  overlay; a complete chain observer still walks a funding graph. Residual,
  documented, unsolved.
- **Squatting, 1–2 character labels, and the absence of any dispute process are
  `[UNSOLVED]`** — consequences of having no authority. Naming them is the most
  this section can honestly do.
- **The migration story is half-written.** `freeze()` and `migrationTarget` make
  the mechanical half possible; getting every resolver to switch authorities
  without that switch becoming a takeover vector is not designed.

---

> **Objection to Constitution §5 (parameter table):** the table fixes descriptor
> lifetime at 3 h with hourly republish, which §11.7 uses to cap `SVC` TTL at
> 3600 s. The coupling is correct, but it means a future change to descriptor
> lifetime silently changes the naming layer's cache behaviour. The parameter
> table should carry the SVC cap explicitly rather than leaving it derived.

> **Objection to Constitution §6 R7:** R7 says a resolver "may operate on a stale
> snapshot within a declared freshness bound and must say so", but does not fix
> *who* declares the bound. §12.6 fixes it at 6 h soft / 48 h hard on the
> resolver's own authority. If two resolvers choose different bounds, two users
> get different answers about whether a name is current — a mild form of the
> epistemic-partition problem R14 names for the relay set. The bound should be a
> Constitution parameter, not a per-resolver choice.
