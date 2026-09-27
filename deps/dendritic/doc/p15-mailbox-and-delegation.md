# P15 — Mailbox mode, and whether delegated signing can be enforced

**Status: DESIGN INVESTIGATION. No production code written. No contract modified.**

---

## 0. The answer to the primary question

**ChannelManagerV2 cannot enforce scoped delegation. Not partially — not at all.**

```
$ grep -ci "delegate\|operator\|authoriz\|approve\|permit" ChannelManagerV2.sol
0
```

The whole of the contract's authorization model is two lines:

```solidity
function _requireSigned(Channel storage ch, bytes32 digest, bytes calldata sigA, bytes calldata sigB) {
    if (_recover(digest, sigA) != ch.partyA) revert BadSignature();
    if (_recover(digest, sigB) != ch.partyB) revert BadSignature();
}
```

The **party address is the authority**. There is no second address, no signer
registry, no expiry, no cap, no operation mask. Any restriction on a delegated
signer would exist only in application code, on the machine we are assuming may
be compromised — which is the definition of a security boundary that isn't one.

### And there is a worse fact underneath it

```solidity
// checkpoint
if (a.withdrawA > 0) token.safeTransfer(ch.partyA, a.withdrawA);
if (a.withdrawB > 0) token.safeTransfer(ch.partyB, a.withdrawB);
// settle → _payout(ch) — same addresses
```

**Value is always paid to the party address, which is the signing address.**

So a *distinct* delegated key is not a key that *could* steal tips. It is the
on-chain **payee** for them. Money lands in the volunteer's address by default
and only reaches the recipient if the volunteer forwards it. That is custody by
construction, not custody by risk — and it is the opposite of what "delegated
signer" is meant to imply.

The two available shapes of Mode B on today's contract:

| shape | what the volunteer gets | max loss |
|---|---|---|
| recipient's **primary wallet key** | signing power over *everything that wallet holds* | **the entire wallet**, not just tips — ERC-20 transfers need no channel |
| a **distinct delegated key** | it is the party, so it is the payee | **all undrawn tips, by default rather than by attack** |

There is no third shape. Both are refused by the brief's own constraints.

---

## 1. Existing architecture findings

### What the digest binds

```solidity
keccak256(abi.encode(block.chainid, address(this), id, nonce,
                     balanceA, balanceB, root, withdrawA, withdrawB))
```

Bound: chain, contract, channel, nonce, both balances, HTLC root, both withdrawals.
**Not bound:** operation kind, expiry, signer identity, delegation, amount cap,
volunteer identity.

`KindPay` / `KindCheckpoint` / `KindLockAdd` are **off-chain concepts only**
(`transition.go`); the contract never sees a kind. `closeCooperative`,
`checkpoint`, `challenge` and `closeUnilateral` all verify through the *same*
`stateDigest`, differing only in which arguments they pass. A key that can sign
a pay state can sign a checkpoint or a close at a higher nonce.

### The one genuine limit that does exist

Every state-admitting path requires **both** signatures, including
`closeUnilateral` (line 382) — "unilateral" means one party may *submit*, not
that one party may *author*. `closeUnilateral` and `settle` additionally require
`msg.sender` to be a party.

So a compromised key cannot invent value: it can only realise a state the
counterparty already co-signed. **Maximum loss is the recipient-side balance of
already-co-signed states in channels using that key** — the undrawn tips, and
nothing beyond them. That bound is real and worth stating precisely, because it
is the only thing standing between "bounded" and "unbounded".

### Everything else, confirmed by inspection

| fact | source |
|---|---|
| One node = one identity = one signer; no multi-tenancy, no remote signer | `NewCoordinator(..., self Address, sign StateSigner)`; no `RemoteSign\|DelegatedSign\|SignerURL` in tree |
| `/scpp/v1` unauthenticated **by design**, cross-origin, authorised by in-message signature | `webpeer.go` |
| `/v1/*` bearer-token, operator-only, must never reach a browser | `api.go`, `webpeer.go` header |
| Recipient console belongs to the **node**, with a password when non-loopback | `internal/ui`, `SetAccessControl` |
| Router = HTLC hops, "CANNOT KEEP WHAT IT FORWARDS" | `hub.go` |
| Bounded hot keys already accepted for routers; channel key ≠ payout key | `keys.go` |
| Volunteer can hold a real HTTPS cert for its own hostname | `gateway/acme.go` |
| Capability bitmask + **unused `endpointCommitment`** | `NodeRegistry.sol` |
| Signed self-registration with ed25519 p2p proof, versioned prefix, wallet-bound to stop replay | `PofRegistration.py` |
| **Channel stack not mounted in the node binary** (P15 prior finding, still true) | `grep WebPeer{ / NewAPI(` → nothing outside tests |

---

## 2–5. The 20 questions, answered

| # | question | answer |
|---|---|---|
| 1 | What does the contract verify? | recovered signer == `partyA`/`partyB`; conservation; status; nonce monotonicity; `msg.sender` is a party on unilateral paths |
| 2 | What does the digest bind? | chainid, contract, id, nonce, balanceA/B, htlcRoot, withdrawA/B — **nothing about the signer** |
| 3 | Which party is each signature? | `sigA`→`partyA`, `sigB`→`partyB`, fixed at `openChannel` by address sort |
| 4 | Distinguish wallet from delegate? | **NO** |
| 5 | Scope delegation to one channel? | Only *by construction* (use a distinct key), never *by enforcement* — and that key becomes the payee |
| 6 | Scope to only `KindPay`? | **NO** — kind is off-chain |
| 7 | Scope to only `KindCheckpoint`? | **NO** |
| 8 | Contract-enforced expiry? | **NO** |
| 9 | Contract-enforced amount limit? | **NO** (only conservation vs deposits) |
| 10 | On-chain revocation? | **NO** — the only revocation is closing the channel |
| 11 | Create a state the recipient never authorized? | **YES**, subject to the counterparty co-signing |
| 12 | Close a channel? | **YES** |
| 13 | Checkpoint? | **YES** |
| 14 | Alter collateral? | Cannot add (deposit pulls from `msg.sender`); **can reduce** via checkpoint/close |
| 15 | Move the entire remaining balance? | Bounded to already-co-signed recipient-side balance; cannot invent |
| 16 | Volunteer compromised? | see table below |
| 17 | Volunteer disappears? | Mode A: nothing lost, change a URL. Mode B: undrawn tips stranded at an address you do not control |
| 18 | Recipient changes volunteer? | Mode A: new authorization, old expires. Mode B: **custody transfer or re-open every channel** |
| 19 | Two volunteers at once? | **Must be refused** — two mailboxes accepting proposals for one address invites two signed states at one nonce (invariant I4) |
| 20 | Limit a delegate to one volunteer? | Only by giving that volunteer a unique key — i.e. option (C), which is custodial |

### Maximum financial loss under compromise

| option | volunteer holds | max loss |
|---|---|---|
| **A — mailbox** | nothing signable | **zero from key compromise**; can censor and can observe metadata |
| **B — primary wallet key** | the recipient's wallet | **everything that wallet holds**, channels or not |
| **C — distinct delegated key** | the party key = the payee | **all undrawn tips**, received by default |
| **D — operation-scoped key** | — | **not constructible** on this contract |
| **E — router-style bounded key** (`keys.go`) | a channel key bounded by `TotalCommittedMax` | works for a router spending *its own* collateral; does not transfer to holding a *third party's* receipts |

**D does not exist**, and that is the finding this phase was asked to produce.
It cannot be built without a contract change.

---

## 6–8. Would a contract change help, and would a key hierarchy be enough?

**A key hierarchy alone is NOT sufficient.** Any key that can produce an accepted
signature is the party, and the party is the payee. Derivation changes who
*knows* the key, never what the key *can do*.

**A contract change could work, and the shape is small.** The missing separation
is between *who may sign* and *who gets paid*:

```
delegates[party] → { address signer; uint64 expiry; uint256 cap; uint8 opMask }
_requireSigned: accept party OR a live delegate
_payout / safeTransfer: keep paying the PARTY, never the delegate
```

That single change makes a delegate powerless to redirect funds and gives
expiry, cap, op-scoping and on-chain revocation. **I am not proposing to make
it.** ChannelManagerV2 is deployed and gated; this is recorded as what *would* be
required, for your decision (§12).

---

## 9–14. Mailbox design (Mode A) — the safe baseline

```
contributor browser ──POST /scpp/v1──► volunteer ──queue by recipient address──┐
                                                                                │
recipient browser ──authenticated, same-origin──► volunteer ◄───────────────────┘
        signs with the recipient's OWN wallet
                    │
                    └──reply frame──► volunteer ──► contributor
```

**Authorization.** The recipient signs a versioned statement — modelled exactly on
`PofRegistration.proof_message`, which already solves "the exact bytes a key
signs, including everything a replay could otherwise repoint" — binding
{recipient address, volunteer node id, endpoint, validity window, nonce}. The
volunteer serves an address only on a valid, unexpired authorization, so it
cannot claim arbitrary recipients. **One active authorization at a time** (Q19).

**Discovery.** `Profile.channel_endpoint` first, because it exists and the tipper
is already on the profile page. `endpointCommitment` in `NodeRegistry` is the
path that removes Syndichan from the loop later; it is unused today and needs a
`CAP_CHANNEL`-style bit that does not yet exist.

**Replacement/revocation.** State is *reconstructable*, never transferable —
`Pool.View()` is a pure function of co-signed states plus the chain, and
`pool.go` says "delete the view and nothing is lost". Replacement is a new
authorization; revocation is expiry plus refusing the old one.

**Multi-recipient.** One volunteer, many recipients, keyed by authorization. No
cross-talk is possible because it holds no key for any of them; the isolation
test is that a frame for recipient X is never offered to recipient Y's session.

### Privacy — stated honestly

| Actor | Must know | Must NOT learn |
|---|---|---|
| Syndichan | pooling is on; recipient's public wallet; an endpoint pointer | balances, aggregates, channel ids, contributor↔recipient pairs, amounts, tx hashes, any per-payment event |
| Volunteer | that frames exist for an authorized address; their size and timing; **in practice, both parties of each channel it carries** | any recipient private key (Mode A) |
| Recipient | everything about their own channels | other recipients' anything |
| Contributor | recipient wallet, own channel, own payments | recipient's other channels, the aggregate, other contributors |
| Browser | endpoint + its own party's state | unrelated financial state |
| Ethereum | parties, deposits, withdrawals at checkpoint | off-chain intermediate states, mailbox metadata |

**A volunteer is not anonymous and must not be described as such.** A bilateral
frame names a channel and a channel names both parties, so a mailbox sees who
paid whom and how much. `hub.go` + `onion.go` are the only real mitigation —
an onion-wrapped terminal hop — and are **explicitly out of scope here**,
recorded as a future privacy layer.

---

## 15. Failure semantics

Five distinguishable states, five messages — none may collapse into another:

| condition | when | message shape |
|---|---|---|
| **recipient unavailable** | no countersignature yet | "waiting for the recipient" — not a failure, not a balance change |
| **contributor offline** | dial failed, nothing written | already built (`ErrPeerUnreachable`, 503) |
| **no channel** | none exists | "set up tipping" |
| **rejected** | peer said no, with a code | refused |
| **UNKNOWN** | transport failed **after** signing | "could not be determined — do not retry yet" |

The boundary: **before** the recipient signs, a transport failure is
*unavailable*; **after**, it is UNKNOWN. That is the same dial-vs-post
distinction already implemented and tested for the contributor side.

A recipient being offline must never render as a zero pooled balance, and
queued-but-unsigned proposals must never count toward `Withdrawable`.

---

## 16. Recommended V0

1. **Mount the channel stack in the node binary** — `/scpp/v1` public, `/v1/*` loopback. Nothing else is possible until this exists.
2. **Move the recipient dashboard into `internal/ui`** (the P7 seam), same-origin, password-gated when non-loopback. This deletes the cross-origin problem instead of punching through it, and retires the harness proxy.
3. **Signed recipient→volunteer authorization**, `PofRegistration`-shaped, one active at a time.
4. **Mailbox queue + the five failure states.**

**Mode B is not implemented.** Per §0 it cannot be given the properties the brief
requires, so the threat model's conclusion is that it should not be built on this
contract at all.

## 17. Files that would change

`cmd/syndichan-node/main.go` (mount) · `internal/ui/receiving*.go` (dashboard) ·
a new mailbox module in `internal/channel` · `backend/model/Profile.py` (endpoint
pointer only) · `NodeRegistry` capability bit (registry, **not** ChannelManagerV2).

**Must not change:** ChannelManagerV2 · `challengePeriod` · the deployment gate ·
`tip-channel.js` · `tip-flow.js` · `Pool.View()` accounting · `/scpp/v1` staying
unauthenticated · `/v1/*` staying token-authed and never CORS-enabled.

## 18. Tests required

- The volunteer **cannot** produce a signature for an address it serves — the load-bearing claim of Mode A.
- A volunteer serving an unauthorized address is refused; a stale authorization is refused; two simultaneous authorizations are refused.
- Two recipients on one volunteer: no cross-talk.
- Volunteer restart persists no financial state; no payment history is written.
- Queued-but-unsigned proposals never count toward `Withdrawable`.
- All five failure states render distinctly.
- `Pool.View()` after endpoint change equals a fresh reconstruction.
- Mutation: delete the authorization check → node serves an unauthorized address → test fails.
- Real devnet: contributor → volunteer → recipient browser signature → ChannelManagerV2 accepts → `Pool.View()` reflects it.

## 19. Deployment gate

**No gate term is invented or changed.** For the record: the gate assumes a
payment node exists in production, and per the prior finding none does — the
channel stack is not mounted in any binary. A volunteer-node architecture does
not relax that assumption; it changes *whose* machine satisfies it. **The gate
cannot be honestly evaluated until V0 exists.** Interpretation is yours.

## 20. Decisions needing your approval

1. **Mode B is refused as specified.** It cannot be scoped on this contract, and a distinct delegated key makes the volunteer the on-chain payee. Do you accept mailbox-only for P15?
2. **If always-available receipt is required**, the only honest routes are (a) a ChannelManagerV2 change adding a delegate registry that separates signer from payee — deployed, gated, re-audited; or (b) the existing on-chain transfer path for absent recipients. Which?
3. **Discovery via `Profile.channel_endpoint` or `endpointCommitment`/DHT?** The latter needs a new capability bit.
4. **Is onion-wrapping the terminal hop in P15 scope?** I recommend no; without it a volunteer is a metadata chokepoint and we should say so in the UI.
5. **Does F1 (nothing mounted) change how you read the P12 gate?**

---

**Pooled tipping is NOT production live.** Mode A is designed and buildable.
Mode B, as specified, is not constructible on the deployed contract.
