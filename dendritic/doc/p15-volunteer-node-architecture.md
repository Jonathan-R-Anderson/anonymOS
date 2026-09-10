# P15 — Volunteer-node architecture for pooled tipping

**Status: DESIGN INVESTIGATION. No production code written.**

> The question is not "can pooled tipping work" — it is devnet-validated. It is
> "how does an ordinary user receive pooled tips through the volunteer PoF
> network without running a node and without anyone becoming a custodian."

---

## 0. The three findings that decide everything

**F1 — The channel stack is not mounted in the node binary.**
`internal/channel` is imported by exactly one non-test file in the tree:
`internal/ui/receiving_adapter.go`. Neither `WebPeer` (`/scpp/v1`) nor
`channel.NewAPI` (`/v1/*`) is constructed anywhere in `cmd/syndichan-node`.

```
$ grep -rn "WebPeer{" --include=*.go .   | grep -v _test   →  (nothing)
$ grep -rn "NewAPI("  --include=*.go .   | grep -v _test   →  only its own definition
```

So **no running node serves payment channels today.** `Profile.channel_endpoint`
is a field no volunteer can currently satisfy. This is a larger blocker than
CORS and it is the real reason the browser test had to talk to a test-only
process.

**F2 — "Add CORS to the node" is not a small fix, it is an authority leak.**
`webpeer.go` already states the rule this phase is rediscovering:

> The operator API in api.go is bearer-token authed because it acts on the
> operator's behalf: it can move this node's money and change its payout policy.
> This endpoint is the opposite — it is how STRANGERS talk to this node, and a
> tipper has no operator token and must never be given one. […] Mounting this on
> the authed mux would be a serious mistake in both directions: tippers locked
> out, and a token handed to a web page.

I built the P15 dashboard against `/v1/*` — the operator surface — and then found
it unreachable cross-origin. That is the design working, not failing.

**F3 — The contributor side is already solved and already remote.**
`/scpp/v1` (P8) is unauthenticated *by design*, handles cross-origin preflight,
and authorises by **the signature inside the message**. A tipper needs no node,
no account on any node, and no token. Questions 4–6 of the brief are already
answered for the *contributor*. The open problem is exclusively the **recipient**.

---

## 1. Current architecture findings

### The two node surfaces, and who may reach them

| surface | auth | audience | cross-origin | status |
|---|---|---|---|---|
| `/scpp/v1` (`webpeer.go`) | **signature in message** | strangers (tippers) | yes, by design | built, **not mounted** |
| `/v1/*` (`api.go`) | bearer token | the operator only | no, by design | built, **not mounted** |
| node console (`internal/ui`) | password when non-loopback | the operator | n/a, same origin | **mounted** in `main.go` |

`ui.Server.SetAccessControl(listen, user, pass)` already implements
"demand a password when I am reachable from the network", and `main.go` wires it
*next to the server it belongs to* so the handler can never exist unaware of its
own exposure. **P7 already established that the recipient's control panel is
served BY THE NODE**, not by Syndichan.

That is the pattern my P15 dashboard broke by living on the Syndichan settings
page. See §8.

### Custody is decided by one function signature

```go
NewCoordinator(store *Store, chain ChainReader, chainID *big.Int,
               contract, self Address, sign StateSigner)
```

One node, **one identity, one signer**. There is no multi-tenancy and there is
no remote or delegated signer anywhere in the tree (`grep RemoteSign\|DelegatedSign\|SignerURL` → nothing).

A channel state is authorised by an ECDSA signature that must recover to the
party address the chain recorded. So whoever can produce that signature can
co-sign a `checkpoint` or `closeCooperative` with any willing counterparty.
**Holding the recipient's channel key IS custody of the recipient's channel
balance.** There is no arrangement of HTTP endpoints that changes this.

### The non-custodial routing model already exists

`hub.go` — and it states the distinction this phase must not lose:

> **ROUTER, NOT WALLET** […] As a CUSTODIAN: the reader's deposit sits in a
> hub-controlled balance and the hub credits recipients from it. […] As a ROUTER
> (this): every hop is locked on a condition […] The hub **CANNOT KEEP WHAT IT
> FORWARDS**, because it never holds an unlocked claim on it.

With `multipath.go`, `onion.go`, `blinded.go` and the P13 tests, the machinery
for a volunteer to carry value it cannot steal is built and tested.

### Bounded hot keys are already an accepted pattern

`keys.go`:

> A routing node must sign UNATTENDED. […] the channel key is DERIVED from the
> node's seed under its own domain, and is deliberately not the payout key. One
> leaked hot key then costs what is committed to open channels — bounded by
> `RouterConfig.TotalCommittedMax` — and not the address the operator's earnings
> accumulate in.

This matters: the project has already decided that *bounded* exposure of a
channel key is acceptable for a router. Whether that extends to a **third
party's** tips is a different question and is the one needing approval (§16).

### Reachability and discovery infrastructure that exists

| capability | where | state |
|---|---|---|
| Volunteer gets a real HTTPS cert for its own hostname | `gateway/acme.go` (autocert) | built, mounted |
| On-chain node registry with capability bitmask | `NodeRegistry.sol` — `CAP_DHT/GATEWAY/STORAGE/LOADBALANCE/DOCKER_WORKER/DOCKER_CONTROLLER/WITNESS` | deployed |
| **`endpointCommitment` (bytes32) per node** | `NodeRegistry.sol`, `PofRegistration` | exists, **unused for routing** |
| Self-service registration with ed25519 p2p-key proof | `PofRegistration.py` | built |
| Live node inventory + liveness | `StorageNode`, `PeerLiveness`, `active_storage_nodes()` | built |
| `payment_channel` flag on a node | `StorageNode.payment_channel` | **telemetry only — nothing routes on it** |
| Recipient→endpoint binding | `Profile.channel_endpoint` (https-only) | built, unsatisfiable (F1) |
| I2P destination per node | `StorageNode.i2p_destination` | built |

There is **no** `CAP_CHANNEL` / `CAP_TIPPING` capability bit. Adding one is a
registry-level change, not a contract change to ChannelManagerV2.

---

## 2. The constraint the brief does not yet account for

**In a bilateral channel, the recipient must sign to receive.**

`KindPay` is a two-message exchange: the payer proposes a state, and the
*recipient's key* countersigns it. There is no "receive while absent" primitive
in this codebase — `escrow.go` is selective dispute disclosure, not offline
receipt; HTLCs shift *when* value settles, not *who signs*.

Therefore "the recipient does not run a node" resolves to exactly one of:

- **(a)** the recipient's key is online in *something they control* (a browser tab), or
- **(b)** the recipient's key is online in *something a volunteer controls* → custody, or
- **(c)** the tip does not use a channel at all.

(c) already exists and already works: `Profile.channel_endpoint` empty means
"awards keep arriving as ordinary transfers", per the model's own comment. An
absent recipient is not currently un-tippable; they are tippable on-chain, with
gas. **That is the honest fallback and it should be stated in the UI rather than
engineered around.**

---

## 3. Two viable designs

### Design A — Volunteer as MAILBOX (non-custodial)

The volunteer runs `WebPeer` on a public HTTPS name and **holds no key for the
recipient**. It accepts inbound SCPP frames addressed to the recipient's
address, stores them, and hands them to the recipient's browser when it appears.
The recipient's key lives in their wallet (MetaMask), exactly like a tipper's.

```
contributor browser ──POST /scpp/v1──► volunteer node ──queue──┐
                                                                │
recipient browser ──authenticated fetch──► volunteer node ◄─────┘
        │  signs the countersignature with the recipient's own wallet
        └──POST reply frame──────────────► volunteer node ──► contributor
```

- The volunteer **cannot sign**, so it cannot checkpoint, close, or move value.
- Replacing it is changing a URL. No custody transfer, no rekeying.
- Pool state is reconstructable from the co-signed states the recipient's browser
  holds, plus the chain — `Pool.View()` is already a pure function of those.
- **Cost: a tip completes only while the recipient has a tab open.** Tips arriving
  otherwise are queued proposals, not payments. That must be shown honestly as
  "N tips waiting for you to accept", never as pool balance.

### Design B — Volunteer as DELEGATED SIGNER (bounded custody)

The recipient generates a **channel-only key** (the `keys.go` pattern: derived,
domain-separated, never the payout wallet), and authorises a volunteer to run a
Coordinator with it. Channels are opened against that key; withdrawals go to the
recipient's real wallet via `WithdrawA/WithdrawB`.

- Always-on: tips complete while the recipient sleeps. This is what users expect.
- **The volunteer can steal every undrawn tip in those channels.** It cannot touch
  the recipient's wallet or any drawn value — bounded, exactly as `keys.go`
  bounds a router's exposure.
- Replacing a volunteer means **transferring the channel key or re-opening every
  channel** — i.e. transferring custody of an aggregate. The brief names this a
  red flag requiring review, and it is.

---

## 4. Security and privacy comparison

| property | A — Mailbox | B — Delegated signer |
|---|---|---|
| Volunteer can spend undrawn tips | **no** | **yes** (bounded to those channels) |
| Volunteer can touch recipient's wallet | no | no |
| Recipient must be online to receive | **yes** | no |
| Node replacement | change a URL | key transfer or re-open channels |
| Requires recipient to hold a key | yes (browser wallet) | yes (to authorise) |
| Survives volunteer disappearing | fully | undrawn tips at risk |
| Meets "must not become a custodian" | **yes** | **no** |

### Actor-visibility table

| Actor | Must know | Must NOT learn |
|---|---|---|
| **Syndichan** | that pooling is on; the recipient's public wallet; a node endpoint or a pointer to one | balances, aggregates, channel ids, contributor↔recipient pairs, amounts, tx hashes, any per-payment event |
| **Recipient** | everything about their own channels | other recipients' anything |
| **Volunteer node** | *A:* that frames exist for an address, their size and timing. *B:* additionally every balance and counterparty | *A:* the meaning of the frames it cannot open is limited — but see below |
| **Contributor** | the recipient's wallet, their own channel, their own payments | the recipient's other channels, the aggregate, other contributors |
| **Browser** | whatever its own party is entitled to | — |
| **Ethereum** | channel parties, deposits, withdrawals at checkpoint | off-chain intermediate states |

**Volunteer as metadata chokepoint — the honest answer.** In *both* designs a
volunteer serving many recipients sees *who paid whom and roughly how much*,
because SCPP frames name the channel and a channel names both parties. `onion.go`
and `blinded.go` exist to blunt this for *routed* payments, but a **direct**
bilateral tip to a recipient's own mailbox is inherently visible to that mailbox.

This is not solvable by endpoint design. The mitigations available are:
one volunteer per recipient (poor), many recipients per volunteer (herd privacy,
worse chokepoint), or routing tips through the hub so the terminal hop is
onion-wrapped (`hub.go` + `onion.go`) — which is the only real answer and is a
larger piece of work than this phase.

---

## 5. Recommendation

**Recommend Design A (mailbox), and do not build Design B without explicit
approval.**

Reasoning: A is the only one that satisfies the brief's own hard constraint. Its
cost — asynchronous receipt — is a *product* limitation that can be stated
honestly in the UI, whereas B's cost is a *custody* limitation that cannot be
stated away. B is not unreasonable and the project has already accepted bounded
hot keys for routers; but it turns a volunteer into a party that can take a
stranger's money, and that decision is the user's to make, not mine.

**However: neither can be built until F1 is fixed.** The first work item is not a
design at all — it is mounting the channel stack in the node binary.

---

## 6–8. Authorization, replacement, browser connection (Design A)

**Authorization.** The recipient signs, with the wallet already linked to their
profile, a statement binding their address to a volunteer's node id and endpoint
for a validity window. `PofRegistration.proof_message` is the existing template
for "the exact bytes a key signs, versioned, including everything a replay could
otherwise repoint". The volunteer serves an address only on a valid, unexpired
authorization; Syndichan stores the pointer, never the money.

**Node replacement.** State is *reconstructable*, not transferable: `Pool.View()`
is a pure function of co-signed states plus the chain, and `pool.go` says so
explicitly ("Delete the view and nothing is lost"). Replacing a volunteer is
issuing a new authorization and letting the old one expire. Contributors
re-resolve the endpoint on their next tip. **Multiple simultaneous authorizations
should be refused**: two mailboxes accepting proposals for one address invites two
proposals at one nonce, which is invariant I4's failure mode.

**Browser connection.** The recipient's console stays where P7 put it — served by
the node, same origin, `SetAccessControl` demanding a password because it is not
on loopback. The Syndichan settings page **links** to it; it does not fetch from
it. That removes the cross-origin problem entirely rather than punching a hole
through it.

---

## 9. What must change, what must not

**Must change**
1. Mount `WebPeer` and (loopback-only) `channel.NewAPI` in `cmd/syndichan-node`.
2. Serve the recipient console from the node (extend `internal/ui`, the P7 seam).
3. Add a channel/tipping capability to the node registry and set
   `StorageNode.payment_channel` from something that routes, not telemetry.
4. A signed recipient→node authorization, modelled on `PofRegistration`.
5. Endpoint resolution for tippers (profile field first; `endpointCommitment`
   later if discovery should not go through Syndichan).

**Must NOT change**
ChannelManagerV2 · `challengePeriod` · the deployment gate · `tip-channel.js` ·
`tip-flow.js` · `Pool.View()` accounting · the P15 privacy boundary ·
`/scpp/v1` staying unauthenticated · `/v1/*` staying token-authed and never CORS-enabled.

**Must be deleted or moved:** the P15 dashboard's cross-origin fetch to
`/v1/pool`. It is the wrong shape and the harness proxy is not a production plan.

---

## 10. Implementation plan (phases, not yet approved)

| phase | work | proves |
|---|---|---|
| **V0** | mount the channel stack in the node binary; `/scpp/v1` public, `/v1/*` loopback | a real node can be tipped at all |
| **V1** | move the recipient dashboard into `internal/ui`, same origin | no CORS, no token in a web page |
| **V2** | signed recipient→node authorization + one-active-node rule | a volunteer knows who it serves; I4 preserved |
| **V3** | capability bit + endpoint resolution for tippers | a tipper finds the node without Syndichan holding financial state |
| **V4** | mailbox queue + "N tips waiting" UX + fail-closed states | asynchronous receipt, honestly displayed |
| **V5** | onion-wrapped terminal hop via `hub.go` | volunteer stops being a metadata chokepoint |

## 11. Tests required before implementation

- A volunteer node **cannot** produce a signature for an address it serves (Design A's whole claim).
- Two authorizations for one recipient are refused; a stale one is refused.
- `Pool.View()` after node replacement equals the view before, reconstructed from a fresh store.
- Queued-but-unaccepted proposals never count toward `Withdrawable`.
- A node outage is distinguishable, in the UI, from: no tips · contributor offline · payment UNKNOWN · pooling disabled — five states, five messages.
- Syndichan receives no channel id, amount, aggregate, contributor identity or tx hash (extend the existing privacy suite).
- Mutation: delete the authorization check → a node serves an address it was never authorised for → test fails.

## 12. Unresolved — needs your decision

1. **Design A or B?** A is non-custodial and asynchronous; B is always-on and lets a volunteer take undrawn tips. My recommendation is A; B needs your explicit approval because it is the red flag your brief names.
2. **Is asynchronous receipt acceptable as the product?** If tips must complete while the recipient is away, the answer is B or the existing on-chain transfer path — not a better endpoint design.
3. **Should discovery go through Syndichan or `endpointCommitment`/DHT?** Syndichan is simpler and already knows the profile; the DHT removes it from the loop. Neither stores money either way.
4. **May a volunteer serve many recipients?** It improves herd privacy and worsens the chokepoint. Related: is V5 (onion terminal hop) in scope for P15 or a later phase?
5. **Does `internal/channel` being unmounted change the P12 deployment gate?** The gate assumes a payment node exists in production. It does not.

---

**Pooled tipping is NOT production live**, and on the evidence of F1 it is
further from live than the devnet results alone suggest: the protocol is
validated, the product has no server to run on yet.
