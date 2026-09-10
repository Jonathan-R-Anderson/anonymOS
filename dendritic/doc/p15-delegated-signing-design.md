# P15 — First-class delegated signing in ChannelManager

**Status: DESIGN + SECURITY ANALYSIS. No contract modified. Nothing deployed.**

Premise accepted: ChannelManagerV2 is **not** in production (devnet/Hardhat
only), so the digest and authorization model are open for redesign.

---

## 0. Verdict

**Yes, this can be done safely, and it does not need a fundamentally different
contract.** It needs two changes, one of which is required whether or not we
ever ship delegation:

1. **The state digest must bind the operation.** Today it does not, and that is
   the reason operation masks cannot be enforced (§2). This is a latent
   authorization coupling that exists *right now*, independent of delegation.
2. **A per-party delegation registry**, separate from channel state, with
   expiry, revocation, an operation mask and a cumulative withdrawal cap (§4).

The invariant the brief asks for — *the payout destination is the party, never
the delegate* — is already how every payout path is written, and the design keeps
it by never letting a delegate appear in `Channel`.

**Do not call it V3.** The contract has no production history to preserve; this
is ChannelManagerV2 finished, not replaced.

---

## 1. Where signer identity and beneficiary identity are coupled today

Audited every path. There are exactly two kinds of coupling.

### (a) Authorization — one place, and it is total

```solidity
function _requireSigned(Channel storage ch, bytes32 digest, bytes calldata sigA, bytes calldata sigB) {
    if (_recover(digest, sigA) != ch.partyA) revert BadSignature();
    if (_recover(digest, sigB) != ch.partyB) revert BadSignature();
}
```

Every signature-checked path — `checkpoint`, `closeCooperative`,
`closeUnilateral`, `challenge` — routes through this one function. **That is
good news: there is a single seam to change.**

### (b) Beneficiary — three places, all already correct

| path | destination |
|---|---|
| `checkpoint` | `token.safeTransfer(ch.partyA/ch.partyB, withdrawA/B)` |
| `settle` → `_payout` | `token.safeTransfer(ch.partyA/ch.partyB, a/b)` |
| `closeCooperative` → `_payout` | same |

Every destination is `ch.partyA` / `ch.partyB`, fixed at `openChannel` by sorting
`msg.sender` and `partner`. **No payout path reads a signer.** So the coupling is
*not* in the money — it is only that today the signer must equal the party.
Breaking that link is a change to `_requireSigned` alone.

### (c) Paths with no signature at all — inherently non-delegatable

`openChannel` and `deposit` authorize on `msg.sender` and move tokens *from* the
caller. A delegate cannot impersonate a party there because there is no signature
to forge — it would be spending its own tokens. `settle`, `claimLock` and
`expireLock` are permissionless by design and change no authorization.
**None of these needs or gets a delegate concept.**

---

## 2. The blocker: the digest does not bind the operation

```solidity
closeCooperative → stateDigest(id, nonce, balanceA, balanceB, bytes32(0), 0, 0)
closeUnilateral  → stateDigest(id, nonce, balanceA, balanceB, root,      0, 0)
challenge        → stateDigest(id, nonce, balanceA, balanceB, root,      0, 0)
```

**When `root == 0` these are byte-identical.** An ordinary agreed state with no
live locks *is already* a valid cooperative-close authorization. Nobody signed
"close the channel"; they signed a balance split, and the contract cannot tell
the difference.

Today that is a griefing surface rather than theft — `closeCooperative` pays the
agreed balances to the real parties, and either party could reach the same
outcome via `closeUnilateral` after a delay. **But it makes an operation mask
unimplementable**: a delegate permitted only to countersign payments would be
producing signatures that also authorize an immediate settle.

`checkpoint` is accidentally separated, because it reverts unless
`withdrawA + withdrawB > 0`, so its digest can never collide with a close digest.
Accidental separation is not a security property.

**Therefore: add an explicit operation domain to `stateDigest`.** This is a
breaking change to every signature — free now, impossible later.

---

## 3. What may be delegated, and one thing that cannot be separated

### The inherent coupling: a payment signature *is* an exit authorization

This is the property that makes a payment channel trustless: the latest co-signed
state is your exit. `closeUnilateral` and `challenge` must accept exactly the
states parties sign during ordinary payment, or a watchtower has nothing to
defend with and going offline stops being safe.

**So a delegate that may countersign payments can necessarily cause an exit at
those states. That cannot be separated and should not be.** It is also harmless
in the sense that matters: an exit pays the *party*.

### Recommended mask

| operation | delegatable | why |
|---|---|---|
| `OP_STATE` — pay / challenge / unilateral exit | **yes** | this is the point: countersigning tips while the recipient is offline. Exit-usability comes with it, inherently |
| `OP_CHECKPOINT` — withdraw without closing | **yes, optional, capped** | lets a node sweep tips; pays the party; bounded by cap |
| `OP_COOP_CLOSE` — immediate settle, no window | **no** | ends the channel with no challenge period. Griefing with no upside; the party can always do it themselves |
| `openChannel`, `deposit` | n/a | `msg.sender`-authorized, no signature exists |
| `settle`, `claimLock`, `expireLock` | n/a | already permissionless; change no authorization |

Two masks, one refusal. Anything broader is authority we cannot justify.

---

## 4. Proposed authorization model

### Delegation lives OUTSIDE channel state and outside the digest

Putting a delegate in the digest would make the same economic state hash
differently depending on who signed it — two valid states at one nonce, which is
precisely the I4 failure mode, and it would break every watchtower holding
previously-signed states. Delegation is a property of a **party**, not of a
**state**.

```solidity
uint32 constant OP_STATE      = 1 << 0;   // pay / challenge / unilateral
uint32 constant OP_CHECKPOINT = 1 << 1;   // withdraw, channel stays open
// deliberately no bit for cooperative close

struct Delegation {
    address signer;      // who may sign for this party; 0 = none
    uint64  expiry;      // unix seconds; hard stop
    uint32  ops;         // permitted operation bits
    uint256 cap;         // cumulative withdrawal ceiling under this delegation
    uint256 spent;       // cumulative withdrawn so far
    uint64  epoch;       // bumped on every change; kills old delegations
}

mapping(address => Delegation) public delegations;   // per PARTY, all channels

event DelegationSet(address indexed party, address indexed signer,
                    uint64 expiry, uint32 ops, uint256 cap, uint64 epoch);
event DelegationRevoked(address indexed party, uint64 epoch);
```

### The changed seam

```solidity
function _authorized(address party, bytes32 digest, bytes calldata sig, uint32 op)
    private view returns (bool)
{
    address who = _recover(digest, sig);
    if (who == party) return true;                       // the party always may

    Delegation storage d = delegations[party];
    if (d.signer == address(0) || who != d.signer) return false;
    if (block.timestamp >= d.expiry) return false;
    if (d.ops & op == 0) return false;
    return true;
}
```

`_requireSigned(ch, digest, sigA, sigB, op)` calls it for each side. **`Channel`
gains no field, and no payout path is touched.**

### Setting a delegation — party only, never delegable

```solidity
function setDelegate(address signer, uint64 expiry, uint32 ops, uint256 cap) external {
    if (ops & ~(OP_STATE | OP_CHECKPOINT) != 0) revert BadOps();   // coop-close unreachable
    if (expiry <= block.timestamp) revert BadExpiry();
    Delegation storage d = delegations[msg.sender];
    d.signer = signer; d.expiry = expiry; d.ops = ops;
    d.cap = cap; d.spent = 0; d.epoch += 1;
    emit DelegationSet(msg.sender, signer, expiry, ops, cap, d.epoch);
}

function revokeDelegate() external { … d.signer = address(0); d.epoch += 1; … }
```

`msg.sender` is the party. **There is no signature-based path to change a
delegation**, so a delegate can never widen, extend or re-point its own
authority. That is the single most important line in the design and it is
enforced by the absence of a function, not by a check.

### The cap, and what it actually bounds

Charged in `checkpoint` only, against the delegating party's own withdrawal:

```solidity
if (signerWasDelegate) {
    d.spent += withdrawForThatParty;
    if (d.spent > d.cap) revert DelegationCapExceeded();
}
```

A cap on `OP_STATE` is **not offered, because it cannot be enforced.** The
contract sees a balance split, not a transfer amount, and the previous off-chain
state is invisible to it. Offering a "spend limit" on state signing would be a
number in a UI that nothing checks — exactly the boundary the brief forbids
inventing.

---

## 5. Security invariants

| # | invariant | enforced by |
|---|---|---|
| D1 | A delegate is never a payee | no payout path reads a signer; `Channel` has no delegate field |
| D2 | A delegate cannot alter any delegation | `setDelegate`/`revokeDelegate` are `msg.sender`-only; no signed variant exists |
| D3 | A delegate cannot cooperatively close | no mask bit exists; `setDelegate` rejects unknown bits |
| D4 | A delegate cannot act after expiry or revocation | checked at submission |
| D5 | A delegate cannot exceed the withdrawal cap | `spent` accumulates in `checkpoint` |
| D6 | The party may always act, delegation or not | `who == party` short-circuits first |
| D7 | The counterparty's protection is unchanged | both signatures still required on every state path |
| D8 | An operation signature cannot be reused as another operation | op domain in the digest (§2) |
| D9 | Delegation changes are public | mapping is `public`, plus events |

**D7 deserves emphasis.** Delegation loosens who may sign for *one* party. It
never loosens the requirement that *both* parties sign. A contributor is exposed
to nothing new: no state can be admitted that they did not personally sign.

---

## 6. Maximum loss under a compromised delegate

| scenario | loss |
|---|---|
| Mailbox mode (no delegation) | **zero** — the volunteer holds nothing signable |
| Delegate with `OP_CHECKPOINT` only | **zero funds.** Withdrawals go to the party. Attacker can force gas and premature sweeps |
| Delegate with `OP_STATE` | **the delegating party's un-checkpointed balance in channels whose counterparty will collude** |
| Delegate with `OP_STATE + OP_CHECKPOINT` | as above; the cap bounds withdrawals but not the state-signing exposure |
| Old design (distinct key = party) | **all tips, received by default** — the thing this redesign removes |

### The residual risk, stated plainly

`OP_STATE` is global across the party's channels, because pooled tipping gets a
new channel per contributor and per-channel authorization would require the
recipient online — defeating the purpose. A compromised delegate therefore
reaches **every** channel of that party, including ones where the party is the
*payer* with a large balance.

Draining requires a **colluding counterparty**, since both signatures are still
needed. It is not a random-attacker risk; it is a "the volunteer opens a channel
to you, or partners with someone who has one" risk.

**Mitigation, and it is a recommendation not a mechanism: use a dedicated
tipping address as the party.** It only ever receives, so its worst case is the
undrawn tips. This is categorically different from the rejected design — the
*recipient* holds that key and is the payee; the volunteer holds only a delegate
key it can never be paid through.

---

## 7. Interaction with I4, nonces and replay

- **I4 (never two different states at one nonce) is unchanged and strengthened.**
  Delegation does not enter the digest, so a given economic state has exactly one
  digest regardless of who signed it. The off-chain rule stays as written.
- **The node must treat delegate and party as one signing identity for I4.** If a
  recipient signs at nonce 5 in their browser while their delegate also signs at
  nonce 5, that is an I4 violation with two keys. **Hence: mailbox mode and
  delegated mode must be mutually exclusive at any instant, and at most one
  delegation may be live.** The single `delegations[party]` slot enforces the
  latter structurally — there is no list, so two simultaneous delegates cannot
  exist.
- **On-chain replay** is unchanged: strictly-increasing nonce in `checkpoint` and
  `challenge`, status gates elsewhere.
- **Cross-operation replay** is closed by the op domain (§2) — the actual replay
  hole in the current contract.
- **Cross-chain / cross-contract replay** already covered: the digest binds
  `block.chainid` and `address(this)`.

### The revocation footgun, and the honest answer

A delegate-signed state is valid **only while that delegation is live**. Revoke,
and states the delegate signed but nobody submitted become unusable.

That is correct when the delegate is compromised — you *want* its signatures
dead. It is a footgun during routine rotation. Two consequences:

- **Safe rotation is: checkpoint → revoke → re-delegate.** Documented procedure,
  not a contract mechanism.
- Losses fall on the **recipient only**. A contributor's fallback is an older
  state, where the recipient had *less* — so the party who revokes bears the
  cost. Correctly aligned.

Recommend both `revokeDelegate()` (immediate, for compromise) and letting
`expiry` do routine rotation, so the common case never strands anything.

---

## 8. Lifecycle

| step | mechanism |
|---|---|
| **create** | party calls `setDelegate(signer, expiry, ops, cap)` from their own address |
| **rotate** | checkpoint, then `setDelegate` with the new signer; `epoch` bumps, old signer dead |
| **revoke** | `revokeDelegate()` — immediate |
| **expire** | `block.timestamp >= expiry`; no transaction needed, and this is the safe default |
| **observe** | public mapping + `DelegationSet`/`DelegationRevoked` events |

`epoch` exists so off-chain code and UIs can detect a change without diffing
fields, and so a node can refuse to keep signing under an authorization that has
moved underneath it.

---

## 9. Do authorization changes need both parties' signatures?

**No, and they must not.**

Delegation says who may sign *for me*. The counterparty is not weakened (D7) —
they still sign everything themselves. Requiring their signature would make
rotation depend on a stranger's cooperation, and after a compromise the recipient
would have to beg every contributor before revoking. Revocation must be
unilateral or it is not revocation.

What the counterparty *does* get is visibility: the mapping is public and every
change emits. A contributor unwilling to transact with a delegated recipient can
see it and decline.

---

## 10. Mailbox mode is preserved

Nothing above is required for mailbox mode. With no delegation set,
`_authorized` reduces to `who == party` — byte-identical behaviour to today.
`delegations[party].signer == address(0)` is the zero value, so **mailbox-only is
the default state of every address that never opts in.**

---

## 11. Tests and mutation tests

**Functional**
- Party signs with no delegation → accepted (unchanged behaviour).
- Delegate with `OP_STATE` countersigns a pay state → `closeUnilateral`/`challenge` accept it.
- Delegate with `OP_CHECKPOINT` checkpoints → **funds arrive at the party address, not the delegate's**.
- Delegate without `OP_CHECKPOINT` tries to checkpoint → revert.
- Delegate tries `closeCooperative` → revert (no bit can grant it).
- Expired delegation → revert. Revoked → revert. Wrong signer → revert.
- Cap: withdrawals accumulate; the one that crosses `cap` reverts; the party is unaffected by the cap.
- `setDelegate` with an unknown bit → revert.
- Party can always act while a delegation is live.

**Adversarial**
- Delegate attempts `setDelegate`/`revokeDelegate` → no such path exists; assert by ABI that no signature-authorized variant is reachable.
- Delegate-signed state replayed as a different operation → must fail (this is the §2 fix; it **passes** today and must stop).
- Two delegations at once → structurally impossible; assert the second overwrites and the first signer is immediately dead.
- Delegate colludes with counterparty to move the party's balance → **succeeds, bounded**; the test pins the bound rather than pretending otherwise.
- Delegate cannot open a channel or deposit as the party.

**Mutation (each must be caught)**
1. `checkpoint` pays `d.signer` instead of `ch.partyA/B`.
2. Drop the `expiry` check.
3. Drop the `ops & op` check.
4. Drop the cap accumulation.
5. Add `OP_COOP_CLOSE` to the allowed mask.
6. Remove the op domain from `stateDigest` (must resurrect the cross-operation replay).
7. Make `setDelegate` accept a signature instead of `msg.sender`.
8. Let `_authorized` fall through to `true` when `d.signer == address(0)`.

---

## 12. Files that would change

`contracts/ChannelManagerV2.sol` — `stateDigest` (op domain), `_requireSigned` →
`_authorized`, the `Delegation` struct/mapping, `setDelegate`/`revokeDelegate`,
cap accounting in `checkpoint`.

Off-chain, the digest change propagates to: `internal/channel/state.go`
(`Digest`), `chainwriter.go` (calldata builders), `tip-channel.js` (browser
signing), and every golden vector. **This is a wide but mechanical change, and it
is the reason to do it now rather than after deployment.**

No change to: `challengePeriod`, the deployment gate, `Pool.View()` accounting,
the P15 privacy boundary, `/scpp/v1`, `/v1/*`.

---

## 13. Decisions needing your approval before I write any code

1. **Approve the digest change?** It is required for op scoping and it fixes a
   real cross-operation replay that exists today. It invalidates every existing
   signature and golden vector — cheap now, impossible after deployment.
2. **Global-per-party delegation, with a dedicated tipping address as the
   recommended practice?** The alternative is per-channel authorization, which is
   safer but requires the recipient online for every new contributor and so
   cannot deliver always-available receipt.
3. **Ship `OP_CHECKPOINT` at all?** `OP_STATE` alone delivers always-available
   receipt. Adding checkpoint delegation buys unattended sweeping and costs a
   capped-but-real exposure. I lean to shipping `OP_STATE` first and
   `OP_CHECKPOINT` behind a second decision.
4. **Confirm cooperative close stays non-delegatable.** I recommend yes.
5. **Accept that revocation invalidates un-submitted delegate-signed states**, with
   "checkpoint → revoke → re-delegate" as the documented rotation?

---

**Nothing deployed, no mainnet transaction, no change to `challengePeriod` or the
deployment gate. Pooled tipping is NOT production live.**
