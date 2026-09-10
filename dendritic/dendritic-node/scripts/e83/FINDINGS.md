# E8.3 — what the second implementation found

10 000 corpus inputs, first run: **1 795 behaviour divergences and 4 921
error-kind divergences.** Accept/reject agreed on every input from the start —
the *grammar* was solid. Everything below the grammar was not.

That distribution is itself the result worth reading. A second implementation
written from a specification does not usually fail on whether a name is legal;
it fails on the parts a reader has to reconstruct, and those are the parts a
contract has to recompute exactly or the chain forks from the client.

Final state: **10 000/10 000 agree** on accept/reject, canonical form, parse,
`zone_id`, `nameHash`, skeleton, and reported error kind.

Each finding below says which side was wrong, because "the implementations
disagree" is not a finding until that is decided.

---

## F1 — `nameHash` omitted the namespace label  ·  **the specification was wrong**  ·  538 names

§11.3.2 stated:

```
nameHash = keccak256( namehash(TLD) ‖ keccak256(label) )
```

which is the pre-namespace two-level shape, left in place when §11.0a made the
namespace label part of every name. Read literally — which is what a second
implementation does — **`alice.lab.axon` and `alice.corp.axon` produce the same
on-chain identifier**, directly contradicting §11.3.1's own statement that they
are "different names owned by potentially different people".

`internal/axon/name` already did the full ENS chain and was right. The document
was wrong, and it is the document a contract implementer works from: §11.3.2
says "the contract must recompute it". A registry written from the stated
formula would have let the holder of `alice.lab` take `alice.corp` for free, and
the bug would have surfaced as a *governance* failure across namespaces rather
than as a hash mismatch.

**Fixed:** §11.3.2 now states the chain fold and why the namespace label is in
it. No code change.

## F2 — `Skeleton` skipped hyphen elision  ·  **the code was wrong**  ·  1 257 labels

§11.3.3's pseudocode opens with `s := replace(s, "-", "")`, and its consequence
1 spells out the result: *"`mybank.axon` blocks `my-bank.axon`, `rnybank.axon`
and the digit-one variant."*

`Skeleton` folded `rn`→`m`, `vv`→`w`, `cl`→`d` and the character pairs, but
never elided hyphens. So:

```
Skeleton("mybank")  = "my6ank"
Skeleton("my-bank") = "my-6ank"     ← different class
```

`mybank.axon` did **not** block `my-bank.axon`. A stated anti-phishing property
was false in the implementation that enforces it, and the file's own comment
shows how: it read "hyphen-like" as a *character fold* — "only ASCII `-`
survives Normalise, so there is nothing to fold here" — when the rule is
*elision*. The non-ASCII hyphens being gone is exactly why the ASCII one has to
be removed rather than folded.

**Fixed:** `confusable.go` elides hyphens first. Pinned by
`TestE83SecondImplementation`.

Second half of the same finding, the other way round: the spec's pseudocode
listed only `'1'->'l'` and `'0'->'o'`, while the code carried the audited T8.4
per-pair table (`o s b g z i l` onto digits) and `cl`→`d` — which §11.3.3's own
*prose* names but its pseudocode omits. **The code's table is the policy** and
is strictly more protective; §11.3.3 has been corrected to state it, including
the fold direction, which is arbitrary for class membership but not for the
bytes stored in `classHolder[skeleton]`.

## F3 — step order inside normalization  ·  **under-specified**  ·  4 921 inputs

Every one of these both-reject-different-reason. Not wrong answers — but a
caller acts on the reason, and two conformant implementations should not
disagree about it.

| | Was | Now |
|---|---|---|
| Steps 1 and 2 | one byte loop, so a control byte earlier in the string beat a non-ASCII byte later | separate passes; §11.3.2 numbers them 1 and 2 and says "which is why step 1 is first" |
| Step 8 | the root-suffix check ran *before* the grammar checks, masking every other refusal | last, as its number says |
| Per-label length bounds | `ErrGrammar` in Go, "too-long" in the second implementation — the spec names no error identifiers at all | `too-long` is the 253-byte whole-name cap **only**; a per-label bound violation in either direction is a grammar refusal |
| Label count vs byte count | unordered | label count first |

**Fixed:** the first two in `name.go`, the last two written into §11.3.2 and
adopted by the second implementation.

## F4 — is `ROOT_SUFFIX` subject to the `label` production?  ·  **under-specified**  ·  41 inputs

`alice.lab.ax--on` — the trailing label breaks the IDNA-prefix rule *and* is not
the root suffix. Which refusal?

§11.3.1's production ends in `ROOT_SUFFIX`, a constant, not an instance of
`label`. So the LDH rules do not apply to it and step 8's equality check is the
whole of its validation — which is also the more useful answer, since telling a
caller to fix a label they cannot choose is noise. Go had it right by
construction (it validates `labels[:len-1]`); nothing said so.

**Fixed:** §11.3.2 now states it.

---

## Out of scope, found anyway: `AxonRegistry.register` trusts the caller's skeleton

Not a §11.3 finding and **not fixed here** — it is a contract change with P9 /
§12.3 consequences and belongs to whoever owns that item.

§11.3.3 is explicit: *"The function runs **in the contract**, over the label
revealed at reveal time, as a bounded loop over at most 63 bytes. A rule
enforced only by clients is not a rule."*

`proof-of-facilitation/contracts/AxonRegistry.sol` takes `skeleton` as a
**caller-supplied argument** (`register(bytes32 nameHash, bytes32 skeleton,
uint8 labelLen, ...)`) and never derives it. The label is never passed, so the
contract *cannot* derive it. Worse, the commitment binds `nameHash` but not
`skeleton`:

```solidity
bytes32 c = keccak256(abi.encode(nameHash, msg.sender, secret, domainKey));
...
address holder = classHolder[skeleton];
if (holder != address(0) && holder != msg.sender) revert ClassHeld();
```

An attacker registers with `skeleton = keccak256(<anything unused>)` and the
class check passes unconditionally. The confusable-class defence — the whole of
§11.3.3's answer to homograph phishing, and the thing F2 above was fixing — is
enforced only by clients today, which §11.3.3 says is not a rule.

Fixing it means passing the revealed label bytes and computing the skeleton
on chain, which changes the commitment preimage and the `register` ABI.

---

## The caveat that does not go away

E8.3 says "two independent implementations". This is **one author, two
languages, spec-only**: `axonname.py` was written from §11.3 before any of
`internal/axon/name`'s source was read beyond its exported signatures, and the
keccak-256 is a separate implementation checked against published vectors, so
no code and no hash is shared. It is not two authors, and a single author
carries a single set of misreadings into both — the four findings above are the
ones that survived that, not necessarily all there are.

E8.3 is claimed on that basis, with the weakening stated. A genuinely
independent implementation remains PAR-14 / P21's deliverable; this harness is
what it should be run against on arrival.
