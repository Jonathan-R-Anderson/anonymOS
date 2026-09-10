# P12-5.4 — BLS12-381 primitive evaluation

**Recommendation: `github.com/supranational/blst` v0.3.17, with a wrapper that
performs key validation itself.**

The headline finding is not about which library. It is that **the convenience
API of the leading candidate does not subgroup-check public keys**, and this was
confirmed by running it rather than by reading its documentation. Any wrapper
that calls `FastAggregateVerify` and considers the job done inherits that gap.

Everything below was verified locally against the fetched module, not recalled.
Where something is *not* verified, it says so.

---

## 1. The finding, first

`blst`'s `FastAggregateVerify(sigGroupcheck bool, pks, msg, dst)` internally does:

```go
aggregator.Aggregate(pks, false)          // groupcheck = FALSE for public keys
sig.Verify(sigGroupcheck, pkAff, false,   // pkValidate  = FALSE for the aggregate
           msg, dst, ...)
```

So the only subgroup check it can be asked to perform is on the **signature**.
The public keys are aggregated unchecked.

Demonstrated, not inferred:

```text
infinity pubkey, KeyValidate()                      false   ← correctly rejects
FastAggregateVerify with that key in the set        true    ← accepts anyway
```

The infinity point is the identity, so aggregating it changes nothing and a
signature by the remaining members still verifies — while the caller believes
the full set participated. That is precisely the "signed but not attested to"
inflation the participation threshold exists to prevent.

**Consequence for our wrapper:** every public key must go through
`KeyValidate()` before it is used, and a committee must be validated once when
it is first authenticated rather than on every verification.

This is the same class of trap you identified in gnark-crypto's `PairingCheck`.
It is not unique to that library; it is how performance-oriented BLS APIs are
built, and the only safe assumption is that no convenience function validates
anything it was not explicitly asked to.

## 2. Requirements table — blst v0.3.17

| Requirement | Finding | Verified how |
|---|---|---|
| Ethereum BLS12-381 scheme | Minimal-pubkey-size (G1 keys, G2 signatures), which is Ethereum's | signed/verified locally |
| Subgroup checks | **Available but NOT automatic.** `KeyValidate()` (G1), `SigValidate()` (G2), `sigGroupcheck` parameter. `FastAggregateVerify` does **not** check keys | source read + runtime test |
| Hash-to-curve | RFC 9380 `SSWU_RO`, DST supplied by the caller | wrong DST rejected at runtime |
| DST | Caller-controlled — we pass Ethereum's `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` | runtime test |
| Aggregate verification | `FastAggregateVerify`, `AggregateVerify`, `MultipleAggregateVerify` | source |
| Malformed encodings | `Uncompress` returns nil on bad input; must be checked | source |
| Infinity points | `KeyValidate()` rejects; the aggregate path does not | **runtime test** |
| Licence | Apache-2.0 | LICENSE file |
| Version | v0.3.17 (note: **not** v0.3.16 — it has moved) | `go get` resolution |
| Audit history | `SECURITY.md` present in the module. **NOT independently verified** — see §5 | — |
| Reproducible build | Go module checksum pinned in go.sum; C and assembly vendored in the module | go.sum |
| Go support | Builds and runs under this project's toolchain | built and ran locally |
| Platform | **cgo required.** Assembly for common targets; `__BLST_NO_ASM__` fallback for loong64/mips64/ppc64/riscv64/s390x. No pure-Go path | build tags read |

## 3. The cgo consequence, stated plainly

blst is a cgo binding over C and assembly. That is a real change to this
module's build, which is currently pure Go:

- cross-compilation needs a C toolchain for the target;
- static linking against musl vs glibc becomes a consideration for containers;
- `CGO_ENABLED=0` builds will no longer include the light client.

None of this is disqualifying, and the assembly is the reason the library is
fast enough to verify a 512-key aggregate per update. But it should be a
decision rather than a surprise at deploy time, and the watchtower's container
build will need checking.

## 4. Candidates considered

**`supranational/blst` — recommended.** The reference implementation, used by
most consensus clients. Fast, Apache-2.0, actively maintained. Costs: cgo, and
an API that requires the caller to ask for validation.

**`consensys/gnark-crypto` — rejected for this role.** Pure Go, which is
genuinely attractive against the cgo cost. Rejected because its pairing API
documents that it does not perform subgroup checks, so the safety of our one
security boundary would depend on assembling several primitives correctly
ourselves — which is nearer to the hand-written pairing the roadmap constraint
forbids than to using a vetted primitive.

**Pure-Go BLS implementations generally.** The trade is real and, if the cgo
cost proves unacceptable in the container build, worth revisiting *as a
comparison of audited options* — not as a reason to assemble one.

## 4b. RESULT — pinned, wrapped, and held to the consensus-spec vectors

`github.com/supranational/blst v0.3.17` is pinned. The wrapper is
`internal/ethproof/bls.go`, and it is the only file in the project that imports
blst or names a curve point (verified by grep, not by convention).

**Consensus-spec vectors, ethereum/consensus-spec-tests v1.5.0, all passing:**

```text
eth_fast_aggregate_verify    12/12   the variant the consensus layer uses
fast_aggregate_verify        11 agree, 1 documented divergence
```

The divergence is the spec's own: `eth_fast_aggregate_verify` accepts empty
pubkeys with the infinity signature; base BLS rejects it. We implement the
Ethereum variant, and the test asserts agreement everywhere else rather than
skipping the case — skipping would hide an accidental match with base BLS
somewhere it should not occur.

`eth_fast_aggregate_verify_infinity_pubkey` passes because the wrapper's
`KeyValidate` loop rejects key 3. That vector is called out in its own test so
that removing the loop as a redundant optimisation fails by name.

**The empty-set special case is contained.** It is a trivially-true branch, so
the layers above are tested to prove it cannot be reached: the committee layer
returns `ErrNoParticipants` before validating keys, and the structural layer
refuses below 2/3 participation long before that.

**`CGO_ENABLED=0` fails to build**, deliberately. There is no pure-Go fallback
that would silently ship a watchtower with no verifier.

## 5. What this evaluation does NOT establish

- **The audit history is not independently verified.** Supranational states
  that blst underwent an NCC Group security audit, and `SECURITY.md` is present
  in the module. **We have not read the report or confirmed its scope**, and
  this document must not be cited as saying we did. "Widely used by consensus
  clients" is evidence of exposure, not of review. Recording the limitation is
  the point; the decision to proceed on it was taken explicitly.
- ~~No Ethereum consensus test vectors have been run.~~ **CLOSED** — see §4b.
  24 cases from consensus-spec-tests v1.5.0 now run in CI.
- **`AggregateVerify`'s distinct-message requirement** has not been exercised.
  We use the single-message form, but the distinction matters if that ever
  changes.

## 6. What the wrapper must therefore do

```go
VerifySyncCommitteeSignature(signingRoot, committee, participation, signature)
```

1. **Validate every public key** with `KeyValidate()` — not optional, given §1.
   Cache the result per committee: 512 validations per period, not per update.
2. **Reject malformed encodings** — `Uncompress` returning nil is a rejection,
   never an empty key.
3. **Pass `sigGroupcheck = true`.** The one thing the API will do if asked.
4. **Select participants from the bitfield**, and require the count to match
   what the caller was told — a mismatch between the bits and the keys used is a
   participation lie.
5. **Use Ethereum's DST**, compiled in, never a parameter a caller can vary.
6. **Return an error, never a bool.** A boolean return invites `if !ok` to be
   forgotten; an error makes ignoring it visible.

Nothing above this function knows what a curve point is; nothing below it knows
what a sync committee is.

## 7. Recommendation

Pin `github.com/supranational/blst v0.3.17`, subject to two things being settled
first:

- **the audit question in §5** — a decision on whether "widely deployed" is
  sufficient assurance, made explicitly rather than by omission;
- **the cgo consequence in §3** — confirmation that the watchtower container can
  build with cgo enabled.

Then build the wrapper per §6, and test it against real Ethereum consensus
vectors rather than only against keys we generated ourselves.
