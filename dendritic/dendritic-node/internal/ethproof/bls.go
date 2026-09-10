//go:build ethbls

package ethproof

// The BLS boundary — roadmap P12-5.4.
//
// THIS IS THE ONLY FILE IN THE PROJECT THAT TOUCHES CURVE POINTS.
//
// Everything above it deals in sync committees, headers and slots. Everything
// below it is github.com/supranational/blst v0.3.17, Apache-2.0, vendored C and
// assembly behind cgo. The roadmap records the constraint that we do not write
// pairing, hash-to-curve, subgroup or cofactor code ourselves; this file is
// where that decision is spent.
//
// WHY THE WRAPPER VALIDATES KEYS ITSELF
// -------------------------------------
// blst's FastAggregateVerify does NOT subgroup-check public keys. Its own
// implementation aggregates with groupcheck=false and verifies with
// pkValidate=false; the only check it will perform on request is on the
// signature. Demonstrated rather than assumed — see doc/bls-library-evaluation.md:
//
//	infinity pubkey, KeyValidate()                 false   (rejected)
//	FastAggregateVerify with that key in the set   true    (accepted)
//
// The infinity point is the identity, so aggregating it changes nothing and the
// remaining members' signature still verifies — while the caller believes the
// whole set participated. That inflates apparent participation, which is the
// one number the 2/3 threshold exists to protect.
//
// So KeyValidate runs here, on every key, and the caller never has to remember
// it. A validation the caller can forget is a validation that will be forgotten.
//
// WHY VALIDATION IS CACHED PER COMMITTEE
// --------------------------------------
// 512 subgroup checks per update would dominate the cost of following the
// chain. A committee is fixed for a period (~27 hours), so it is validated once
// when first seen and the result is remembered against its hash tree root — not
// against a pointer, so a substituted committee with the same address cannot
// inherit an earlier committee's clean bill of health.
//
// WHAT THIS FILE DOES NOT ESTABLISH
// ---------------------------------
// That our ciphersuite matches Ethereum's. Signing and verifying against keys
// we generated proves the API works, not that mainnet validators produce
// signatures this accepts. Only consensus-spec vectors establish that, and
// P12-5.4 is not complete without them — see bls_vectors_test.go.

import (
	"errors"
	"fmt"
	"sync"

	blst "github.com/supranational/blst/bindings/go"
)

// EthereumDST is the domain separation tag Ethereum's consensus layer uses for
// every BLS signature, including sync committee aggregates.
//
// Compiled in, never a parameter. A caller able to vary the DST could ask this
// to verify a signature made for another protocol entirely, and the result
// would be a correct verification of the wrong thing.
//
// The suite is RFC 9380's BLS12-381 G2, SHA-256, SSWU random-oracle encoding,
// proof-of-possession variant — which is what the consensus specification
// names.
var EthereumDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

// Ethereum uses minimal-pubkey-size: public keys in G1, signatures in G2.
type blstPublicKey = blst.P1Affine
type blstSignature = blst.P2Affine

const (
	// BLSPubkeyBytes is a compressed G1 point.
	BLSPubkeyBytes = 48
	// BLSSignatureBytes is a compressed G2 point.
	BLSSignatureBytes = 96
)

var (
	// ErrBadPublicKey means a committee key is malformed or not in the correct
	// subgroup. Fatal for the committee, not just for one update.
	ErrBadPublicKey = errors.New("bls: committee public key is invalid")
	// ErrBadSignature means the signature is malformed or not in the subgroup.
	ErrBadSignature = errors.New("bls: signature is malformed or off-subgroup")
	// ErrSignatureDoesNotVerify means everything was well-formed and the
	// aggregate simply does not verify. The ordinary rejection.
	ErrSignatureDoesNotVerify = errors.New("bls: aggregate signature does not verify")
	// ErrNoParticipants means the bitfield selected nobody.
	ErrNoParticipants = errors.New("bls: no committee members participated")
)

// BLSVerifier implements SyncCommitteeVerifier over blst.
//
// Safe for concurrent use: the validation cache is the only mutable state.
type BLSVerifier struct {
	mu sync.RWMutex
	// validated remembers committees whose keys have passed KeyValidate,
	// keyed by hash tree root. Keyed by ROOT rather than by pointer so a
	// different committee cannot inherit an earlier one's result.
	validated map[Root]bool
}

// NewBLSVerifier builds one.
func NewBLSVerifier() *BLSVerifier {
	return &BLSVerifier{validated: map[Root]bool{}}
}

// ValidateCommittee subgroup-checks every public key.
//
// Called automatically by VerifySyncCommitteeSignature; exported so a committee
// can be validated at the moment it is first authenticated, which is where the
// cost belongs.
func (v *BLSVerifier) ValidateCommittee(committee *SyncCommittee) error {
	if committee == nil {
		return errors.New("bls: no committee")
	}
	root, err := committee.HashTreeRoot()
	if err != nil {
		return err
	}

	v.mu.RLock()
	done := v.validated[root]
	v.mu.RUnlock()
	if done {
		return nil
	}

	for i, raw := range committee.Pubkeys {
		if len(raw) != BLSPubkeyBytes {
			return fmt.Errorf("%w: key %d is %d bytes, want %d",
				ErrBadPublicKey, i, len(raw), BLSPubkeyBytes)
		}
		pk := new(blstPublicKey).Uncompress(raw)
		if pk == nil {
			// Malformed encoding. Not an empty key, not a zero point — a
			// rejection, because a nil here silently becomes the identity in
			// any aggregation that follows.
			return fmt.Errorf("%w: key %d does not decompress", ErrBadPublicKey, i)
		}
		// THE CHECK THE LIBRARY WILL NOT DO FOR US. Rejects the infinity point
		// and any point outside the prime-order subgroup.
		if !pk.KeyValidate() {
			return fmt.Errorf("%w: key %d is the infinity point or off-subgroup", ErrBadPublicKey, i)
		}
	}

	v.mu.Lock()
	v.validated[root] = true
	v.mu.Unlock()
	return nil
}

// VerifySyncCommitteeSignature is the one door to pairing cryptography.
//
// Order matters and is the order below: cheap structural rejections first, key
// validation before aggregation, and the pairing last.
func (v *BLSVerifier) VerifySyncCommitteeSignature(
	signingRoot Root, committee *SyncCommittee,
	participation Participation, signature []byte) error {

	// 1. Shape.
	if committee == nil {
		return errors.New("bls: no committee")
	}
	if len(signature) != BLSSignatureBytes {
		return fmt.Errorf("%w: %d bytes, want %d",
			ErrBadSignature, len(signature), BLSSignatureBytes)
	}

	// 2. Participants first, because it is the cheapest rejection and the most
	//    informative error. Validating 512 keys before discovering that nobody
	//    signed is work done to reach a conclusion already available — and it
	//    would report "key 0 is invalid" for an update whose real problem is
	//    that it is empty.
	//
	//    The count is re-derived from the bitfield rather than taken from the
	//    caller: a bitfield and a claimed count that disagree is a participation
	//    lie, and this is where it is caught.
	members := participation.Members()
	if len(members) == 0 {
		return ErrNoParticipants
	}

	// 3. Every key validated. Cached per committee root, so this is 512 checks
	//    per period rather than per update.
	if err := v.ValidateCommittee(committee); err != nil {
		return err
	}

	selected := make([][]byte, 0, len(members))
	for _, index := range members {
		if index >= len(committee.Pubkeys) {
			return fmt.Errorf("%w: bitfield names member %d of a %d-key committee",
				ErrBadPublicKey, index, len(committee.Pubkeys))
		}
		selected = append(selected, committee.Pubkeys[index])
	}

	// 4 and 5. The crypto boundary proper.
	return verifyAggregate(signingRoot, selected, signature)
}

// verifyAggregate is the crypto boundary with nothing above it.
//
// Split out so the consensus-spec vectors can exercise EXACTLY this — they
// supply a flat list of keys and a signature, not a 512-member committee with a
// participation bitfield, and a test that had to construct one would be testing
// the adapter rather than the cryptography.
//
// Ethereum's eth_fast_aggregate_verify semantics, which differ from the base
// BLS FastAggregateVerify in one way that matters: an infinity public key is
// REJECTED rather than absorbed. That rejection happens in the KeyValidate loop
// above and again here, because this function is reachable on its own.
func verifyAggregate(signingRoot Root, pubkeys [][]byte, signature []byte) error {
	// THE ONE PLACE THIS RETURNS SUCCESS FOR EMPTY INPUT.
	//
	// eth_fast_aggregate_verify defines it: no public keys and the infinity
	// signature is VALID. Base BLS FastAggregateVerify says the opposite, and
	// the consensus-spec vectors carry both — the eth_ case expects true, the
	// base case expects false.
	//
	// This is a trivially-true branch and therefore exactly the kind that leaks
	// upward into "verified" where it means nothing. It is safe here ONLY
	// because no caller in this package can reach it with an empty set:
	// VerifySyncCommitteeSignature returns ErrNoParticipants first, and above
	// that ValidateStructure requires 2/3 participation. Both are tested.
	//
	// If a new caller is ever added, it must guard this itself.
	if len(pubkeys) == 0 {
		if isInfinitySignature(signature) {
			return nil
		}
		return ErrNoParticipants
	}
	if len(signature) != BLSSignatureBytes {
		return fmt.Errorf("%w: %d bytes, want %d",
			ErrBadSignature, len(signature), BLSSignatureBytes)
	}

	keys := make([]*blstPublicKey, 0, len(pubkeys))
	for i, raw := range pubkeys {
		if len(raw) != BLSPubkeyBytes {
			return fmt.Errorf("%w: key %d is %d bytes", ErrBadPublicKey, i, len(raw))
		}
		pk := new(blstPublicKey).Uncompress(raw)
		if pk == nil {
			return fmt.Errorf("%w: key %d does not decompress", ErrBadPublicKey, i)
		}
		// THE CHECK blst WILL NOT DO. Rejects infinity and off-subgroup points,
		// which FastAggregateVerify would otherwise absorb silently.
		if !pk.KeyValidate() {
			return fmt.Errorf("%w: key %d is infinity or off-subgroup", ErrBadPublicKey, i)
		}
		keys = append(keys, pk)
	}

	sig := new(blstSignature).Uncompress(signature)
	if sig == nil {
		return fmt.Errorf("%w: does not decompress", ErrBadSignature)
	}
	// sigInfcheck=true: an infinity signature is never a legitimate aggregate
	// here, and rejecting it early avoids a pairing that would accept it.
	if !sig.SigValidate(true) {
		return fmt.Errorf("%w: infinity or off-subgroup", ErrBadSignature)
	}

	// sigGroupcheck=true is redundant after SigValidate and passed anyway:
	// relying on a check performed somewhere else is how a refactor removes it.
	if !sig.FastAggregateVerify(true, keys, signingRoot[:], EthereumDST) {
		return ErrSignatureDoesNotVerify
	}
	return nil
}

var _ SyncCommitteeVerifier = (*BLSVerifier)(nil)

// isInfinitySignature reports the canonical compressed encoding of the G2
// identity: 0xc0 followed by zeros.
//
// Compared bytewise rather than decompressed, because the question is about the
// ENCODING the spec names, and an implementation that decompressed first would
// also accept any other encoding that happened to decode to infinity.
func isInfinitySignature(sig []byte) bool {
	if len(sig) != BLSSignatureBytes || sig[0] != 0xC0 {
		return false
	}
	for _, b := range sig[1:] {
		if b != 0 {
			return false
		}
	}
	return true
}
