//go:build !ethbls

package ethproof

// The BLS boundary when pairing cryptography is NOT compiled in.
//
// WHY THIS FILE EXISTS
// --------------------
// blst is cgo, and it cannot build with CGO_ENABLED=0 on any target except
// wasm: its `Message` type lives in the cgo file, and the one pure-Go file in
// the package references it. The node's release build is CGO-free by design —
// seven platforms cross-compiled from one host, static, -trimpath — and that
// script predates the blst dependency by two weeks. So a node that links blst
// is a node that cannot be released.
//
// WHAT THIS IS NOT
// ----------------
// It is NOT a second implementation of sync-committee verification, a
// degraded one, or a fast path. There is no cryptography here at all. Every
// method fails, always, with the same error.
//
// That is safe today only because of a fact worth stating plainly: NOTHING in
// cmd/syndichan-node constructs a BLSVerifier. The only callers of
// NewBLSVerifier in the whole repository are tests, and the light client takes
// its verifier as a parameter rather than building one. BLS arrived as a
// verified library capability with its consensus-spec vectors and was never
// wired into a runtime path. This file makes that boundary explicit instead of
// leaving it as an unused import that breaks the release.
//
// THE DIRECTION OF THE TAG IS DELIBERATE
// --------------------------------------
// `ethbls` ENABLES the real implementation; its absence selects this one. A
// forgotten tag therefore yields the build that refuses to verify, never the
// build that silently claims it did. The opposite arrangement would make a
// typo into a security downgrade.

import "errors"

// EthereumDST is the domain separation tag Ethereum's consensus layer uses.
//
// Kept real in both builds because it is PROTOCOL DATA, not an implementation:
// it is a constant from the specification, and code that reads it — to compare,
// to log, to check a fixture — is not asking this build to verify anything.
var EthereumDST = []byte("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_")

const (
	// BLSPubkeyBytes is a compressed G1 point.
	BLSPubkeyBytes = 48
	// BLSSignatureBytes is a compressed G2 point.
	BLSSignatureBytes = 96
)

// ErrNoBLSSupport is returned by every verification entry point in a build
// without the `ethbls` tag.
//
// Worded so it cannot be mistaken for a verification FAILURE. "The signature
// did not verify" and "this binary cannot verify signatures" call for opposite
// responses: the first rejects one update, the second means no update has been
// checked at all and none can be.
var ErrNoBLSSupport = errors.New(
	"bls: this binary was built without P12 BLS support (build tag `ethbls`); " +
		"it cannot verify Ethereum sync-committee signatures and must not be " +
		"treated as having verified any")

// BLSVerifier is the no-BLS stand-in for the real verifier.
//
// Same name and same methods as the `ethbls` implementation, so every caller
// compiles identically in both builds and the difference is a build decision
// rather than a code path somebody can take by accident.
type BLSVerifier struct{}

// NewBLSVerifier returns a verifier that refuses everything.
//
// RETURNS A VALUE, NEVER NIL. A nil return would invite `if v != nil { verify }`
// at call sites, and that guard is a bypass: the branch that skips verification
// would be the branch that runs. A non-nil verifier whose every method errors
// cannot be routed around — the caller has to handle the error.
func NewBLSVerifier() *BLSVerifier { return &BLSVerifier{} }

// ValidateCommittee always fails.
func (v *BLSVerifier) ValidateCommittee(committee *SyncCommittee) error {
	return ErrNoBLSSupport
}

// VerifySyncCommitteeSignature always fails.
//
// No argument is inspected — not the shape, not the participation count, not
// the length of the signature. Rejecting on a malformed input would imply that
// a well-formed one might pass, and nothing here can ever return nil.
func (v *BLSVerifier) VerifySyncCommitteeSignature(
	signingRoot Root, committee *SyncCommittee,
	participation Participation, signature []byte) error {

	return ErrNoBLSSupport
}

// The same assertion the real implementation carries. It has to hold in both
// builds, or the two files are not interchangeable and the tag is a lie.
var _ SyncCommitteeVerifier = (*BLSVerifier)(nil)
