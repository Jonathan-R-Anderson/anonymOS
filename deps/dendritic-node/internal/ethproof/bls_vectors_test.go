//go:build ethbls

package ethproof

// Ethereum consensus-spec BLS vectors — roadmap P12-5.4's completion gate.
//
// These are NOT signatures we generated. They are ethereum/consensus-spec-tests
// v1.5.0, the same vectors every consensus client is held to, and they are the
// only thing that establishes our ciphersuite, DST, encoding and scheme variant
// match what mainnet validators actually produce.
//
// Verifying a signature we made ourselves proves the library works. It proves
// nothing about whether we are speaking Ethereum's dialect of BLS, and P12-5.4
// is not complete on that basis.
//
// THE CASE THAT MATTERS MOST
// --------------------------
// eth_fast_aggregate_verify_infinity_pubkey. Ethereum REJECTS a committee
// containing the infinity point; base BLS FastAggregateVerify absorbs it. blst's
// convenience API implements the latter, so this vector is precisely the one
// that fails if the wrapper's KeyValidate loop is ever removed as redundant.

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type blsVector struct {
	Input struct {
		Pubkeys   []string `yaml:"pubkeys"`
		Message   string   `yaml:"message"`
		Signature string   `yaml:"signature"`
	} `yaml:"input"`
	Output bool `yaml:"output"`
}

func loadVectors(t *testing.T, suite string) map[string]blsVector {
	t.Helper()
	dir := filepath.Join("testdata", "bls", suite)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Skipf("vectors not installed: %v", err)
	}
	out := map[string]blsVector{}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var v blsVector
		if err := yaml.Unmarshal(raw, &v); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		out[strings.TrimSuffix(e.Name(), ".yaml")] = v
	}
	if len(out) == 0 {
		t.Skip("no vectors found")
	}
	return out
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return raw
}

// suiteDirs finds every eth_fast_aggregate_verify_* case directory.
func suiteDirs(t *testing.T, prefix string) []string {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join("testdata", "bls"))
	if err != nil {
		t.Skipf("vectors not installed: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), prefix) {
			out = append(out, e.Name())
		}
	}
	return out
}

// runSuite checks every case in every directory under a prefix.
func runSuite(t *testing.T, prefix string) (passed int) {
	t.Helper()
	dirs := suiteDirs(t, prefix)
	if len(dirs) == 0 {
		t.Skipf("no %s* vectors installed", prefix)
	}
	for _, dir := range dirs {
		for name, v := range loadVectors(t, dir) {
			t.Run(dir+"/"+name, func(t *testing.T) {
				var root Root
				msg := unhex(t, v.Input.Message)
				if len(msg) != 32 {
					t.Skipf("message is %d bytes; this wrapper signs 32-byte roots", len(msg))
				}
				copy(root[:], msg)

				keys := make([][]byte, 0, len(v.Input.Pubkeys))
				for _, k := range v.Input.Pubkeys {
					keys = append(keys, unhex(t, k))
				}
				err := verifyAggregate(root, keys, unhex(t, v.Input.Signature))

				if v.Output && err != nil {
					t.Fatalf("spec says VALID, we rejected: %v", err)
				}
				if !v.Output && err == nil {
					t.Fatal("spec says INVALID, we accepted")
				}
			})
			passed++
		}
	}
	return passed
}

// Ethereum's own variant — the one the consensus layer uses.
func TestEthereumConsensusSpecFastAggregateVerify(t *testing.T) {
	n := runSuite(t, "eth_fast_aggregate_verify")
	t.Logf("%d consensus-spec eth_fast_aggregate_verify cases", n)
}

// The base BLS variant, which we deliberately do NOT implement.
//
// We implement eth_fast_aggregate_verify. The two agree on everything except
// one case, and this asserts exactly that: agreement everywhere, and a
// divergence only where the spec itself diverges. Skipping the case instead
// would hide whether we match base BLS by accident somewhere else.
func TestWeImplementTheEthereumVariantNotBaseBLS(t *testing.T) {
	const divergent = "fast_aggregate_verify_na_pubkeys_and_infinity_signature"
	agreed, diverged := 0, 0

	for _, dir := range suiteDirs(t, "fast_aggregate_verify") {
		for name, v := range loadVectors(t, dir) {
			var root Root
			msg := unhex(t, v.Input.Message)
			if len(msg) != 32 {
				continue
			}
			copy(root[:], msg)
			keys := make([][]byte, 0, len(v.Input.Pubkeys))
			for _, k := range v.Input.Pubkeys {
				keys = append(keys, unhex(t, k))
			}
			weAccept := verifyAggregate(root, keys, unhex(t, v.Input.Signature)) == nil

			if dir == divergent {
				// The documented divergence: base BLS says false, Ethereum says
				// true, and we follow Ethereum.
				if v.Output {
					t.Errorf("%s: base BLS is expected to REJECT this", name)
				}
				if !weAccept {
					t.Errorf("%s: we should follow Ethereum and ACCEPT it", name)
				}
				diverged++
				continue
			}
			if weAccept != v.Output {
				t.Errorf("%s/%s: base says %v, we say %v — an undocumented divergence",
					dir, name, v.Output, weAccept)
			}
			agreed++
		}
	}
	if diverged != 1 {
		t.Errorf("expected exactly one documented divergence, saw %d", diverged)
	}
	t.Logf("base BLS: %d cases agree, %d documented divergence", agreed, diverged)
}

// THE CASE THE WHOLE EVALUATION TURNED ON.
//
// Called out on its own so that if the KeyValidate loop is ever removed as a
// redundant optimisation, the failure names itself rather than appearing as one
// anonymous case among twenty-four.
func TestTheInfinityPubkeyVectorIsRejected(t *testing.T) {
	for _, suite := range []string{
		"eth_fast_aggregate_verify_infinity_pubkey",
		"fast_aggregate_verify_infinity_pubkey",
	} {
		vectors := loadVectors(t, suite)
		for name, v := range vectors {
			var root Root
			copy(root[:], unhex(t, v.Input.Message))
			keys := make([][]byte, 0, len(v.Input.Pubkeys))
			for _, k := range v.Input.Pubkeys {
				keys = append(keys, unhex(t, k))
			}
			err := verifyAggregate(root, keys, unhex(t, v.Input.Signature))

			t.Logf("%s/%s: spec output=%v, we returned err=%v", suite, name, v.Output, err)
			if v.Output {
				t.Errorf("%s: the spec accepts an infinity pubkey here?", suite)
			}
			if err == nil {
				t.Fatalf("%s: an infinity public key was ACCEPTED — the KeyValidate "+
					"loop in verifyAggregate is missing or was removed", suite)
			}
		}
	}
}

// The DST must be Ethereum's exactly. A valid vector under a different DST must
// fail, or we are verifying signatures from some other protocol.
func TestTheDSTIsEthereumsExactly(t *testing.T) {
	if want := "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"; string(EthereumDST) != want {
		t.Fatalf("DST is %q, want %q", EthereumDST, want)
	}
	// A known-valid vector must stop verifying if the DST changes.
	for _, dir := range suiteDirs(t, "eth_fast_aggregate_verify_valid") {
		for _, v := range loadVectors(t, dir) {
			if !v.Output {
				continue
			}
			var root Root
			copy(root[:], unhex(t, v.Input.Message))
			keys := make([][]byte, 0, len(v.Input.Pubkeys))
			for _, k := range v.Input.Pubkeys {
				keys = append(keys, unhex(t, k))
			}
			if err := verifyAggregate(root, keys, unhex(t, v.Input.Signature)); err != nil {
				t.Fatalf("a valid vector did not verify under our DST: %v", err)
			}
			return // one is enough to establish the DST is right
		}
	}
}

// The empty-set special case must NEVER reach the sync committee layer.
//
// eth_fast_aggregate_verify says empty pubkeys plus the infinity signature is
// valid. That is correct for the primitive and meaningless for a sync
// committee, where it would mean "nobody attested, therefore verified". These
// assert the guards that keep it contained.
func TestTheEmptySetSpecialCaseCannotReachTheCommitteeLayer(t *testing.T) {
	infinitySig := make([]byte, BLSSignatureBytes)
	infinitySig[0] = 0xC0

	// The primitive: spec-exact.
	if err := verifyAggregate(Root{}, nil, infinitySig); err != nil {
		t.Fatalf("the primitive must match eth_fast_aggregate_verify: %v", err)
	}

	// The committee layer: refuses on participation BEFORE it validates keys,
	// so a synthetic committee is fine here — reaching KeyValidate at all would
	// itself be the bug.
	v := NewBLSVerifier()
	empty := make(Participation, SyncCommitteeSize/8)
	err := v.VerifySyncCommitteeSignature(Root{}, committee(0xAA), empty, infinitySig)
	if !errorsIs(err, ErrNoParticipants) {
		t.Fatalf("the committee layer returned %v, want ErrNoParticipants", err)
	}

	// And the structural layer refuses long before that, on the 2/3 threshold.
	s := &LightClientState{
		FinalizedHeader: BeaconBlockHeader{Slot: 1}, CurrentCommittee: committee(0xAA),
		Checkpoint: goodCheckpoint(),
	}
	u := &Update{
		FinalizedHeader: BeaconBlockHeader{Slot: 2},
		AttestedHeader:  BeaconBlockHeader{Slot: 3},
		SignatureSlot:   4, Participation: empty, Signature: infinitySig,
	}
	if err := s.ValidateStructure(u); !errorsIs(err, ErrInsufficientParticipation) {
		t.Fatalf("structural validation returned %v, want ErrInsufficientParticipation", err)
	}
}

// A non-infinity signature with no keys is still a rejection.
func TestAnEmptySetWithARealSignatureIsRejected(t *testing.T) {
	sig := make([]byte, BLSSignatureBytes)
	sig[0] = 0xA0 // compressed, not infinity
	if err := verifyAggregate(Root{}, nil, sig); err == nil {
		t.Fatal("an empty key set with a non-infinity signature was accepted")
	}
}

func errorsIs(err, target error) bool { return errors.Is(err, target) }
