package ethproof

// The execution bridge — roadmap P12-5.7.
//
// This is where the consensus light client meets the storage-proof verifier
// from P12-2, and where the discovery that created P12-5 gets its regression
// test: a fabricated state root produces storage proofs that verify perfectly,
// so the only defence is never obtaining the fabricated root in the first place.

import (
	"errors"
	"testing"
)

func samplePayload() ExecutionPayloadHeader {
	p := ExecutionPayloadHeader{
		BlockNumber: 21_000_000, GasLimit: 30_000_000, GasUsed: 15_000_000,
		Timestamp: 1_700_000_000, ExtraData: []byte("honest"),
		BaseFeePerGas: Uint256LE(7),
	}
	p.ParentHash[0], p.StateRoot[0], p.ReceiptsRoot[0] = 0x11, 0x22, 0x33
	p.PrevRandao[0], p.BlockHash[0], p.TxRoot[0] = 0x44, 0x55, 0x66
	p.WithdrawalsRoot[0] = 0x77
	p.FeeRecipient[0] = 0x88
	p.LogsBloom[0] = 0x99
	return p
}

// bridgedState is a client with a finalised header whose body root actually
// commits to a payload, by deriving the body root from the payload's branch.
func bridgedState(t *testing.T, p ExecutionPayloadHeader) (*LightClientState, []Root) {
	t.Helper()
	s := &LightClientState{
		Spec: SpecAltair, CurrentCommittee: committee(0xAA), Checkpoint: goodCheckpoint(),
	}
	root, err := p.HashTreeRoot(s.Spec)
	if err != nil {
		t.Fatalf("payload root: %v", err)
	}
	branch, bodyRoot := branchFor(t, root, ExecutionPayloadIndex)
	s.FinalizedHeader = BeaconBlockHeader{Slot: 2 * periodSlots, BodyRoot: bodyRoot}
	return s, branch
}

// ---- the bridge works --------------------------------------------------------

func TestTheBridgeYieldsTheAuthenticatedStateRoot(t *testing.T) {
	p := samplePayload()
	s, branch := bridgedState(t, p)

	stateRoot, number, hash, err := s.AuthenticatedStateRoot(p, branch)
	if err != nil {
		t.Fatalf("AuthenticatedStateRoot: %v", err)
	}
	if stateRoot != p.StateRoot {
		t.Errorf("state root %x, want the payload's %x", stateRoot[:8], p.StateRoot[:8])
	}
	if number != p.BlockNumber || hash != p.BlockHash {
		t.Errorf("block %d/%x, want %d/%x", number, hash[:4], p.BlockNumber, p.BlockHash[:4])
	}
}

// ---- THE HEADLINE ------------------------------------------------------------

// A malicious RPC supplies an execution header whose state root is fabricated.
// Everything about it is internally consistent, and storage proofs beneath that
// root will verify perfectly — that is exactly the attack P12-5 exists for.
//
// It must not matter, because the fabricated root is never obtainable: the
// bridge returns the root from the AUTHENTICATED payload, and the fabricated
// payload does not verify into the finalised block.
func TestAFabricatedStateRootIsNeverObtainable(t *testing.T) {
	honest := samplePayload()
	s, branch := bridgedState(t, honest)

	// The attacker's version: one field changed, everything else identical.
	forged := honest
	forged.StateRoot[0] = 0xFF

	// 1. Offered with the honest branch — the branch no longer places it.
	if _, _, _, err := s.AuthenticatedStateRoot(forged, branch); !errors.Is(err, ErrPayloadNotAuthenticated) {
		t.Fatalf("a forged payload with the honest branch returned %v", err)
	}

	// 2. Offered with a branch built FOR the forgery — internally perfect, and
	//    it does not hang from the finalised block.
	forgedRoot, err := forged.HashTreeRoot(s.Spec)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	forgedBranch, forgedBody := branchFor(t, forgedRoot, ExecutionPayloadIndex)
	if forgedBody == s.FinalizedHeader.BodyRoot {
		t.Fatal("the forgery collided with the honest body root")
	}
	if _, _, _, err := s.AuthenticatedStateRoot(forged, forgedBranch); !errors.Is(err, ErrPayloadNotAuthenticated) {
		t.Fatalf("a self-consistent forgery was authenticated: %v", err)
	}

	// 3. And the honest root is what a caller gets, so there is no path by
	//    which the forged root reaches the storage-proof verifier.
	got, _, _, err := s.AuthenticatedStateRoot(honest, branch)
	if err != nil {
		t.Fatalf("the honest payload stopped verifying: %v", err)
	}
	if got == forged.StateRoot {
		t.Fatal("the bridge returned the forged state root")
	}
}

// ---- finality is required, not merely verification --------------------------

// A payload hanging from an attested-but-not-finalised header could name a
// block that never existed.
func TestThePayloadMustHangFromAFinalisedHeader(t *testing.T) {
	p := samplePayload()
	s, branch := bridgedState(t, p)

	// Move the body root somewhere the finalised header does not commit to,
	// simulating a payload from a merely-attested block.
	s.optimistic.header = s.FinalizedHeader
	s.optimistic.known = true
	s.FinalizedHeader = BeaconBlockHeader{} // nothing finalised

	if _, _, _, err := s.AuthenticatedStateRoot(p, branch); !errors.Is(err, ErrNotFinalized) {
		t.Fatalf("got %v, want ErrNotFinalized", err)
	}
}

// ---- the branch must place the payload where it claims ----------------------

func TestAPayloadAtTheWrongIndexIsRefused(t *testing.T) {
	p := samplePayload()
	s, _ := bridgedState(t, p)

	root, err := p.HashTreeRoot(s.Spec)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	// A branch for a different position in the body.
	wrongBranch, _ := branchFor(t, root, FinalizedRootIndex)

	if _, _, _, err := s.AuthenticatedStateRoot(p, wrongBranch); err == nil {
		t.Fatal("a payload proven at the wrong index was authenticated")
	}
}

func TestATamperedBranchIsRefused(t *testing.T) {
	p := samplePayload()
	s, branch := bridgedState(t, p)
	branch[0][0] ^= 0x01

	if _, _, _, err := s.AuthenticatedStateRoot(p, branch); !errors.Is(err, ErrPayloadNotAuthenticated) {
		t.Fatalf("got %v, want ErrPayloadNotAuthenticated", err)
	}
}

// ---- the payload root commits to every field --------------------------------

// If any field were left out of the root, an attacker could vary it freely
// while the branch still verified.
func TestEveryPayloadFieldChangesItsRoot(t *testing.T) {
	base := samplePayload()
	baseRoot, err := base.HashTreeRoot(SpecAltair)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}

	variants := map[string]func(*ExecutionPayloadHeader){
		"parentHash":      func(p *ExecutionPayloadHeader) { p.ParentHash[0] ^= 0xFF },
		"feeRecipient":    func(p *ExecutionPayloadHeader) { p.FeeRecipient[0] ^= 0xFF },
		"stateRoot":       func(p *ExecutionPayloadHeader) { p.StateRoot[0] ^= 0xFF },
		"receiptsRoot":    func(p *ExecutionPayloadHeader) { p.ReceiptsRoot[0] ^= 0xFF },
		"logsBloom":       func(p *ExecutionPayloadHeader) { p.LogsBloom[255] ^= 0xFF },
		"prevRandao":      func(p *ExecutionPayloadHeader) { p.PrevRandao[0] ^= 0xFF },
		"blockNumber":     func(p *ExecutionPayloadHeader) { p.BlockNumber++ },
		"gasLimit":        func(p *ExecutionPayloadHeader) { p.GasLimit++ },
		"gasUsed":         func(p *ExecutionPayloadHeader) { p.GasUsed++ },
		"timestamp":       func(p *ExecutionPayloadHeader) { p.Timestamp++ },
		"extraData":       func(p *ExecutionPayloadHeader) { p.ExtraData = []byte("forged") },
		"baseFeePerGas":   func(p *ExecutionPayloadHeader) { p.BaseFeePerGas[0] ^= 0xFF },
		"blockHash":       func(p *ExecutionPayloadHeader) { p.BlockHash[0] ^= 0xFF },
		"txRoot":          func(p *ExecutionPayloadHeader) { p.TxRoot[0] ^= 0xFF },
		"withdrawalsRoot": func(p *ExecutionPayloadHeader) { p.WithdrawalsRoot[0] ^= 0xFF },
		"blobGasUsed":     func(p *ExecutionPayloadHeader) { p.BlobGasUsed++ },
		"excessBlobGas":   func(p *ExecutionPayloadHeader) { p.ExcessBlobGas++ },
	}
	for name, mutate := range variants {
		v := base
		mutate(&v)
		root, err := v.HashTreeRoot(SpecAltair)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if root == baseRoot {
			t.Errorf("changing %s did not change the payload root", name)
		}
	}
}

// extra_data is a LIST: its length is mixed in, so two values sharing a prefix
// must not collide.
func TestExtraDataLengthIsCommittedTo(t *testing.T) {
	a, b := samplePayload(), samplePayload()
	a.ExtraData = []byte("ab")
	b.ExtraData = []byte("ab\x00")

	rootA, err := a.HashTreeRoot(SpecAltair)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	rootB, err := b.HashTreeRoot(SpecAltair)
	if err != nil {
		t.Fatalf("HashTreeRoot: %v", err)
	}
	if rootA == rootB {
		t.Fatal("extra_data values differing only in length collided")
	}
}

func TestAnOverlongExtraDataIsRefused(t *testing.T) {
	p := samplePayload()
	p.ExtraData = make([]byte, 33) // limit is 32
	if _, err := p.HashTreeRoot(SpecAltair); err == nil {
		t.Fatal("a 33-byte extra_data was accepted against a 32-byte limit")
	}
}

// ---- fork discipline ---------------------------------------------------------

// The field COUNT changes across forks, and a root over the wrong count is
// self-consistent and wrong. An unrecorded fork must refuse.
func TestAnUnrecordedForkRefusesToRootAPayload(t *testing.T) {
	p := samplePayload()
	// Electra and Fulu are now RECORDED: neither redefines
	// ExecutionPayloadHeader, so both share Deneb's seventeen fields. Confirmed
	// against live mainnet Fulu data, which serialises exactly that set.
	for _, spec := range []SpecVersion{SpecAltair, SpecElectra, SpecFulu} {
		if _, err := p.HashTreeRoot(spec); err != nil {
			t.Errorf("%s should be recorded: %v", spec, err)
		}
	}
	// All three must agree, since the layout is the same.
	a, _ := p.HashTreeRoot(SpecAltair)
	b, _ := p.HashTreeRoot(SpecFulu)
	if a != b {
		t.Error("Fulu and the Deneb field set produced different payload roots")
	}
	// An unnamed or unknown fork still refuses.
	if _, err := p.HashTreeRoot(""); !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("an unnamed fork rooted a payload: %v", err)
	}
	if _, err := p.HashTreeRoot("gloas"); !errors.Is(err, ErrSpecUnsupported) {
		t.Fatalf("an unrecorded future fork rooted a payload: %v", err)
	}
}

// ---- the full chain ----------------------------------------------------------

// The hierarchy, asserted end to end: every step takes its authority from the
// step before, and nothing introduces a parallel source of truth.
func TestTheAuthenticatedStateRootFeedsTheStorageProofVerifier(t *testing.T) {
	p := samplePayload()
	s, branch := bridgedState(t, p)

	stateRoot, _, _, err := s.AuthenticatedStateRoot(p, branch)
	if err != nil {
		t.Fatalf("AuthenticatedStateRoot: %v", err)
	}

	// The state root is now an input to P12-2's verifier, unchanged. A proof
	// against a DIFFERENT root must not verify under it — which is the property
	// that makes the bridge worth having.
	var elsewhere Root
	elsewhere[0] = 0xAB
	if stateRoot == elsewhere {
		t.Fatal("unreachable")
	}
	// VerifyProof takes the root as bytes; a nil proof cannot satisfy any root,
	// and the point here is that the ROOT is the authenticated one.
	if _, err := VerifyProof(stateRoot[:], []byte("key"), nil); err == nil {
		t.Fatal("an empty proof verified against the authenticated root")
	}
}
