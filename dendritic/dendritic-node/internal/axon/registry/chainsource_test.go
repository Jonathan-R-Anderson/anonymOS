package registry

import (
	"context"
	"errors"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/resolver"
	"github.com/syndichan/maniwani/storage-client/internal/ethproof"
)

// ChainReader must be usable as the resolver's slow-path ChainSource.
var _ resolver.ChainSource = (*ChainReader)(nil)

type fakeState struct {
	root  [32]byte
	block uint64
	chain uint64
	err   error
}

func (f *fakeState) AuthenticatedStateRoot(context.Context) ([32]byte, uint64, error) {
	return f.root, f.block, f.err
}
func (f *fakeState) ChainID() uint64 { return f.chain }

// capturingProofs records the slots it was asked to prove, then fails. It lets
// a test assert WHICH slots ChainReader reads without needing real proofs --
// and the slots are the catastrophic-if-wrong part, because a wrong slot reads
// an unrelated word of mainnet storage.
type capturingProofs struct {
	slots []([32]byte)
}

func (c *capturingProofs) AccountAndSlots(_ context.Context, _ [20]byte, slots [][32]byte, _ uint64) ([][]byte, [][][]byte, error) {
	c.slots = append([]([32]byte){}, slots...)
	return nil, nil, errors.New("capturing proof source: no proofs served")
}

// TestReadsTheSolcConfirmedSlots pins stateOf=8 and domainKey=(base slot 1)+1.
//
// THESE THREE NUMBERS ARE THE WHOLE RISK. AxonRegistry inherits Ownable, whose
// _owner takes slot 0, so the mappings do not start where reading the .sol would
// suggest; the values are what `solc --storage-layout` reported and the struct
// member layout it reported (owner/expiresAt/version pack into struct slot 0, so
// domainKey is struct slot 1). If any of 8, 1, or the +1 offset is wrong, a
// mainnet read returns an unrelated word and the resolver believes a lie. This
// asserts ChainReader asks for exactly those slots.
func TestReadsTheSolcConfirmedSlots(t *testing.T) {
	var nameHash [32]byte
	for i := range nameHash {
		nameHash[i] = byte(i + 1)
	}

	cap := &capturingProofs{}
	cr := &ChainReader{
		Registry: [20]byte{0x5b}, ChainID: 1,
		State:  &fakeState{block: 100, chain: 1},
		Proofs: cap,
	}
	_, _, err := cr.Resolve(context.Background(), nameHash)
	if err == nil {
		t.Fatal("expected an error from the capturing proof source")
	}
	if len(cap.slots) != 2 {
		t.Fatalf("asked for %d slots, want 2 (stateOf, domainKey)", len(cap.slots))
	}

	wantState := ethproof.StorageSlotKey(nameHash, 8)                   // stateOf slot 8
	wantKey := ethproof.SlotAt(ethproof.StorageSlotKey(nameHash, 1), 1) // _names slot 1, struct +1
	if cap.slots[0] != wantState {
		t.Errorf("stateOf slot = %x, want StorageSlotKey(nameHash, 8) = %x", cap.slots[0], wantState)
	}
	if cap.slots[1] != wantKey {
		t.Errorf("domainKey slot = %x, want SlotAt(StorageSlotKey(nameHash,1),1) = %x", cap.slots[1], wantKey)
	}
}

// TestUnverifiableWithoutASource: no state or proof source means fail closed,
// never resolve on no evidence.
func TestUnverifiableWithoutASource(t *testing.T) {
	nh := [32]byte{1}
	for _, cr := range []*ChainReader{
		{Registry: [20]byte{0x5b}, ChainID: 1, State: nil, Proofs: &capturingProofs{}},
		{Registry: [20]byte{0x5b}, ChainID: 1, State: &fakeState{}, Proofs: nil},
		nil,
	} {
		if cr.Authenticated() {
			t.Error("a reader with a missing source reported Authenticated")
		}
		if _, _, err := cr.Resolve(context.Background(), nh); !errors.Is(err, ErrUnverifiable) {
			t.Errorf("missing source: err = %v, want ErrUnverifiable", err)
		}
	}
}

// TestUnverifiableWhenTheLightClientHasNoRoot: an RPC that cannot produce a
// verified root has not produced an unverified one -- resolution fails rather
// than proceeding on nothing.
func TestUnverifiableWhenTheLightClientHasNoRoot(t *testing.T) {
	cr := &ChainReader{
		Registry: [20]byte{0x5b}, ChainID: 1,
		State:  &fakeState{err: errors.New("no sync committee yet")},
		Proofs: &capturingProofs{},
	}
	if cr.Authenticated() {
		t.Error("Authenticated is true while the light client has no root")
	}
	if _, _, err := cr.Resolve(context.Background(), [32]byte{1}); !errors.Is(err, ErrUnverifiable) {
		t.Errorf("no root: err = %v, want ErrUnverifiable", err)
	}
}

func TestNameStateString(t *testing.T) {
	for s, want := range map[NameState]string{
		StateActive: "ACTIVE", StatePruned: "PRUNED",
		StateSeized: "SEIZED", StateRecyclable: "RECYCLABLE",
	} {
		if s.String() != want {
			t.Errorf("NameState(%d).String() = %q, want %q", s, s.String(), want)
		}
	}
}
