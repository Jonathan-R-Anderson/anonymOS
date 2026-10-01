package ethproof

// The trust anchor — roadmap P12-5.1.
//
// The anchor is the one subjective input in the whole design. These tests are
// about confining that subjectivity: it must be complete, attributable, and
// impossible to change once a session has started trusting it.

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func goodCheckpoint() Checkpoint {
	c := Checkpoint{
		Slot:                  12_000_000,
		GenesisValidatorsRoot: MainnetGenesisValidatorsRoot,
		ForkVersion:           [4]byte{0x05, 0x00, 0x00, 0x00},
		Source:                "compared against three explorers by hand",
		Note:                  "operator-verified",
	}
	c.BlockRoot[0], c.SyncCommitteeRoot[0] = 0xAA, 0xBB
	return c
}

// An anchor that does not say enough anchors nothing.
func TestAnIncompleteCheckpointIsRefused(t *testing.T) {
	cases := map[string]func(*Checkpoint){
		"no block root":     func(c *Checkpoint) { c.BlockRoot = Root{} },
		"no committee root": func(c *Checkpoint) { c.SyncCommitteeRoot = Root{} },
		"no genesis root":   func(c *Checkpoint) { c.GenesisValidatorsRoot = Root{} },
		"no fork version":   func(c *Checkpoint) { c.ForkVersion = [4]byte{} },
		"no source":         func(c *Checkpoint) { c.Source = "  " },
	}
	for name, break_ := range cases {
		c := goodCheckpoint()
		break_(&c)
		if err := c.Validate(); !errors.Is(err, ErrCheckpointIncomplete) {
			t.Errorf("%s: got %v, want ErrCheckpointIncomplete", name, err)
		}
	}
	if err := goodCheckpoint().Validate(); err != nil {
		t.Fatalf("a complete checkpoint was refused: %v", err)
	}
}

// The committee root is required for a specific reason: without it, the first
// update supplies both the committee and its own authorisation.
func TestTheMissingCommitteeRootSaysWhyItMatters(t *testing.T) {
	c := goodCheckpoint()
	c.SyncCommitteeRoot = Root{}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "its own authorisation") {
		t.Errorf("the refusal does not explain the circularity: %v", err)
	}
}

// An anchor that can be replaced is not an anchor.
func TestASealedAnchorCannotBeReplaced(t *testing.T) {
	var a SealedAnchor
	if err := a.Seal(goodCheckpoint()); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	other := goodCheckpoint()
	other.BlockRoot[0] = 0xEE

	if err := a.Seal(other); !errors.Is(err, ErrAnchorSealed) {
		t.Fatalf("re-sealing returned %v, want ErrAnchorSealed", err)
	}
	got, ok := a.Checkpoint()
	if !ok || got.BlockRoot[0] != 0xAA {
		t.Error("the anchor was replaced")
	}
}

func TestAnInvalidCheckpointCannotBeSealed(t *testing.T) {
	var a SealedAnchor
	if err := a.Seal(Checkpoint{}); err == nil {
		t.Fatal("an empty checkpoint was sealed")
	}
	if _, ok := a.Checkpoint(); ok {
		t.Error("a refused checkpoint was retained")
	}
}

// The mainnet genesis validators root is a published constant and the one value
// that distinguishes mainnet's signing domain from every testnet's.
func TestTheMainnetGenesisRootIsThePublishedConstant(t *testing.T) {
	want := "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95"
	if got := hex.EncodeToString(MainnetGenesisValidatorsRoot[:]); got != want {
		t.Fatalf("genesis validators root = %s, want %s", got, want)
	}
}

// ---- the signing domain -----------------------------------------------------

// A signature must not verify across chains or forks. The domain is what binds
// it, so both inputs must change it.
func TestTheDomainBindsToChainAndFork(t *testing.T) {
	base := goodCheckpoint()
	baseDomain, err := base.ComputeDomain()
	if err != nil {
		t.Fatalf("ComputeDomain: %v", err)
	}

	otherChain := base
	otherChain.GenesisValidatorsRoot[0] ^= 0xFF
	otherDomain, err := otherChain.ComputeDomain()
	if err != nil {
		t.Fatalf("ComputeDomain: %v", err)
	}
	if otherDomain == baseDomain {
		t.Error("a different genesis root produced the same domain; a signature " +
			"from another chain would verify here")
	}

	otherFork := base
	otherFork.ForkVersion[0] ^= 0xFF
	forkDomain, err := otherFork.ComputeDomain()
	if err != nil {
		t.Fatalf("ComputeDomain: %v", err)
	}
	if forkDomain == baseDomain {
		t.Error("a different fork version produced the same domain")
	}
}

// DOMAIN_SYNC_COMMITTEE is 0x07000000 and occupies the first four bytes.
func TestTheDomainCarriesTheSyncCommitteeType(t *testing.T) {
	d, err := goodCheckpoint().ComputeDomain()
	if err != nil {
		t.Fatalf("ComputeDomain: %v", err)
	}
	if d[0] != 0x07 || d[1] != 0 || d[2] != 0 || d[3] != 0 {
		t.Errorf("domain type is %x, want 07000000", d[:4])
	}
}

// The signing root binds the header to the domain. Signing a bare header root
// would let the signature be replayed anywhere the containers match.
func TestTheSigningRootBindsTheHeaderToTheDomain(t *testing.T) {
	var headerRoot Root
	headerRoot[0] = 0x42
	domain, err := goodCheckpoint().ComputeDomain()
	if err != nil {
		t.Fatalf("ComputeDomain: %v", err)
	}
	signing, err := SigningRoot(headerRoot, domain)
	if err != nil {
		t.Fatalf("SigningRoot: %v", err)
	}
	if signing == headerRoot {
		t.Fatal("the signing root is the bare header root; the domain does nothing")
	}
	// A different domain must produce a different signing root for one header.
	var otherDomain Root
	otherDomain[0] = 0x07
	otherDomain[5] = 0x99
	other, err := SigningRoot(headerRoot, otherDomain)
	if err != nil {
		t.Fatalf("SigningRoot: %v", err)
	}
	if other == signing {
		t.Error("the domain does not affect the signing root")
	}
}

// An operator compares the block root against explorers by hand; a rendering
// they cannot read defeats that.
func TestTheCheckpointRendersForAHuman(t *testing.T) {
	text := goodCheckpoint().String()
	for _, want := range []string{"slot 12000000", "block root", "committee", "source"} {
		if !strings.Contains(text, want) {
			t.Errorf("the rendering is missing %q:\n%s", want, text)
		}
	}
}
