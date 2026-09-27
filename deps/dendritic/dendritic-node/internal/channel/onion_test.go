package channel

import (
	"errors"
	"testing"
)

func route() ([]HopInstruction, [][32]byte, [32]byte) {
	hops := []HopInstruction{
		{NextHop: "middle", OutgoingCommitment: Commitment{1}, FeeCommitment: Commitment{9}, OutgoingExpiry: 300},
		{NextHop: "exit", OutgoingCommitment: Commitment{2}, FeeCommitment: Commitment{9}, OutgoingExpiry: 200},
		{BlindedEndpoint: "blinded:xyz", OutgoingCommitment: Commitment{3}, FeeCommitment: Commitment{9}, OutgoingExpiry: 100},
	}
	secrets := [][32]byte{{0xa1}, {0xb2}, {0xc3}}
	return hops, secrets, [32]byte{0xee}
}

func TestEachHopReadsOnlyItsOwnInstruction(t *testing.T) {
	hops, secrets, eph := route()
	p, err := Build(eph, hops, secrets)
	if err != nil {
		t.Fatal(err)
	}
	for i := range hops {
		got, err := p.Peel(secrets[i])
		if err != nil {
			t.Fatalf("hop %d could not peel: %v", i, err)
		}
		if got.NextHop != hops[i].NextHop || got.OutgoingExpiry != hops[i].OutgoingExpiry {
			t.Errorf("hop %d got the wrong instruction: %+v", i, got)
		}
	}
}

// A router must not be able to read another hop's layer — that is the whole
// point, and it is the assertion that fails first if the keying is wrong.
func TestAStrangerLearnsNothing(t *testing.T) {
	hops, secrets, eph := route()
	p, _ := Build(eph, hops, secrets)
	if _, err := p.Peel([32]byte{0xff}); !errors.Is(err, ErrNotForUs) {
		t.Fatalf("an unrelated key peeled a layer: %v", err)
	}
}

// Size must not depend on route length: a two-hop route must be
// indistinguishable from a three-hop one, or the hop count leaks.
func TestPacketSizeIsConstantWhateverTheRouteLength(t *testing.T) {
	hops, secrets, eph := route()
	three, _ := Build(eph, hops, secrets)
	two, err := Build(eph, hops[:2], secrets[:2])
	if err != nil {
		t.Fatal(err)
	}
	one, err := Build(eph, hops[:1], secrets[:1])
	if err != nil {
		t.Fatal(err)
	}
	if three.Size() != two.Size() || two.Size() != one.Size() {
		t.Fatalf("sizes differ by route length: 1=%d 2=%d 3=%d",
			one.Size(), two.Size(), three.Size())
	}
	if len(three.Slots) != MaxHops || len(one.Slots) != MaxHops {
		t.Error("slot count varies with route length")
	}
}

// Every slot must be the same length, or a slot's size says which it is.
func TestAllSlotsAreTheSameSize(t *testing.T) {
	hops, secrets, eph := route()
	p, _ := Build(eph, hops, secrets)
	first := len(p.Slots[0])
	for i, s := range p.Slots {
		if len(s) != first {
			t.Errorf("slot %d is %d bytes, slot 0 is %d", i, len(s), first)
		}
	}
}

// Instructions of very different sizes must still produce equal slots — the
// exit carries a blinded endpoint the others do not.
func TestSlotSizeIsIndependentOfInstructionSize(t *testing.T) {
	hops, secrets, eph := route()
	hops[0].BlindedEndpoint = ""
	hops[2].BlindedEndpoint = "a-very-much-longer-blinded-endpoint-value-than-the-others"
	p, err := Build(eph, hops, secrets)
	if err != nil {
		t.Fatal(err)
	}
	first := len(p.Slots[0])
	for i, s := range p.Slots {
		if len(s) != first {
			t.Errorf("slot %d leaks its content size", i)
		}
	}
}

// Position must not be readable from slot index. Across many ephemeral keys the
// entry hop should land in every slot, not a fixed one.
func TestSlotAssignmentIsPermutedPerPayment(t *testing.T) {
	hops, secrets, _ := route()
	seen := map[int]bool{}
	for i := 0; i < 60; i++ {
		eph := [32]byte{byte(i), byte(i >> 8), 0x5a}
		p, err := Build(eph, hops, secrets)
		if err != nil {
			t.Fatal(err)
		}
		for slot := range p.Slots {
			if _, ok := open(hopKey(secrets[0]), p.Slots[slot]); ok {
				seen[slot] = true
			}
		}
	}
	if len(seen) < 2 {
		t.Fatalf("the entry hop always occupies the same slot(s): %v — position leaks", seen)
	}
}

// Expiries must strictly decrease, so an upstream lock always outlives the
// downstream one it depends on.
func TestExpiriesMustStrictlyDecrease(t *testing.T) {
	hops, secrets, eph := route()
	hops[1].OutgoingExpiry = hops[0].OutgoingExpiry
	if _, err := Build(eph, hops, secrets); !errors.Is(err, ErrExpiryOrdering) {
		t.Fatalf("accepted non-decreasing expiries: %v", err)
	}
	hops[1].OutgoingExpiry = hops[0].OutgoingExpiry + 1
	if _, err := Build(eph, hops, secrets); !errors.Is(err, ErrExpiryOrdering) {
		t.Fatal("accepted an increasing expiry")
	}
}

// A packet replayed under a different ephemeral key must fail, or a captured
// packet can be re-sent down the same route.
func TestReplayUnderANewEphemeralKeyIsRejected(t *testing.T) {
	hops, secrets, eph := route()
	p, _ := Build(eph, hops, secrets)
	p.EphemeralPublicKey = [32]byte{0x01} // as an attacker would rewrite it
	if _, err := p.Peel(secrets[0]); err == nil {
		t.Fatal("a packet with a swapped ephemeral key still peeled")
	}
}

// Tampering with a slot must be detected, not produce a mangled instruction a
// router then acts on.
func TestTamperedSlotsAreRejected(t *testing.T) {
	hops, secrets, eph := route()
	p, _ := Build(eph, hops, secrets)
	for i := range p.Slots {
		p.Slots[i][len(p.Slots[i])/2] ^= 0x01
	}
	if _, err := p.Peel(secrets[0]); !errors.Is(err, ErrNotForUs) {
		t.Fatalf("a tampered packet was accepted: %v", err)
	}
}

// Replay guards must differ per hop. One value shared across hops would be a
// correlation handle by construction.
func TestReplayGuardsDifferPerHop(t *testing.T) {
	hops, secrets, eph := route()
	p, _ := Build(eph, hops, secrets)
	seen := map[[32]byte]bool{}
	for i := range hops {
		got, err := p.Peel(secrets[i])
		if err != nil {
			t.Fatal(err)
		}
		if seen[got.ReplayGuard] {
			t.Fatal("two hops share a replay guard — it is a route identifier")
		}
		seen[got.ReplayGuard] = true
	}
}

func TestRouteLongerThanTheFormatIsRefused(t *testing.T) {
	hops, secrets, eph := route()
	long := append(append([]HopInstruction{}, hops...), hops[0])
	longSecrets := append(append([][32]byte{}, secrets...), [32]byte{0xd4})
	if _, err := Build(eph, long, longSecrets); !errors.Is(err, ErrTooManyHops) {
		t.Fatal("accepted a route longer than the packet format allows")
	}
}

func TestOversizedInstructionIsRefusedNotTruncated(t *testing.T) {
	hops, secrets, eph := route()
	big := make([]byte, SlotSize*2)
	for i := range big {
		big[i] = 'x'
	}
	hops[0].BlindedEndpoint = string(big)
	if _, err := Build(eph, hops, secrets); !errors.Is(err, ErrHopTooLarge) {
		t.Fatalf("an oversized instruction was not refused: %v", err)
	}
}

// Failure messages travel back encrypted, so an error does not announce where
// it came from — "insufficient liquidity" names a stranger's balance.
func TestFailureMessagesAreEncryptedPerHop(t *testing.T) {
	_, secrets, _ := route()
	sealed, err := SealFailure(secrets[2], "insufficient liquidity")
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := OpenFailure(secrets[2], sealed); !ok || got != "insufficient liquidity" {
		t.Fatalf("round trip failed: %q ok=%v", got, ok)
	}
	if _, ok := OpenFailure(secrets[0], sealed); ok {
		t.Error("another hop read a failure message not addressed to it")
	}
}

func TestEmptyRouteIsRefused(t *testing.T) {
	if _, err := Build([32]byte{1}, nil, nil); err == nil {
		t.Fatal("built a packet for an empty route")
	}
}
