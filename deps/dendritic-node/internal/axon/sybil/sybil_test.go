package sybil

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"net/netip"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
	"github.com/syndichan/maniwani/storage-client/internal/axon/peer"
)

// ---------------------------------------------------------------------------
// Bond verification
// ---------------------------------------------------------------------------

// fakeState is a light client stand-in. It hands out a root it was given.
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

// hostileProofs is a provider that answers with garbage. It is the adversary
// T14.2 names: a provider that would like the node to believe a bond exists.
type hostileProofs struct{ calls int }

func (h *hostileProofs) AccountAndSlots(context.Context, Address, [][32]byte, uint64) ([][]byte, [][][]byte, error) {
	h.calls++
	// Well-formed-looking nonsense: the shape is right and nothing hashes to
	// the root. A verifier that checked shape rather than proof would pass it.
	return [][]byte{{0x80}}, [][][]byte{{{0x80}}, {{0x80}}}, nil
}

// TestT142UnverifiableProofIsNeverBelieved is T14.2.
//
// "Bond verification uses the light client's verified state root — falsified by
// any path that trusts a provider."
//
// The structural half of this is in the ProofSource interface, which returns
// proof nodes and nothing a caller could use directly. This is the behavioural
// half: a provider that answers confidently with data that does not verify gets
// nothing believed.
func TestT142UnverifiableProofIsNeverBelieved(t *testing.T) {
	state := &fakeState{root: [32]byte{1, 2, 3}, block: 1000, chain: 1}
	proofs := &hostileProofs{}
	ref := BondRef{Chain: 1, Contract: Address{0xaa}, Owner: Address{0xbb}}

	got, err := VerifyBond(context.Background(), ref, state, proofs)
	if !errors.Is(err, ErrUnverifiable) && !errors.Is(err, ErrNoBond) {
		t.Fatalf("a hostile provider produced %v (amount %v)", err, got.Amount)
	}
	if got.Amount == nil || got.Amount.Sign() != 0 {
		t.Fatalf("T14.2 violated: an unverified proof yielded amount %v", got.Amount)
	}
	if got.VerifiedAt != 0 {
		t.Fatalf("T14.2 violated: an unverified proof was stamped as verified at block %d", got.VerifiedAt)
	}
	if proofs.calls == 0 {
		t.Fatal("the proof source was never consulted -- the test is not exercising the path")
	}

	// A light client that cannot produce a root must fail closed. Admitting on
	// no evidence during a client outage is admitting during exactly the window
	// an adversary would arrange.
	broken := &fakeState{chain: 1, err: errors.New("no finalised header")}
	if _, err := VerifyBond(context.Background(), ref, broken, proofs); !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("a broken light client gave %v, want ErrUnverifiable", err)
	}

	// No state source at all is not "skip the check".
	if _, err := VerifyBond(context.Background(), ref, nil, proofs); !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("a nil state source gave %v", err)
	}
}

// TestBondOnAnotherChainIsRefused checks the chain-id guard.
//
// A bond on a chain this node does not follow is a bond this node cannot see
// slashed. Accepting it would let an adversary bond on the cheapest chain
// available and present it everywhere.
func TestBondOnAnotherChainIsRefused(t *testing.T) {
	state := &fakeState{root: [32]byte{9}, block: 5, chain: 1}
	ref := BondRef{Chain: 137, Contract: Address{0xaa}, Owner: Address{0xbb}}
	if _, err := VerifyBond(context.Background(), ref, state, &hostileProofs{}); !errors.Is(err, ErrWrongChain) {
		t.Fatalf("a foreign-chain bond gave %v", err)
	}
}

// TestT141AdmissionRefusesAbsentAndWithdrawnBonds is T14.1.
func TestT141AdmissionRefusesAbsentAndWithdrawnBonds(t *testing.T) {
	// Never verified: refused, and refused as UNVERIFIABLE rather than as
	// "no bond", so a caller that forgot to call VerifyBond learns that rather
	// than concluding the node is broke.
	if _, err := Admit(BondRef{}, RoleRelay); !errors.Is(err, ErrUnverifiable) {
		t.Fatalf("an unverified reference gave %v", err)
	}

	// Verified at zero: no bond.
	zero := BondRef{Amount: big.NewInt(0), PendingWithdraw: big.NewInt(0), VerifiedAt: 100}
	if _, err := Admit(zero, RoleRelay); !errors.Is(err, ErrNoBond) {
		t.Fatalf("a zero bond gave %v", err)
	}

	// Below the floor.
	small := BondRef{
		Amount: big.NewInt(params.BondFloorRelay - 1), PendingWithdraw: big.NewInt(0), VerifiedAt: 100,
	}
	if _, err := Admit(small, RoleRelay); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("a sub-floor bond gave %v", err)
	}

	// At the floor: admitted.
	ok := BondRef{
		Amount: big.NewInt(params.BondFloorRelay), PendingWithdraw: big.NewInt(0), VerifiedAt: 100,
	}
	withdrawing, err := Admit(ok, RoleRelay)
	if err != nil {
		t.Fatalf("a bond at the floor was refused: %v", err)
	}
	if withdrawing {
		t.Fatal("a bond with no pending withdrawal reported as withdrawing")
	}

	// Withdrawing: admitted, but REPORTED. The bond is still active and still
	// slashable, so refusing outright would be wrong; a caller about to pin a
	// 45-day guard should still be told the operator has announced an exit.
	exiting := BondRef{
		Amount:          big.NewInt(params.BondFloorRelay * 2),
		PendingWithdraw: big.NewInt(5),
		VerifiedAt:      100,
	}
	withdrawing, err = Admit(exiting, RoleRelay)
	if err != nil {
		t.Fatalf("a bond with a pending withdrawal was refused: %v", err)
	}
	if !withdrawing {
		t.Fatal("T14.1: a pending withdrawal was not reported")
	}
}

// TestE141BondFloorsAreOrderedByConsequence is E14.1's shape.
//
// The FIGURES are provisional and the test does not assert them. The ORDER is
// derived — from what a role can do to somebody else, not from what it costs to
// run — so the order is what is asserted. A later calibration pass may move
// every number; if it inverts the order it has changed the policy and should
// have to say so.
func TestE141BondFloorsAreOrderedByConsequence(t *testing.T) {
	if !(BondFloor(RoleDHT) < BondFloor(RoleRelay) &&
		BondFloor(RoleRelay) < BondFloor(RoleStorage) &&
		BondFloor(RoleStorage) < BondFloor(RoleExit)) {
		t.Fatalf("bond floors are not ordered dht < relay < storage < exit: %d %d %d %d",
			BondFloor(RoleDHT), BondFloor(RoleRelay), BondFloor(RoleStorage), BondFloor(RoleExit))
	}
	// And a node with no bond enters no consequential role at all.
	for _, r := range []Role{RoleRelay, RoleStorage, RoleDHT, RoleExit} {
		if _, err := Admit(BondRef{Amount: big.NewInt(0), VerifiedAt: 1}, r); err == nil {
			t.Fatalf("E14.1 violated: an unbonded node entered role %s", r)
		}
	}
}

// TestStaleBondMustBeReproven covers the freshness rule.
func TestStaleBondMustBeReproven(t *testing.T) {
	const blockTime = 12 * time.Second
	fresh := BondRef{Amount: big.NewInt(1000), VerifiedAt: 1000}
	if Stale(fresh, 1010, blockTime) {
		t.Fatal("a bond proven 10 blocks ago is stale")
	}
	// Freshness / 12 s = 300 blocks at one hour.
	if !Stale(fresh, 1000+400, blockTime) {
		t.Fatal("a bond proven 400 blocks (80 min) ago is not stale")
	}
	// Never proven is always stale -- never "fresh because zero is recent".
	if !Stale(BondRef{}, 1, blockTime) {
		t.Fatal("an unproven bond reported fresh")
	}
	// A chain that appears to have gone backwards is stale, not negative.
	if !Stale(fresh, 999, blockTime) {
		t.Fatal("a bond proven after the current block reported fresh")
	}
}

// ---------------------------------------------------------------------------
// Proof of work
// ---------------------------------------------------------------------------

func TestPoWBindsToItsSubjectAndExpires(t *testing.T) {
	now := time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)
	subject := []byte("node-alpha")
	c, err := NewChallenge(subject, now)
	if err != nil {
		t.Fatal(err)
	}
	c.Bits = 8 // cheap, so the test is fast; difficulty itself is measured below

	nonce, ok := c.Solve(1 << 20)
	if !ok {
		t.Fatal("could not solve an 8-bit puzzle in 2^20 tries")
	}
	if err := c.Verify(subject, nonce, now.Add(time.Minute)); err != nil {
		t.Fatalf("a valid solution was refused: %v", err)
	}

	// Another node cannot use it. Without this the puzzle is a bearer token and
	// one solution admits a fleet.
	if err := c.Verify([]byte("node-bravo"), nonce, now.Add(time.Minute)); !errors.Is(err, ErrPoWWrongSubject) {
		t.Fatalf("a solution bound to one subject verified for another: %v", err)
	}
	// A same-length different subject, which a length check alone would pass.
	if err := c.Verify([]byte("node-alphX"), nonce, now.Add(time.Minute)); !errors.Is(err, ErrPoWWrongSubject) {
		t.Fatalf("a same-length different subject verified: %v", err)
	}
	// Expired.
	if err := c.Verify(subject, nonce, now.Add(c.TTL+time.Second)); !errors.Is(err, ErrPoWStale) {
		t.Fatalf("an expired solution verified: %v", err)
	}
	// Wrong nonce.
	if err := c.Verify(subject, nonce+1, now.Add(time.Minute)); !errors.Is(err, ErrPoWTooEasy) {
		t.Fatalf("a wrong nonce verified: %v", err)
	}
}

// TestPoWLengthPrefixPreventsSubjectAmbiguity is the encoding check.
//
// Concatenating a variable-length subject raw lets two different subjects
// produce the same digest — "ab" + "c" and "a" + "bc" — and one solution would
// then admit two identities. The length prefix is what forbids it.
func TestPoWLengthPrefixPreventsSubjectAmbiguity(t *testing.T) {
	now := time.Now()
	a, _ := NewChallenge([]byte("abc"), now)
	b := a
	b.Subject = []byte("ab")
	// Same seed, same bits, different subject split: digests must differ.
	if a.digest(7) == b.digest(7) {
		t.Fatal("two different subjects produced the same digest")
	}
}

// TestT145PoWCostIsMeasured is T14.5.
//
// "The PoW cost is measured on low-end hardware and recorded, so the exclusion
// it causes is a known quantity."
//
// The measurement is taken here and logged. The honest caveat is logged with
// it: this runs on the development machine, not on the low-end hardware T14.5
// names, so what is recorded is a rate and a scaling, and the low-end figure
// remains outstanding.
func TestT145PoWCostIsMeasured(t *testing.T) {
	// Measured at a reduced difficulty and scaled, because measuring the real
	// 18-bit difficulty in a unit test would make the suite slow for no extra
	// information: the work is linear in 2^bits and the rate is what varies.
	const measureBits = 14
	m, err := MeasurePoW(measureBits, []byte("node-measure"), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if m.HashesPerSecond <= 0 {
		t.Fatal("measurement produced no rate")
	}
	full := m.Expected // reused below for the scaling
	_ = full

	expectedAtParam := float64(uint64(1) << params.AdmissionPoWBits)
	secondsAtParam := expectedAtParam / m.HashesPerSecond

	t.Logf("T14.5 MEASUREMENT (development machine, NOT the low-end hardware "+
		"T14.5 names):\n"+
		"  %d-bit solve: %d attempts in %v (%.0f H/s); mean for the difficulty is %.0f\n"+
		"  scaled to the configured %d bits: ~%.0f attempts, ~%.2f s here\n"+
		"  a machine 20x slower would pay ~%.1f s\n"+
		"  the exclusion this causes on low-end hardware is NOT YET MEASURED",
		measureBits, m.Attempts, m.Elapsed.Round(time.Millisecond), m.HashesPerSecond, m.Expected,
		params.AdmissionPoWBits, expectedAtParam, secondsAtParam, secondsAtParam*20)

	// A sanity bound rather than an assertion about the machine: a solve that
	// took wildly more than the mean means the difficulty test is wrong, not
	// that the run was unlucky. 30x the mean has probability e^-30.
	if float64(m.Attempts) > 30*m.Expected {
		t.Fatalf("a %d-bit solve took %d attempts against a mean of %.0f -- "+
			"the difficulty check is miscounting", measureBits, m.Attempts, m.Expected)
	}
}

// ---------------------------------------------------------------------------
// Composed caps
// ---------------------------------------------------------------------------

func ann(t *testing.T, addr string, asn uint32, owner byte) peer.Annotation {
	t.Helper()
	a, err := peer.Annotate(netip.MustParseAddr(addr))
	if err != nil {
		t.Fatal(err)
	}
	a.ASN = asn
	if asn != peer.ASNUnknown {
		a.ASNSource = peer.ASNSourceOperator
	}
	if owner != 0 {
		var o peer.OperatorID
		for i := range o {
			o[i] = owner
		}
		a.Operator, a.OperatorSource = o, peer.OperatorSourceChain
	}
	return a
}

// TestE144OneAdversaryPrefixOccupiesOneSlotEverywhere is E14.4 and T14.3.
//
// "An adversary with 100 identities in one /24 occupies at most one slot per
// bucket and one hop per path" — and the test runs the SAME population through
// every selection point in one pass, because a cap enforced at three points out
// of four is no cap at all.
func TestE144OneAdversaryPrefixOccupiesOneSlotEverywhere(t *testing.T) {
	// 100 identities, one /24, one AS, one owner. The cheapest fleet there is.
	var fleet []peer.Annotation
	for i := 0; i < 100; i++ {
		fleet = append(fleet, ann(t, fmt.Sprintf("10.7.0.%d", i%254+1), 64512, 0x11))
	}

	for _, p := range AllPoints {
		caps := CapsFor(p)
		// Admit greedily under the caps, exactly as a selection point would.
		var admitted []peer.Annotation
		for _, a := range fleet {
			trial := append(append([]peer.Annotation(nil), admitted...), a)
			if Check(MeasureOccupancy(trial), p) == nil {
				admitted = append(admitted, a)
			}
		}
		if len(admitted) > caps.PerPrefix {
			t.Fatalf("E14.4 violated at %s: 100 identities in one /24 took %d slots, cap %d",
				p, len(admitted), caps.PerPrefix)
		}
		// The path and the guard set are the two E14.4 names explicitly.
		if (p == PointPath || p == PointGuardSet) && len(admitted) != 1 {
			t.Fatalf("E14.4 violated: %s admitted %d of one adversary's identities, want 1",
				p, len(admitted))
		}
	}
}

// TestT143CapsHoldSimultaneouslyAcrossPoints is T14.3.
//
// The adversary spreads across /24s to defeat the prefix cap while staying in
// one AS. Every point must still hold, and the point that catches it differs
// from the one that caught the previous fleet — which is the reason the caps
// are composed rather than each point having its own idea.
func TestT143CapsHoldSimultaneouslyAcrossPoints(t *testing.T) {
	var fleet []peer.Annotation
	for i := 0; i < 100; i++ {
		fleet = append(fleet, ann(t, fmt.Sprintf("10.%d.0.1", i+1), 64512, 0x22))
	}
	for _, p := range AllPoints {
		caps := CapsFor(p)
		var admitted []peer.Annotation
		for _, a := range fleet {
			trial := append(append([]peer.Annotation(nil), admitted...), a)
			if Check(MeasureOccupancy(trial), p) == nil {
				admitted = append(admitted, a)
			}
		}
		if len(admitted) > caps.PerASN {
			t.Fatalf("T14.3 violated at %s: 100 identities across 100 /24s in one AS "+
				"took %d slots, ASN cap %d", p, len(admitted), caps.PerASN)
		}
	}
}

// TestUnknownDomainsAreCountedNotAssumedAway is the honesty half.
//
// A set that satisfies every cap on a population whose ASNs and owners are all
// unknown has satisfied the prefix rung and nothing else. Occupancy reports that
// so a caller can tell it from a real result — §56.2's failure mode, in the one
// place where it would look most like success.
func TestUnknownDomainsAreCountedNotAssumedAway(t *testing.T) {
	var pop []peer.Annotation
	for i := 0; i < 20; i++ {
		pop = append(pop, ann(t, fmt.Sprintf("10.%d.0.1", i+1), peer.ASNUnknown, 0))
	}
	o := MeasureOccupancy(pop)
	if o.UnknownASN != 20 || o.UnknownOperator != 20 {
		t.Fatalf("unknown domains were not counted: asn %d, operator %d",
			o.UnknownASN, o.UnknownOperator)
	}
	if len(o.ASN) != 0 || len(o.Operator) != 0 {
		t.Fatal("unknown domains were counted as known ones")
	}
	// And the caps pass, because there is nothing to collide on. That is the
	// correct behaviour and the reason the counters must be visible.
	for _, p := range AllPoints {
		if err := Check(o, p); err != nil {
			t.Fatalf("%s refused a population with no determinable domains: %v", p, err)
		}
	}
}

// TestCheckNamesTheOffender covers the error's usefulness and its determinism.
func TestCheckNamesTheOffender(t *testing.T) {
	pop := []peer.Annotation{
		ann(t, "10.1.0.1", 100, 0x01),
		ann(t, "10.1.0.2", 200, 0x02),
	}
	err := Check(MeasureOccupancy(pop), PointPath)
	if err == nil {
		t.Fatal("two hops in one /24 passed the path cap")
	}
	first := err.Error()
	for i := 0; i < 50; i++ {
		if Check(MeasureOccupancy(pop), PointPath).Error() != first {
			t.Fatal("Check names a different offender across runs -- map iteration order is leaking")
		}
	}
}

// ---------------------------------------------------------------------------
// Storage admission
// ---------------------------------------------------------------------------

// TestT144StorageAdmissionNeedsNoCoordinator is T14.4.
//
// "Storage admission works with no coordinator reachable — falsified by any
// dependence on syndichan.org."
//
// The structural half is an audit (audit_test.go). This is the behavioural
// half: the decision is a pure function of the request, so there is no
// reachability for it to depend on.
func TestT144StorageAdmissionNeedsNoCoordinator(t *testing.T) {
	bond := BondRef{
		Amount: big.NewInt(params.BondFloorStorage), PendingWithdraw: big.NewInt(0), VerifiedAt: 500,
	}
	ok := StoreRequest{Writer: "w", Bond: bond, Bytes: 1 << 20, FreeBytes: 1 << 30}
	if err := AdmitStore(ok); err != nil {
		t.Fatalf("a bonded writer with room was refused: %v", err)
	}

	// An unbonded writer is refused. There is no anonymous-writer path: a node
	// that accepted unbonded writes would be a free disk for anybody.
	unbonded := ok
	unbonded.Bond = BondRef{}
	if err := AdmitStore(unbonded); !errors.Is(err, ErrWriterUnbonded) {
		t.Fatalf("an unbonded writer gave %v", err)
	}

	// A writer bonded below the STORAGE floor is refused even though it would
	// pass the relay floor -- the floors are per role for a reason.
	underBonded := ok
	underBonded.Bond = BondRef{
		Amount: big.NewInt(params.BondFloorRelay), PendingWithdraw: big.NewInt(0), VerifiedAt: 500,
	}
	if err := AdmitStore(underBonded); !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("a relay-bonded writer was admitted to storage: %v", err)
	}

	// Out of room is a first-class outcome with its own error, not a generic
	// refusal: §10 says an unplaced shard is a visible deficit.
	full := ok
	full.FreeBytes = 1024
	if err := AdmitStore(full); !errors.Is(err, ErrNoCapacity) {
		t.Fatalf("a full node gave %v", err)
	}
}
