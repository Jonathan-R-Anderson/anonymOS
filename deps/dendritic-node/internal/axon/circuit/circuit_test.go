package circuit

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

func newRelayCrypto(t *testing.T) (*HopWide, *HopWide) {
	t.Helper()
	c, r := func() (*HopWide, *HopWide) {
		cs, rs := wideHops(t, 1)
		return cs[0], rs[0]
	}()
	return c, r
}

// TestTrafficClassMustBeDeclared is R2: a default class is a design error, not a
// convenience.
func TestTrafficClassMustBeDeclared(t *testing.T) {
	if _, err := NewCircuit(1, ClassUnset, time.Now()); !errors.Is(err, ErrNoTrafficClass) {
		t.Fatalf("err = %v, want ErrNoTrafficClass", err)
	}
	// The zero value of the type must be the invalid one, or a struct literal
	// that forgets the field silently gets a default.
	var zero TrafficClass
	if zero.Valid() {
		t.Fatal("the zero TrafficClass is valid; forgetting the field would pick a default")
	}
	for _, c := range []TrafficClass{ClassInteractive, ClassBulk} {
		if _, err := NewCircuit(1, c, time.Now()); err != nil {
			t.Fatalf("%s rejected: %v", c, err)
		}
	}
}

// TestCircuitIDsAreRewrittenAndUnrelated is T5.3.
//
// The id on link G->M must differ from the id on client->G, and a correlator
// holding BOTH links must not be able to join them without the relay's table.
func TestCircuitIDsAreRewrittenAndUnrelated(t *testing.T) {
	tbl := NewCircuitTable(time.Now)
	const trials = 2000

	same, sequential, xorConst := 0, 0, 0
	var firstXor uint64
	for i := 0; i < trials; i++ {
		var in link.CircuitID
		for in == 0 {
			var b [8]byte
			if _, err := rand.Read(b[:]); err != nil {
				t.Fatal(err)
			}
			in = link.CircuitID(b[0])<<56 | link.CircuitID(b[1])<<48 |
				link.CircuitID(b[2])<<40 | link.CircuitID(b[3])<<32 |
				link.CircuitID(b[4])<<24 | link.CircuitID(b[5])<<16 |
				link.CircuitID(b[6])<<8 | link.CircuitID(b[7])
		}
		_, r := newRelayCrypto(t)
		rc, err := tbl.Admit("guard", in, r)
		if err != nil {
			t.Fatal(err)
		}
		if rc.PrevID != in {
			t.Fatal("incoming id was not preserved")
		}
		if rc.NextID == 0 {
			t.Fatal("outgoing id is zero, which is reserved for link cells")
		}
		if rc.NextID == rc.PrevID {
			same++
		}
		if rc.NextID == rc.PrevID+1 {
			sequential++
		}
		x := uint64(rc.NextID) ^ uint64(rc.PrevID)
		if i == 0 {
			firstXor = x
		} else if x == firstXor {
			xorConst++
		}
		tbl.Teardown(rc)
	}

	// Any of these would let a correlator holding both links join them.
	if same > 0 {
		t.Fatalf("T5.3 falsified: %d of %d circuits reused the incoming id", same, trials)
	}
	if sequential > 1 {
		t.Fatalf("T5.3 falsified: %d of %d outgoing ids are incoming+1", sequential, trials)
	}
	if xorConst > 1 {
		t.Fatalf("T5.3 falsified: the in/out XOR is constant in %d of %d cases; "+
			"the mapping is derivable without the table", xorConst, trials)
	}
}

// TestOutgoingIDsDoNotRepeat: a repeated outgoing id across circuits would let a
// correlator link two circuits to one relay.
func TestOutgoingIDsDoNotRepeat(t *testing.T) {
	seen := map[link.CircuitID]bool{}
	for i := 0; i < 5000; i++ {
		id, err := AllocateID()
		if err != nil {
			t.Fatal(err)
		}
		if seen[id] {
			t.Fatalf("circuit id %d repeated within 5000 draws", id)
		}
		seen[id] = true
	}
}

// TestExtendToAHopAlreadyOnTheCircuitIsRefused is T5.7.
func TestExtendToAHopAlreadyOnTheCircuitIsRefused(t *testing.T) {
	c, err := NewCircuit(1, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	s1, _ := newRelayStatic(t)
	s2, _ := newRelayStatic(t)

	if err := c.AddHop(&Hop{Static: s1}); err != nil {
		t.Fatal(err)
	}
	if err := c.AddHop(&Hop{Static: s2}); err != nil {
		t.Fatal(err)
	}
	// The previous hop specifically -- the case T5.7 names.
	if err := c.AddHop(&Hop{Static: s2}); !errors.Is(err, ErrExtendToSelf) {
		t.Fatalf("extending to the previous hop: err = %v, want ErrExtendToSelf", err)
	}
	// And any earlier hop, which collapses the path just as badly.
	if err := c.AddHop(&Hop{Static: s1}); !errors.Is(err, ErrExtendToSelf) {
		t.Fatalf("extending to the guard: err = %v, want ErrExtendToSelf", err)
	}
	if c.Len() != 2 {
		t.Fatalf("path length = %d, want 2", c.Len())
	}
}

// TestPathLengthIsBounded.
func TestPathLengthIsBounded(t *testing.T) {
	c, err := NewCircuit(1, ClassBulk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < params.MaxHops; i++ {
		s, _ := newRelayStatic(t)
		if err := c.AddHop(&Hop{Static: s}); err != nil {
			t.Fatalf("hop %d: %v", i+1, err)
		}
	}
	s, _ := newRelayStatic(t)
	if err := c.AddHop(&Hop{Static: s}); !errors.Is(err, ErrPathLength) {
		t.Fatalf("err = %v, want ErrPathLength", err)
	}
}

// TestRelayBuildBudget is T5.8 / PAR-08.
func TestRelayBuildBudget(t *testing.T) {
	if params.RelayBuildBudget != 8 {
		t.Fatalf("RelayBuildBudget = %d, want 8 (MaxHops 4 + 2 redraws + 2 spare)",
			params.RelayBuildBudget)
	}
	c, err := NewCircuit(1, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < params.RelayBuildBudget; i++ {
		if err := c.SpendBuildBudget(); err != nil {
			t.Fatalf("spend %d: %v", i+1, err)
		}
	}
	if err := c.SpendBuildBudget(); !errors.Is(err, ErrRelayBudget) {
		t.Fatalf("err = %v, want ErrRelayBudget", err)
	}

	// And the budget is decremented at every HOP too, not only at the client --
	// a client that ignores its own budget is the client the budget bounds.
	tbl := NewCircuitTable(time.Now)
	_, r := newRelayCrypto(t)
	rc, err := tbl.Admit("guard", 42, r)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < params.RelayBuildBudget; i++ {
		if err := rc.SpendBuildBudget(); err != nil {
			t.Fatalf("relay spend %d: %v", i+1, err)
		}
	}
	if err := rc.SpendBuildBudget(); !errors.Is(err, ErrRelayBudget) {
		t.Fatalf("relay err = %v, want ErrRelayBudget", err)
	}
}

// TestExtendOutsideRelayBuildIsRefused is the other half of T5.8: the cap alone
// leaves the class-confusion path open.
func TestExtendOutsideRelayBuildIsRefused(t *testing.T) {
	clients, relays := wideHops(t, 1)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}

	send := func(cmd link.Command) error {
		rcell := &RelayCell{Stream: 0, Cmd: RCmdExtend, Data: []byte("target")}
		inner, err := rcell.Encode()
		if err != nil {
			t.Fatal(err)
		}
		block, err := SealInnermost(af, inner)
		if err != nil {
			t.Fatal(err)
		}
		if err := WideSealForward(clients, block); err != nil {
			t.Fatal(err)
		}
		rc := &RelayCircuit{Crypto: relays[0], buildBudget: params.RelayBuildBudget}
		_, err = ProcessForward(rc, &link.Cell{Circuit: 1, Command: cmd, Payload: block}, af, true)
		return err
	}

	if err := send(link.CmdRelay); !errors.Is(err, ErrRelayNotBuild) {
		t.Fatalf("EXTEND in a plain RELAY: err = %v, want ErrRelayNotBuild", err)
	}

	clients, relays = wideHops(t, 1)
	if err := send(link.CmdRelayBuild); err != nil {
		t.Fatalf("EXTEND in a RELAY_BUILD was refused: %v", err)
	}
}

// TestImpossibleCellsAreCountedAndTearDown is T5.9 / PAR-28.
func TestImpossibleCellsAreCountedAndTearDown(t *testing.T) {
	c, err := NewCircuit(1, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < params.DropCellThreshold; i++ {
		if err := c.NoteImpossibleCell(); err != nil {
			t.Fatalf("tore down after %d impossible cells, threshold is %d",
				i, params.DropCellThreshold)
		}
	}
	if err := c.NoteImpossibleCell(); !errors.Is(err, ErrDropThreshold) {
		t.Fatalf("err = %v after %d impossible cells, want ErrDropThreshold",
			err, params.DropCellThreshold)
	}
	if c.Drops() != params.DropCellThreshold {
		t.Fatalf("drops = %d, want %d", c.Drops(), params.DropCellThreshold)
	}
}

// TestTeardownFreesStateAndQuarantinesIDs is T5.5.
func TestTeardownFreesStateAndQuarantinesIDs(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	clock := func() time.Time { return now }
	tbl := NewCircuitTable(clock)

	_, r := newRelayCrypto(t)
	rc, err := tbl.Admit("guard", 77, r)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Link(rc, "middle")

	if _, ok := tbl.LookupForward("guard", 77); !ok {
		t.Fatal("circuit not installed")
	}
	if _, ok := tbl.LookupBackward("middle", rc.NextID); !ok {
		t.Fatal("backward mapping not installed")
	}

	prev, next := tbl.Teardown(rc)
	// Teardown propagates BOTH ways.
	if prev != "guard" || next != "middle" {
		t.Fatalf("teardown notified %q/%q, want guard/middle", prev, next)
	}
	// State is freed at this hop.
	if _, ok := tbl.LookupForward("guard", 77); ok {
		t.Fatal("forward state survived teardown")
	}
	if _, ok := tbl.LookupBackward("middle", rc.NextID); ok {
		t.Fatal("backward state survived teardown")
	}
	if tbl.Len() != 0 {
		t.Fatalf("%d circuits remain after teardown", tbl.Len())
	}
	// A second teardown is a no-op rather than a double free.
	if p, n := tbl.Teardown(rc); p != "" || n != "" {
		t.Fatal("teardown was not idempotent")
	}

	// The id is quarantined, so a late cell from the dead circuit cannot land
	// on a fresh one.
	if _, err := tbl.Admit("guard", 77, r); !errors.Is(err, ErrCircuitExists) {
		t.Fatalf("a quarantined id was reused immediately: %v", err)
	}
	now = now.Add(params.CircuitIDQuarantine + time.Second)
	if n := tbl.PruneQuarantine(); n == 0 {
		t.Fatal("quarantine did not expire")
	}
	if _, err := tbl.Admit("guard", 77, r); err != nil {
		t.Fatalf("id not reusable after quarantine: %v", err)
	}
}

// TestTeardownIsFastEnough is E5.2's teardown half: no hop retains circuit state
// after teardown. The bound is one second; the operation is a map delete.
func TestTeardownIsFastEnough(t *testing.T) {
	tbl := NewCircuitTable(time.Now)
	var circuits []*RelayCircuit
	for i := 1; i <= 1000; i++ {
		_, r := newRelayCrypto(t)
		rc, err := tbl.Admit("guard", link.CircuitID(i), r)
		if err != nil {
			t.Fatal(err)
		}
		tbl.Link(rc, "middle")
		circuits = append(circuits, rc)
	}
	start := time.Now()
	for _, rc := range circuits {
		tbl.Teardown(rc)
	}
	elapsed := time.Since(start)
	if tbl.Len() != 0 {
		t.Fatalf("%d circuits retained state after teardown", tbl.Len())
	}
	if elapsed > time.Second {
		t.Fatalf("tearing down 1000 circuits took %v, over the 1 s bound", elapsed)
	}
	t.Logf("T5.5: 1000 circuits torn down in %v, zero residual entries", elapsed.Truncate(time.Microsecond))
}

// TestRelayKnowsOnlyItsNeighbours is T5.2 in the form a unit test can assert:
// the relay's circuit record has room for exactly two peers, and nothing else
// on the path is reachable from it.
func TestRelayKnowsOnlyItsNeighbours(t *testing.T) {
	tbl := NewCircuitTable(time.Now)
	_, r := newRelayCrypto(t)
	rc, err := tbl.Admit("guard", 5, r)
	if err != nil {
		t.Fatal(err)
	}
	tbl.Link(rc, "terminal")

	peers := map[string]bool{rc.PrevPeer: true, rc.NextPeer: true}
	if len(peers) != 2 {
		t.Fatalf("relay holds %d peer identities, want exactly 2", len(peers))
	}
	if !peers["guard"] || !peers["terminal"] {
		t.Fatalf("relay holds %v, want its two neighbours", peers)
	}
}

// TestForwardRewritesTheIDAndPeelsOneLayer.
func TestForwardRewritesTheIDAndPeelsOneLayer(t *testing.T) {
	clients, relays := wideHops(t, 2)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}
	rcell := &RelayCell{Stream: 3, Cmd: RCmdData, Data: []byte("hello")}
	inner, err := rcell.Encode()
	if err != nil {
		t.Fatal(err)
	}
	block, err := SealInnermost(af, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := WideSealForward(clients, block); err != nil {
		t.Fatal(err)
	}

	tbl := NewCircuitTable(time.Now)
	rc1, err := tbl.Admit("client", 11, relays[0])
	if err != nil {
		t.Fatal(err)
	}
	res, err := ProcessForward(rc1, &link.Cell{Circuit: 11, Command: link.CmdRelay, Payload: block}, af, false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Terminal {
		t.Fatal("a middle hop reported itself terminal")
	}
	if res.Out.Circuit != rc1.NextID {
		t.Fatalf("outgoing id = %d, want the rewritten %d", res.Out.Circuit, rc1.NextID)
	}
	if res.Out.Circuit == 11 {
		t.Fatal("T5.3 falsified: the incoming id was forwarded unchanged")
	}

	rc2 := &RelayCircuit{Crypto: relays[1], buildBudget: params.RelayBuildBudget}
	res2, err := ProcessForward(rc2, res.Out, af, true)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Terminal || res2.Relay == nil {
		t.Fatal("the terminal did not parse the relay message")
	}
	if string(res2.Relay.Data) != "hello" {
		t.Fatalf("data = %q, want %q", res2.Relay.Data, "hello")
	}
}

// TestStateMachineRefusesImpossibleTransitions.
func TestStateMachineRefusesImpossibleTransitions(t *testing.T) {
	c, err := NewCircuit(1, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// C_NEW cannot jump straight to C_ACTIVE.
	if err := c.SetState(CActive); !errors.Is(err, ErrWrongState) {
		t.Fatalf("err = %v, want ErrWrongState", err)
	}
	for _, s := range []State{CLink, CCreating, CExtending, COpen, CActive, CRotate} {
		if err := c.SetState(s); err != nil {
			t.Fatalf("legal transition to %s refused: %v", s, err)
		}
	}
	// Teardown is reachable from anywhere; that is the point of teardown.
	if err := c.SetState(CClosing); err != nil {
		t.Fatalf("teardown from %s refused: %v", c.State(), err)
	}
}

// TestStreamIDsStayOdd: the initiator's ids must not collide with the far end's.
func TestStreamIDsStayOdd(t *testing.T) {
	c, err := NewCircuit(1, ClassBulk, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		id := c.NextStreamID()
		if !id.IsInitiator() {
			t.Fatalf("allocated stream id %d is even", id)
		}
	}
}
