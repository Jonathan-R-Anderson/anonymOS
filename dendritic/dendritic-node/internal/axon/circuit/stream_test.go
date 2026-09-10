package circuit

import (
	"bytes"
	"errors"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

func iso(dst string, class TrafficClass) Isolation {
	return Isolation{IdentityScope: "alice", Tag: dst, Destination: dst, Class: class}
}

// TestInteractiveAndBulkNeverShareACircuit is §8.6's first hard rule.
//
// Different windows and, in v2, different padding regimes: mixing them makes
// padding meaningless and windows wrong.
func TestInteractiveAndBulkNeverShareACircuit(t *testing.T) {
	tbl := NewStreamTable()
	if _, err := tbl.Open(1, iso("service.axon", ClassInteractive)); err != nil {
		t.Fatal(err)
	}
	_, err := tbl.Open(3, iso("service.axon", ClassBulk))
	if !errors.Is(err, ErrIsolationMismatch) {
		t.Fatalf("err = %v, want ErrIsolationMismatch", err)
	}
}

// TestDifferentIdentityScopesNeverShare is §8.5's guard rule one level down.
func TestDifferentIdentityScopesNeverShare(t *testing.T) {
	tbl := NewStreamTable()
	a := Isolation{IdentityScope: "alice", Tag: "d", Destination: "d", Class: ClassInteractive}
	b := Isolation{IdentityScope: "bob", Tag: "d", Destination: "d", Class: ClassInteractive}
	if _, err := tbl.Open(1, a); err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.Open(3, b); !errors.Is(err, ErrIsolationMismatch) {
		t.Fatalf("err = %v, want ErrIsolationMismatch", err)
	}
}

// TestOnceBoundAlwaysBound: a circuit that has carried a stream for D is never
// used for D', even after every stream on it has closed.
//
// Reusing a drained circuit re-creates the linkage isolation prevents, one
// destination at a time — which is why Close does NOT clear the binding.
func TestOnceBoundAlwaysBound(t *testing.T) {
	tbl := NewStreamTable()
	if _, err := tbl.Open(1, iso("first.axon", ClassInteractive)); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Close(1); err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 0 {
		t.Fatal("the stream was not removed")
	}
	// The circuit is now empty, and still bound.
	bound, ok := tbl.Binding()
	if !ok || bound.Destination != "first.axon" {
		t.Fatalf("binding = %+v, want first.axon", bound)
	}
	if _, err := tbl.Open(3, iso("second.axon", ClassInteractive)); !errors.Is(err, ErrCircuitBound) {
		t.Fatalf("a drained circuit accepted a second destination: %v", err)
	}
	// The original destination is still welcome.
	if _, err := tbl.Open(5, iso("first.axon", ClassInteractive)); err != nil {
		t.Fatalf("the bound destination was refused: %v", err)
	}
}

// TestIsolationTagSeparatesSameDestination: a caller may isolate further than
// the destination, and the tag is honoured.
func TestIsolationTagSeparatesSameDestination(t *testing.T) {
	tbl := NewStreamTable()
	a := Isolation{IdentityScope: "alice", Tag: "tab-1", Destination: "d", Class: ClassInteractive}
	b := Isolation{IdentityScope: "alice", Tag: "tab-2", Destination: "d", Class: ClassInteractive}
	if _, err := tbl.Open(1, a); err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.Open(3, b); !errors.Is(err, ErrIsolationMismatch) {
		t.Fatalf("differing tags shared a circuit: %v", err)
	}
}

// TestAllFourFieldsAreCompared guards against the bug of comparing three of
// four, which would silently merge traffic that must stay apart.
func TestAllFourFieldsAreCompared(t *testing.T) {
	base := Isolation{IdentityScope: "alice", Tag: "t", Destination: "d", Class: ClassInteractive}
	for name, mut := range map[string]func(Isolation) Isolation{
		"identity scope": func(i Isolation) Isolation { i.IdentityScope = "bob"; return i },
		"tag":            func(i Isolation) Isolation { i.Tag = "u"; return i },
		"destination":    func(i Isolation) Isolation { i.Destination = "e"; return i },
		"class":          func(i Isolation) Isolation { i.Class = ClassBulk; return i },
	} {
		t.Run(name, func(t *testing.T) {
			tbl := NewStreamTable()
			if _, err := tbl.Open(1, base); err != nil {
				t.Fatal(err)
			}
			if _, err := tbl.Open(3, mut(base)); err == nil {
				t.Fatalf("a stream differing only in %s was allowed to share", name)
			}
		})
	}
}

// TestStreamCapIsEnforced is §8.6's 64-stream limit, and it is the same for both
// classes: a per-class cap would make the class inferable from the count.
func TestStreamCapIsEnforced(t *testing.T) {
	if params.MaxStreamsPerCircuit != 64 {
		t.Fatalf("MaxStreamsPerCircuit = %d, want 64", params.MaxStreamsPerCircuit)
	}
	for _, class := range []TrafficClass{ClassInteractive, ClassBulk} {
		tbl := NewStreamTable()
		for i := 0; i < params.MaxStreamsPerCircuit; i++ {
			if _, err := tbl.Open(StreamID(2*i+1), iso("d", class)); err != nil {
				t.Fatalf("%s stream %d: %v", class, i, err)
			}
		}
		if _, err := tbl.Open(9999, iso("d", class)); !errors.Is(err, ErrStreamCap) {
			t.Fatalf("%s: err = %v, want ErrStreamCap", class, err)
		}
	}
}

// TestDrainingCircuitAcceptsNoNewStreams: a long stream must not keep a circuit
// alive past rotation and defeat the 10-minute lifetime.
func TestDrainingCircuitAcceptsNoNewStreams(t *testing.T) {
	tbl := NewStreamTable()
	if _, err := tbl.Open(1, iso("d", ClassInteractive)); err != nil {
		t.Fatal(err)
	}
	tbl.Drain()
	if _, err := tbl.Open(3, iso("d", ClassInteractive)); !errors.Is(err, ErrCircuitDraining) {
		t.Fatalf("err = %v, want ErrCircuitDraining", err)
	}
	// Existing streams keep working — draining is not closing.
	if _, ok := tbl.Get(1); !ok {
		t.Fatal("draining closed an existing stream")
	}
}

// TestMayCarryDoesNotMutate: P12 asks the question before committing, and asking
// must not leave a half-created stream behind.
func TestMayCarryDoesNotMutate(t *testing.T) {
	tbl := NewStreamTable()
	if err := tbl.MayCarry(iso("d", ClassInteractive)); err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 0 {
		t.Fatal("MayCarry created a stream")
	}
	if _, bound := tbl.Binding(); bound {
		t.Fatal("MayCarry bound the circuit")
	}
}

// TestIncompleteIsolationIsRefused: an isolation context missing its class or
// destination is a caller who has not decided, and deciding for them is how a
// default gets introduced by the back door.
func TestIncompleteIsolationIsRefused(t *testing.T) {
	tbl := NewStreamTable()
	for name, i := range map[string]Isolation{
		"no class":       {IdentityScope: "a", Tag: "d", Destination: "d"},
		"no destination": {IdentityScope: "a", Tag: "d", Class: ClassInteractive},
	} {
		if _, err := tbl.Open(1, i); !errors.Is(err, ErrNoIsolation) {
			t.Errorf("%s: err = %v, want ErrNoIsolation", name, err)
		}
	}
}

// TestStreamZeroIsReserved: stream 0 is circuit-scoped and must never be opened
// as a stream.
func TestStreamZeroIsReserved(t *testing.T) {
	tbl := NewStreamTable()
	if _, err := tbl.Open(0, iso("d", ClassInteractive)); err == nil {
		t.Fatal("stream 0 was opened as a stream")
	}
}

// TestStreamLifecycle.
func TestStreamLifecycle(t *testing.T) {
	tbl := NewStreamTable()
	s, err := tbl.Open(1, iso("d", ClassInteractive))
	if err != nil {
		t.Fatal(err)
	}
	if s.State() != SNew {
		t.Fatalf("state = %s, want S_NEW", s.State())
	}
	if err := tbl.Begin(1); err != nil {
		t.Fatal(err)
	}
	if s.State() != SConnecting {
		t.Fatalf("state = %s, want S_CONNECTING", s.State())
	}
	if _, err := tbl.HandleInbound(&RelayCell{Stream: 1, Cmd: RCmdConnected}); err != nil {
		t.Fatal(err)
	}
	if s.State() != SOpen {
		t.Fatalf("state = %s, want S_OPEN", s.State())
	}
	if _, err := tbl.HandleInbound(&RelayCell{Stream: 1, Cmd: RCmdData, Data: []byte("x")}); err != nil {
		t.Fatal(err)
	}
	if _, err := tbl.HandleInbound(&RelayCell{Stream: 1, Cmd: RCmdEnd}); err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 0 {
		t.Fatal("END did not close the stream")
	}
}

// TestImpossibleInboundCellsAreReported is T5.9 / PAR-28 at the stream layer.
//
// Each of these is structurally valid on the wire and impossible in this state.
// §8.9's injection argument covers cells that must be DECRYPTED and says nothing
// about these.
func TestImpossibleInboundCellsAreReported(t *testing.T) {
	tbl := NewStreamTable()
	if _, err := tbl.Open(1, iso("d", ClassInteractive)); err != nil {
		t.Fatal(err)
	}

	for name, msg := range map[string]*RelayCell{
		"DATA for a stream that never opened":   {Stream: 99, Cmd: RCmdData, Data: []byte("x")},
		"SENDME for a stream that never opened": {Stream: 99, Cmd: RCmdSendme},
		"END for a stream already gone":         {Stream: 99, Cmd: RCmdEnd},
		"CONNECTED for a stream never begun":    {Stream: 1, Cmd: RCmdConnected},
		"DATA before CONNECTED":                 {Stream: 1, Cmd: RCmdData, Data: []byte("x")},
	} {
		t.Run(name, func(t *testing.T) {
			impossible, err := tbl.HandleInbound(msg)
			if !impossible {
				t.Fatalf("not reported impossible (err = %v)", err)
			}
		})
	}

	// And the counter drives teardown at the threshold.
	c, err := NewCircuit(1, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var last error
	for i := 0; i < params.DropCellThreshold; i++ {
		impossible, _ := tbl.HandleInbound(&RelayCell{Stream: 99, Cmd: RCmdData, Data: []byte("x")})
		if impossible {
			last = c.NoteImpossibleCell()
		}
	}
	if !errors.Is(last, ErrDropThreshold) {
		t.Fatalf("impossible cells did not drive teardown: %v", last)
	}
}

// TestCircuitScopedCommandsBypassTheStreamTable: EXTEND, TRUNCATE and DROP are
// circuit business and must not be looked up as streams.
func TestCircuitScopedCommandsBypassTheStreamTable(t *testing.T) {
	tbl := NewStreamTable()
	for _, cmd := range []RCmd{RCmdExtend, RCmdExtended, RCmdTruncate, RCmdTruncated, RCmdDrop} {
		impossible, err := tbl.HandleInbound(&RelayCell{Stream: 0, Cmd: cmd})
		if impossible || err != nil {
			t.Fatalf("%s was treated as a stream cell: impossible=%v err=%v", cmd, impossible, err)
		}
	}
	// A circuit-level SENDME likewise.
	if impossible, err := tbl.HandleInbound(&RelayCell{Stream: 0, Cmd: RCmdSendme}); impossible || err != nil {
		t.Fatalf("circuit-level SENDME was treated as a stream cell: %v", err)
	}
}

// TestBeginBodyRoundTripsAndBoundsItsLengths.
func TestBeginBodyRoundTripsAndBoundsItsLengths(t *testing.T) {
	dst := []byte("alice.lab.axon")
	body := BeginBody(0x01, 443, dst, 0x00)
	dt, port, got, flags, err := ParseBeginBody(body)
	if err != nil {
		t.Fatal(err)
	}
	if dt != 0x01 || port != 443 || !bytes.Equal(got, dst) || flags != 0 {
		t.Fatalf("BEGIN body did not round trip: %d %d %q %d", dt, port, got, flags)
	}

	for name, b := range map[string][]byte{
		"truncated": body[:4],
		"empty":     nil,
		"dst overrun": func() []byte {
			c := append([]byte(nil), body...)
			c[3], c[4] = 0xFF, 0xFF
			return c
		}(),
	} {
		if _, _, _, _, err := ParseBeginBody(b); err == nil {
			t.Errorf("%s BEGIN body was accepted", name)
		}
	}
}

// TestStreamsFitInARelayCell: a BEGIN for a long destination must still fit.
func TestStreamsFitInARelayCell(t *testing.T) {
	dst := bytes.Repeat([]byte("a"), 255)
	body := BeginBody(0x01, 443, dst, 0)
	c := &RelayCell{Stream: 1, Cmd: RCmdBegin, Data: body}
	if _, err := c.Encode(); err != nil {
		t.Fatalf("a 255-byte destination did not fit: %v", err)
	}
	if len(body) > RelayDataSize {
		t.Fatalf("BEGIN body %d exceeds relay capacity %d", len(body), RelayDataSize)
	}
}
