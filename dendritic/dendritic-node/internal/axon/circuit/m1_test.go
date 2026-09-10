package circuit

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/link"
)

// M1 (§24) and E5.1: three nodes forward a cell.
//
// The relays here are in-process and the "links" are pipes rather than libp2p
// hosts — P2 already proved the link layer carries cells over real QUIC and TCP,
// and repeating that here would test the transport a third time instead of
// testing the circuit. What IS real: every handshake, every permutation, every
// key, the relay tables, and the id rewriting.

// pipeStream is a CellStream over an in-memory pair, so a test can drive both
// ends of a link without a network.
type pipeStream struct {
	id   link.CircuitID
	out  chan *link.Cell
	in   chan *link.Cell
	done chan struct{}
}

func newPipe(id link.CircuitID) (a, b *pipeStream) {
	ab := make(chan *link.Cell, 16)
	ba := make(chan *link.Cell, 16)
	done := make(chan struct{})
	return &pipeStream{id: id, out: ab, in: ba, done: done},
		&pipeStream{id: id, out: ba, in: ab, done: done}
}

func (p *pipeStream) CircuitID() link.CircuitID { return p.id }

func (p *pipeStream) WriteCell(c *link.Cell) error {
	// Round-trip through the real codec, so a cell that would not survive the
	// wire does not survive this test either.
	var buf [1024]byte
	if err := c.Encode(buf[:]); err != nil {
		return err
	}
	got, err := link.Decode(buf[:])
	if err != nil {
		return err
	}
	select {
	case p.out <- got:
		return nil
	case <-p.done:
		return errors.New("pipe closed")
	}
}

func (p *pipeStream) ReadCell() (*link.Cell, error) {
	select {
	case c := <-p.in:
		return c, nil
	case <-p.done:
		return nil, errors.New("pipe closed")
	case <-time.After(5 * time.Second):
		return nil, errors.New("pipe read timed out")
	}
}

func (p *pipeStream) Close() error {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
	return nil
}

// testRelay is one node: its routing identity, its circuit table, and its
// endpoint.
type testRelay struct {
	name     string
	endpoint *RelayEndpoint
	table    *CircuitTable
	af       [32]byte
}

func newTestRelay(t *testing.T, name string) *testRelay {
	t.Helper()
	static, b := newRelayStatic(t)
	r := &testRelay{
		name:     name,
		endpoint: &RelayEndpoint{Static: static, B: b},
		table:    NewCircuitTable(time.Now),
	}
	if _, err := rand.Read(r.af[:]); err != nil {
		t.Fatal(err)
	}
	return r
}

// TestM1ThreeNodesForwardACell is milestone M1.
//
// A client builds a 3-hop circuit by telescoping — CREATE to the guard, then
// EXTEND through it to the middle, then EXTEND through both to the terminal —
// and sends one relay message that arrives intact at the terminal and nowhere
// else in cleartext.
func TestM1ThreeNodesForwardACell(t *testing.T) {
	guard := newTestRelay(t, "guard")
	middle := newTestRelay(t, "middle")
	term := newTestRelay(t, "terminal")

	// The client's link to the guard.
	clientSide, guardSide := newPipe(0)
	defer clientSide.Close()

	circ, err := NewCircuit(0x1122334455667788, ClassInteractive, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	b := &Builder{}

	// --- hop 1: CREATE -------------------------------------------------------
	guardHop := make(chan *HopWide, 1)
	go func() {
		in, err := guardSide.ReadCell()
		if err != nil {
			t.Error(err)
			return
		}
		out, hw, err := guard.endpoint.AnswerCreate(in)
		if err != nil {
			t.Error(err)
			return
		}
		if err := guardSide.WriteCell(out); err != nil {
			t.Error(err)
			return
		}
		guardHop <- hw
	}()

	if err := b.Create(clientSide, circ, guard.endpoint.Static); err != nil {
		t.Fatalf("CREATE: %v", err)
	}
	guardCrypto := <-guardHop
	if circ.Len() != 1 {
		t.Fatalf("path length = %d after CREATE, want 1", circ.Len())
	}

	// The guard installs the circuit and gets an independent outgoing id.
	guardCirc, err := guard.table.Admit("client", circ.ID(), guardCrypto)
	if err != nil {
		t.Fatal(err)
	}
	if guardCirc.NextID == guardCirc.PrevID {
		t.Fatal("T5.3: the guard reused the client's circuit id")
	}

	// --- hop 2: EXTEND through the guard ------------------------------------
	middleCrypto := extendThrough(t, b, circ, clientSide, guardSide,
		[]*RelayCircuit{guardCirc}, []*testRelay{guard}, middle)
	middleCirc, err := middle.table.Admit("guard", guardCirc.NextID, middleCrypto)
	if err != nil {
		t.Fatal(err)
	}
	guard.table.Link(guardCirc, "middle")
	if circ.Len() != 2 {
		t.Fatalf("path length = %d after first EXTEND, want 2", circ.Len())
	}

	// --- hop 3: EXTEND through guard and middle ------------------------------
	termCrypto := extendThrough(t, b, circ, clientSide, guardSide,
		[]*RelayCircuit{guardCirc, middleCirc}, []*testRelay{guard, middle}, term)
	termCirc, err := term.table.Admit("middle", middleCirc.NextID, termCrypto)
	if err != nil {
		t.Fatal(err)
	}
	middle.table.Link(middleCirc, "terminal")
	if circ.Len() != 3 {
		t.Fatalf("path length = %d after second EXTEND, want 3", circ.Len())
	}
	_ = termCirc

	// Every link carries a different circuit id (T5.3).
	ids := map[link.CircuitID]bool{
		circ.ID(): true, guardCirc.NextID: true, middleCirc.NextID: true,
	}
	if len(ids) != 3 {
		t.Fatalf("T5.3 falsified: the three links use %d distinct ids, want 3", len(ids))
	}

	// --- the cell ------------------------------------------------------------
	payload := []byte("M1: three nodes forward a cell")
	msg := &RelayCell{Stream: circ.NextStreamID(), Cmd: RCmdData, Data: payload}
	block, err := circ.SendRelay(term.af, msg)
	if err != nil {
		t.Fatal(err)
	}
	onWire := &link.Cell{Circuit: circ.ID(), Command: link.CmdRelay, Payload: block}

	// E5.1 / T5.1: capture what enters hop 1.
	entering := append([]byte(nil), onWire.Payload...)

	// Hop 1.
	r1, err := ProcessForward(guardCirc, onWire, guard.af, false)
	if err != nil {
		t.Fatalf("guard forward: %v", err)
	}
	if r1.Out.Circuit != guardCirc.NextID {
		t.Fatalf("guard emitted id %d, want %d", r1.Out.Circuit, guardCirc.NextID)
	}
	// Hop 2.
	r2, err := ProcessForward(middleCirc, r1.Out, middle.af, false)
	if err != nil {
		t.Fatalf("middle forward: %v", err)
	}
	// Hop 3 — terminal.
	r3, err := ProcessForward(termCirc, r2.Out, term.af, true)
	if err != nil {
		t.Fatalf("terminal forward: %v", err)
	}
	if !r3.Terminal || r3.Relay == nil {
		t.Fatal("the terminal did not parse the relay message")
	}
	if !bytes.Equal(r3.Relay.Data, payload) {
		t.Fatalf("M1 falsified: terminal got %q, want %q", r3.Relay.Data, payload)
	}

	// T5.1: bytes entering hop 1 and the plaintext leaving hop 3 share nothing.
	if bytes.Contains(entering, payload) {
		t.Fatal("T5.1 falsified: the plaintext was visible entering hop 1")
	}
	if n := longestCommonRun(entering, r2.Out.Payload, 8); n >= 8 {
		t.Fatalf("T5.1 falsified: hop 1 input and hop 3 input share a %d-byte run", n)
	}

	// No intermediate hop ever saw the plaintext.
	for name, seen := range map[string][]byte{
		"guard output":  r1.Out.Payload,
		"middle output": r2.Out.Payload,
	} {
		if bytes.Contains(seen, payload) {
			t.Fatalf("the plaintext was visible in the %s", name)
		}
	}
	t.Logf("M1: 3-hop circuit built by telescoping; %d-byte payload delivered; "+
		"link ids %d / %d / %d all distinct",
		len(payload), circ.ID(), guardCirc.NextID, middleCirc.NextID)
}

// extendThrough performs one EXTEND, driving both the client and every relay on
// the existing path.
func extendThrough(t *testing.T, b *Builder, circ *Circuit, clientSide, guardSide *pipeStream,
	path []*RelayCircuit, relays []*testRelay, next *testRelay) *HopWide {
	t.Helper()

	result := make(chan *HopWide, 1)
	go func() {
		// The guard reads the RELAY_BUILD cell and the path peels it hop by hop.
		in, err := guardSide.ReadCell()
		if err != nil {
			t.Error(err)
			return
		}
		cur := in
		for i, rc := range path {
			terminal := i == len(path)-1
			res, err := ProcessForward(rc, cur, relays[i].af, terminal)
			if err != nil {
				t.Errorf("hop %d forward: %v", i+1, err)
				return
			}
			if !terminal {
				cur = res.Out
				continue
			}
			// The last hop on the current path performs the extension.
			target, err := ParseExtend(rc, relays[i].endpoint.Static.ID(), res.Relay)
			if err != nil {
				t.Errorf("parse EXTEND: %v", err)
				return
			}
			if target.NextID != next.endpoint.Static.ID() {
				t.Error("EXTEND named the wrong relay")
				return
			}
			created, hw, err := next.endpoint.AnswerCreate(&link.Cell{
				Circuit: 0, Command: link.CmdCreate,
				Payload: EncodeCreate(target.HType, target.Handshake),
			})
			if err != nil {
				t.Errorf("next hop CREATE: %v", err)
				return
			}
			reply, err := DecodeCreated(created.Payload)
			if err != nil {
				t.Error(err)
				return
			}
			back, err := SendBackward(rc, relays[i].af, &RelayCell{
				Stream: 0, Cmd: RCmdExtended, Data: EncodeExtended(reply),
			})
			if err != nil {
				t.Errorf("send EXTENDED: %v", err)
				return
			}
			// Wrap back up through the earlier hops.
			for j := i - 1; j >= 0; j-- {
				back, err = WrapBackwardHop(path[j], back)
				if err != nil {
					t.Errorf("wrap backward at hop %d: %v", j+1, err)
					return
				}
			}
			if err := guardSide.WriteCell(back); err != nil {
				t.Error(err)
				return
			}
			result <- hw
		}
	}()

	if err := b.Extend(clientSide, circ, next.endpoint.Static, []byte(next.name), relays[len(relays)-1].af); err != nil {
		t.Fatalf("EXTEND: %v", err)
	}
	select {
	case hw := <-result:
		return hw
	case <-time.After(5 * time.Second):
		t.Fatal("EXTEND did not complete")
		return nil
	}
}

// TestCreateAgainstTheWrongStaticKeyIsDestroyed is §8.2's DoS defence on the
// wire: a client with a stale descriptor gets DESTROY(WRONG_KEY) and the relay
// does no scalar multiplication.
func TestCreateAgainstTheWrongStaticKeyIsDestroyed(t *testing.T) {
	relay := newTestRelay(t, "relay")
	other := newTestRelay(t, "other")

	_, body, err := NewClientHandshake(rand.Reader, other.endpoint.Static)
	if err != nil {
		t.Fatal(err)
	}
	out, hw, err := relay.endpoint.AnswerCreate(&link.Cell{
		Circuit: 9, Command: link.CmdCreate, Payload: EncodeCreate(HTypeNtorV1, body),
	})
	if !errors.Is(err, ErrWrongKey) {
		t.Fatalf("err = %v, want ErrWrongKey", err)
	}
	if hw != nil {
		t.Fatal("key material was derived for a handshake aimed elsewhere")
	}
	if out.Command != link.CmdDestroy {
		t.Fatalf("answer = %s, want DESTROY", out.Command)
	}
	if destroyReason(out) != ReasonWrongKey {
		t.Fatalf("reason = %d, want ReasonWrongKey", destroyReason(out))
	}
}

// TestUnsupportedHandshakeTypeIsRefused: HTYPE 0x0002 is reserved and not
// implemented in v1, and a reserved code must be refused rather than ignored.
func TestUnsupportedHandshakeTypeIsRefused(t *testing.T) {
	relay := newTestRelay(t, "relay")
	_, body, err := NewClientHandshake(rand.Reader, relay.endpoint.Static)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := relay.endpoint.AnswerCreate(&link.Cell{
		Circuit: 1, Command: link.CmdCreate, Payload: EncodeCreate(HTypeNtorHybrid, body),
	})
	if !errors.Is(err, ErrHandshakeType) {
		t.Fatalf("err = %v, want ErrHandshakeType", err)
	}
	if out.Command != link.CmdDestroy {
		t.Fatalf("answer = %s, want DESTROY", out.Command)
	}
}

// TestExtendNamingTheRelayItself is T5.7 at the relay, where the client cannot
// be trusted to have applied the rule.
func TestExtendNamingTheRelayItself(t *testing.T) {
	relay := newTestRelay(t, "relay")
	self := relay.endpoint.Static.ID()
	msg := &RelayCell{Stream: 0, Cmd: RCmdExtend,
		Data: EncodeExtend(self, []byte("addr"), HTypeNtorV1, make([]byte, CreateBodySize))}
	if _, err := ParseExtend(&RelayCircuit{}, self, msg); !errors.Is(err, ErrExtendToSelf) {
		t.Fatalf("err = %v, want ErrExtendToSelf", err)
	}
}

// TestExtendBodyLengthsAreBounded: every length is checked against the remaining
// buffer before it is used. A length trusted before it is bounded is how a
// parser becomes a read primitive, and this one is reachable by any relay.
func TestExtendBodyLengthsAreBounded(t *testing.T) {
	var id [32]byte
	good := EncodeExtend(id, []byte("addr"), HTypeNtorV1, make([]byte, CreateBodySize))

	for _, tc := range []struct {
		name string
		mut  func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:10] }},
		{"link specs overrun", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[32], c[33] = 0xFF, 0xFF
			return c
		}},
		{"handshake overrun", func(b []byte) []byte {
			c := append([]byte(nil), b...)
			c[len(c)-CreateBodySize-2], c[len(c)-CreateBodySize-1] = 0xFF, 0xFF
			return c
		}},
		{"empty", func([]byte) []byte { return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, _, _, err := DecodeExtend(tc.mut(good)); err == nil {
				t.Fatal("malformed EXTEND body was accepted")
			}
		})
	}

	// The good one still parses, so the bounds are not simply refusing
	// everything.
	gotID, ls, htype, hs, err := DecodeExtend(good)
	if err != nil {
		t.Fatal(err)
	}
	if gotID != id || string(ls) != "addr" || htype != HTypeNtorV1 || len(hs) != CreateBodySize {
		t.Fatal("a well-formed EXTEND body did not round trip")
	}
}

// TestDestroyIsNeverOnioned: §8.1 requires each relay to emit its own DESTROY
// rather than forward one verbatim.
func TestDestroyIsNeverOnioned(t *testing.T) {
	c := DestroyCell(7, ReasonTimeout)
	if c.Command.Onioned() {
		t.Fatal("DESTROY is marked onioned")
	}
	if c.Circuit != 7 {
		t.Fatalf("circuit = %d, want 7", c.Circuit)
	}
	if destroyReason(c) != ReasonTimeout {
		t.Fatal("reason code did not survive")
	}
	// It must survive the real codec, since it is sent on a live link.
	var buf [1024]byte
	if err := c.Encode(buf[:]); err != nil {
		t.Fatal(err)
	}
	got, err := link.Decode(buf[:])
	if err != nil {
		t.Fatal(err)
	}
	if destroyReason(got) != ReasonTimeout {
		t.Fatal("reason code did not survive the wire")
	}
}

// TestCreateAndCreatedBodiesRoundTrip.
func TestCreateAndCreatedBodiesRoundTrip(t *testing.T) {
	hs := make([]byte, CreateBodySize)
	if _, err := rand.Read(hs); err != nil {
		t.Fatal(err)
	}
	htype, got, err := DecodeCreate(EncodeCreate(HTypeNtorV1, hs))
	if err != nil {
		t.Fatal(err)
	}
	if htype != HTypeNtorV1 || !bytes.Equal(got, hs) {
		t.Fatal("CREATE body did not round trip")
	}

	reply := make([]byte, CreatedBodySize)
	if _, err := rand.Read(reply); err != nil {
		t.Fatal(err)
	}
	got2, err := DecodeCreated(EncodeCreated(reply))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got2, reply) {
		t.Fatal("CREATED body did not round trip")
	}
	if _, err := DecodeCreated([]byte{0x00}); err == nil {
		t.Fatal("a truncated CREATED body was accepted")
	}
}

// longestCommonRun returns the length of the longest common substring, capped so
// the scan stays bounded. It is how T5.1's "share no common substring" is turned
// into something a test can assert.
func longestCommonRun(a, b []byte, capAt int) int {
	for i := 0; i+capAt <= len(a); i++ {
		if bytes.Contains(b, a[i:i+capAt]) {
			return capAt
		}
	}
	for n := capAt - 1; n > 0; n-- {
		for i := 0; i+n <= len(a); i++ {
			if bytes.Contains(b, a[i:i+n]) {
				return n
			}
		}
	}
	return 0
}
