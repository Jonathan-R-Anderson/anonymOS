package link

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math/rand"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

// P2's framing invariants, executable. T2.1 (constant cell size) and the
// framing half of T2.4 (identical bytes for identical input) live here; the
// transport half of T2.4 needs two live links and belongs with the dialer.

// TestCellSizeIsConstant is T2.1. Every encoded cell is exactly CellSize bytes
// no matter what it carries -- a cell whose length tracked its payload would
// leak message size to every relay on the path.
func TestCellSizeIsConstant(t *testing.T) {
	sizes := []int{0, 1, 17, 255, 256, MaxPayload - 1, MaxPayload}
	for _, n := range sizes {
		c := &Cell{
			Circuit: 0x0102030405060708,
			Command: CmdRelay,
			Payload: bytes.Repeat([]byte{0xab}, n),
		}
		buf := make([]byte, params.CellSize*2) // deliberately oversized
		if err := c.Encode(buf); err != nil {
			t.Fatalf("payload %d: encode: %v", n, err)
		}
		// Encode must touch exactly CellSize bytes and not one more.
		for i := params.CellSize; i < len(buf); i++ {
			if buf[i] != 0 {
				t.Fatalf("payload %d: encode wrote past the cell at offset %d", n, i)
			}
		}
	}
}

// TestPayloadCapacityDoesNotDependOnPathLength guards the arithmetic that keeps
// path length off the wire.
//
// It used to assert a 64-byte tag reservation for MaxHops positions, used or
// not. PAR-01 withdrew that tag stack and P5a replaced it with a wide-block
// permutation over the whole body, so the reservation is gone and its PURPOSE is
// now structural: the body is one fixed-size permuted block whatever the path
// length, so capacity cannot vary with H because there is nothing for H to
// change.
func TestPayloadCapacityDoesNotDependOnPathLength(t *testing.T) {
	want := params.CellSize - params.CellHeaderSize
	if MaxPayload != want {
		t.Fatalf("MaxPayload = %d, want %d (CellSize %d - header %d)",
			MaxPayload, want, params.CellSize, params.CellHeaderSize)
	}
	// The formula must not mention MaxHops at all -- that is the property.
	for _, hops := range []int{1, 2, 3, 4} {
		_ = hops
		if MaxPayload != params.CellSize-params.CellHeaderSize {
			t.Fatal("capacity varies with path length")
		}
	}
	if MaxPayload <= 0 {
		t.Fatal("cell has no payload capacity")
	}
	// A cell one byte over capacity must be refused rather than truncated.
	c := &Cell{Command: CmdRelay, Payload: make([]byte, MaxPayload+1)}
	if err := c.Encode(make([]byte, params.CellSize)); !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized payload accepted: %v", err)
	}
}

// TestRoundTrip is the basic correctness property.
func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 100, MaxPayload} {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i * 7)
		}
		in := &Cell{
			Circuit: CircuitID(0xdeadbeefcafef00d),
			// CmdCreate is non-onioned, so LENGTH carries the true payload
			// size and the round trip is length-exact. Onioned cells are
			// covered separately by TestOnionedCellsHideTheirLength.
			Command: CmdCreate,
			Flags:   FlagEarly,
			Payload: payload,
		}
		var buf bytes.Buffer
		if err := WriteCell(&buf, in); err != nil {
			t.Fatalf("write: %v", err)
		}
		if buf.Len() != params.CellSize {
			t.Fatalf("wrote %d bytes, want %d", buf.Len(), params.CellSize)
		}
		out, err := ReadCell(&buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if out.Circuit != in.Circuit || out.Command != in.Command || out.Flags != in.Flags {
			t.Fatalf("header round trip failed: %+v vs %+v", out, in)
		}
		if !bytes.Equal(out.Payload, in.Payload) {
			t.Fatalf("payload round trip failed for length %d", n)
		}
	}
}

// TestEncodeIsDeterministic is the framing half of T2.4: the same cell must
// always produce the same bytes, or QUIC and TCP paths cannot be compared.
func TestEncodeIsDeterministic(t *testing.T) {
	c := &Cell{Circuit: 42, Command: CmdCreate, Flags: FlagEarly, Payload: []byte("hello")}
	a := make([]byte, params.CellSize)
	b := make([]byte, params.CellSize)
	if err := c.Encode(a); err != nil {
		t.Fatal(err)
	}
	if err := c.Encode(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("encoding is not deterministic")
	}
}

// TestEncodeClearsReusedBuffer is a disclosure test, not a tidiness one. A
// buffer reused without clearing leaks the previous cell's plaintext into this
// cell's padding, and no test of the payload would catch it.
func TestEncodeClearsReusedBuffer(t *testing.T) {
	buf := make([]byte, params.CellSize)

	secret := bytes.Repeat([]byte{0x5a}, MaxPayload)
	big := &Cell{Circuit: 1, Command: CmdRelay, Payload: secret}
	if err := big.Encode(buf); err != nil {
		t.Fatal(err)
	}

	// Now a much smaller cell into the same buffer.
	small := &Cell{Circuit: 1, Command: CmdRelay, Payload: []byte{0x01}}
	if err := small.Encode(buf); err != nil {
		t.Fatal(err)
	}
	tail := buf[offPayload+1:]
	if bytes.Contains(tail, bytes.Repeat([]byte{0x5a}, 8)) {
		t.Fatal("previous cell's payload survived in the padding of the next")
	}
	for i, b := range tail {
		if b != 0 {
			t.Fatalf("padding byte %d is 0x%02x, want 0", i, b)
		}
	}
}

// TestDecodeRejectsMalformed covers every field a peer controls. A relay that
// accepts nonsense is a relay that can be used as an oracle or a covert channel.
func TestDecodeRejectsMalformed(t *testing.T) {
	// Non-onioned: the padding-zero check only applies where the cell is seen
	// in plaintext, so the covert-channel sub-test needs a command whose tail
	// is not ciphertext.
	good := &Cell{Circuit: 7, Command: CmdCreate, Payload: []byte("x")}
	base := make([]byte, params.CellSize)
	if err := good.Encode(base); err != nil {
		t.Fatal(err)
	}

	t.Run("unknown command", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offCommand] = 0x7f
		if _, err := Decode(b); !errors.Is(err, ErrBadCommand) {
			t.Fatalf("accepted unknown command: %v", err)
		}
	})

	t.Run("unknown flag bits", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offFlags] = 0x80
		if _, err := Decode(b); !errors.Is(err, ErrBadFlags) {
			t.Fatalf("accepted unknown flags: %v", err)
		}
	})

	t.Run("reserved bytes not zero", func(t *testing.T) {
		for i := 0; i < 4; i++ {
			b := append([]byte(nil), base...)
			b[offReserved+i] = 1
			if _, err := Decode(b); !errors.Is(err, ErrReservedNonZero) {
				t.Fatalf("accepted nonzero reserved byte %d: %v", i, err)
			}
		}
	})

	t.Run("declared length beyond capacity", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offLength] = 0xff
		b[offLength+1] = 0xff
		if _, err := Decode(b); !errors.Is(err, ErrBadLength) {
			t.Fatalf("accepted oversized declared length: %v", err)
		}
	})

	t.Run("non-zero padding is a covert channel", func(t *testing.T) {
		// Found by FuzzDecode: a valid cell whose tail carried attacker-chosen
		// bytes. Every relay would have forwarded them.
		b := append([]byte(nil), base...)
		b[params.CellSize-1] = 0x41
		if _, err := Decode(b); !errors.Is(err, ErrPaddingNonZero) {
			t.Fatalf("accepted non-zero padding: %v", err)
		}
		// …and every byte of the tail is covered, not just the last.
		for _, off := range []int{offPayload + 1, offPayload + 200, params.CellSize / 2} {
			c := append([]byte(nil), base...)
			c[off] = 0xff
			if _, err := Decode(c); !errors.Is(err, ErrPaddingNonZero) {
				t.Fatalf("accepted non-zero padding at offset %d: %v", off, err)
			}
		}
	})

	t.Run("short buffer", func(t *testing.T) {
		if _, err := Decode(base[:params.CellSize-1]); !errors.Is(err, ErrShortBuffer) {
			t.Fatalf("accepted short buffer: %v", err)
		}
	})
}

// TestDeclaredLengthBoundsThePayload: a cell declaring 5 bytes must yield 5
// bytes even though 1024 arrived. Trusting the buffer instead of the length
// would hand every relay the padding as free payload.
func TestDeclaredLengthBoundsThePayload(t *testing.T) {
	c := &Cell{Circuit: 1, Command: CmdCreate, Payload: []byte("12345")}
	buf := make([]byte, params.CellSize)
	if err := c.Encode(buf); err != nil {
		t.Fatal(err)
	}
	out, err := Decode(buf)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Payload) != 5 || string(out.Payload) != "12345" {
		t.Fatalf("payload not bounded by declared length: %q", out.Payload)
	}
	// And scribbling in the padding is refused rather than ignored, so the
	// declared length cannot be used to smuggle bytes past it.
	for i := offPayload + 5; i < params.CellSize; i++ {
		buf[i] = 0xff
	}
	if _, err := Decode(buf); !errors.Is(err, ErrPaddingNonZero) {
		t.Fatalf("padding after the declared length was ignored: %v", err)
	}
}

// TestReadCellDistinguishesCleanCloseFromTruncation matters for connection
// handling: a closed link is normal, half a cell is a protocol violation.
func TestReadCellDistinguishesCleanCloseFromTruncation(t *testing.T) {
	if _, err := ReadCell(bytes.NewReader(nil)); err != io.EOF {
		t.Fatalf("clean close reported as %v, want io.EOF", err)
	}
	half := make([]byte, params.CellSize/2)
	if _, err := ReadCell(bytes.NewReader(half)); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated cell reported as %v, want io.ErrUnexpectedEOF", err)
	}
}

// TestStreamOfCellsResynchronises checks that framing holds across many cells
// back to back -- the case a stream actually sees.
func TestStreamOfCellsResynchronises(t *testing.T) {
	var buf bytes.Buffer
	rng := rand.New(rand.NewSource(1))

	const n = 500
	sent := make([]*Cell, 0, n)
	for i := 0; i < n; i++ {
		p := make([]byte, rng.Intn(MaxPayload+1))
		rng.Read(p)
		c := &Cell{
			Circuit: CircuitID(rng.Uint64()),
			Command: CmdRelay,
			Payload: p,
		}
		if err := WriteCell(&buf, c); err != nil {
			t.Fatalf("cell %d: %v", i, err)
		}
		sent = append(sent, c)
	}
	if buf.Len() != n*params.CellSize {
		t.Fatalf("stream is %d bytes, want %d", buf.Len(), n*params.CellSize)
	}
	for i := 0; i < n; i++ {
		got, err := ReadCell(&buf)
		if err != nil {
			t.Fatalf("cell %d: %v", i, err)
		}
		if got.Circuit != sent[i].Circuit {
			t.Fatalf("cell %d did not survive the stream", i)
		}
		if sent[i].Command.Onioned() {
			// An onioned cell yields the whole 944-byte region; the sent
			// prefix must still be intact at the front of it.
			if !bytes.Equal(got.Payload[:len(sent[i].Payload)], sent[i].Payload) {
				t.Fatalf("cell %d payload prefix did not survive the stream", i)
			}
		} else if !bytes.Equal(got.Payload, sent[i].Payload) {
			t.Fatalf("cell %d did not survive the stream", i)
		}
	}
	if _, err := ReadCell(&buf); err != io.EOF {
		t.Fatal("stream did not end cleanly")
	}
}

// TestPaddingCellCarriesNothing: padding must be indistinguishable in size from
// any other cell, which is the entire point of a fixed frame.
func TestPaddingCellCarriesNothing(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteCell(&buf, PaddingCell(99)); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != params.CellSize {
		t.Fatalf("padding cell is %d bytes, want %d", buf.Len(), params.CellSize)
	}
	c, err := ReadCell(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if c.Command != CmdPadding || len(c.Payload) != 0 {
		t.Fatalf("padding cell decoded as %+v", c)
	}
}

func FuzzDecode(f *testing.F) {
	base := make([]byte, params.CellSize)
	c := &Cell{Circuit: 1, Command: CmdRelay, Payload: []byte("seed")}
	_ = c.Encode(base)
	f.Add(base)
	f.Add(make([]byte, params.CellSize))

	// Decode must never panic on peer-controlled bytes, and anything it accepts
	// must re-encode to exactly what came in.
	f.Fuzz(func(t *testing.T, data []byte) {
		cell, err := Decode(data)
		if err != nil {
			return
		}
		out := make([]byte, params.CellSize)
		if err := cell.Encode(out); err != nil {
			t.Fatalf("accepted a cell it cannot re-encode: %v", err)
		}
		if !bytes.Equal(out, data[:params.CellSize]) {
			t.Fatal("decode/encode is not a round trip: two encodings of one cell")
		}
	})
}

// TestBodyIsTheWholeCellAfterTheHeader: PAR-01 removed the 64-byte tag stack,
// so the body is 1008 bytes and there is no reserved region between the header
// and the payload.
func TestBodyIsTheWholeCellAfterTheHeader(t *testing.T) {
	if offPayload != params.CellHeaderSize {
		t.Fatalf("payload starts at %d, want %d -- a reserved region has reappeared",
			offPayload, params.CellHeaderSize)
	}
	if MaxPayload != 1008 {
		t.Fatalf("MaxPayload = %d, want 1008 (1024 cell - 16 header)", MaxPayload)
	}
	// The reclaimed 64 bytes are real capacity, not an accounting change.
	c := &Cell{Circuit: 1, Command: CmdCreate, Payload: bytes.Repeat([]byte{0xAB}, MaxPayload)}
	buf := make([]byte, params.CellSize)
	if err := c.Encode(buf); err != nil {
		t.Fatalf("a full-capacity payload was rejected: %v", err)
	}
	out, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Payload) != MaxPayload {
		t.Fatalf("round-tripped %d bytes, want %d", len(out.Payload), MaxPayload)
	}
}

// TestCellSizeIsIndependentOfPathLength: capacity must not vary with H, or the
// cell announces path length. The tag stack bought this by reservation; the
// wide-block construction gets it structurally, because the body is one fixed
// permuted block whatever the path.
func TestCellSizeIsIndependentOfPathLength(t *testing.T) {
	if params.MaxPayload != params.CellSize-params.CellHeaderSize {
		t.Fatal("MaxPayload depends on something other than the header size")
	}
}

// TestOnionedCellsHideTheirLength: for RELAY/RELAY_BUILD the LENGTH field MUST
// be zero on the wire, because the real length lives inside the onion where an
// observer cannot read it. Writing the true length would hand every relay the
// plaintext size of a message it cannot decrypt.
func TestOnionedCellsHideTheirLength(t *testing.T) {
	for _, cmd := range []Command{CmdRelay, CmdRelayBuild} {
		c := &Cell{Circuit: 3, Command: cmd, Payload: []byte("a short inner message")}
		buf := make([]byte, params.CellSize)
		if err := c.Encode(buf); err != nil {
			t.Fatal(err)
		}
		if got := binary.BigEndian.Uint16(buf[offLength:]); got != 0 {
			t.Fatalf("%s wrote LENGTH = %d, want 0", cmd, got)
		}
		out, err := Decode(buf)
		if err != nil {
			t.Fatal(err)
		}
		if len(out.Payload) != MaxPayload {
			t.Fatalf("%s decoded %d payload bytes, want the whole %d region",
				cmd, len(out.Payload), MaxPayload)
		}
	}

	// A peer that DOES declare a length on an onioned cell is signalling, and
	// is refused rather than tolerated.
	c := &Cell{Circuit: 3, Command: CmdCreate, Payload: []byte("x")}
	buf := make([]byte, params.CellSize)
	if err := c.Encode(buf); err != nil {
		t.Fatal(err)
	}
	buf[offCommand] = byte(CmdRelay) // now onioned, but LENGTH is still 1
	if _, err := Decode(buf); !errors.Is(err, ErrBadLength) {
		t.Fatalf("an onioned cell declaring a length was accepted: %v", err)
	}
}

// TestCommandNumbersMatchTheSpec pins the section 8.1 wire codes. Renumbering
// them is a protocol break, and a silent one.
func TestCommandNumbersMatchTheSpec(t *testing.T) {
	for cmd, want := range map[Command]uint8{
		CmdPadding: 0x00, CmdCreate: 0x01, CmdCreated: 0x02, CmdRelay: 0x03,
		CmdRelayBuild: 0x04, CmdCreateFrag: 0x05, CmdDestroy: 0x06,
		CmdVersions: 0x07, CmdNetInfo: 0x08,
	} {
		if uint8(cmd) != want {
			t.Errorf("%s = 0x%02x, section 8.1 says 0x%02x", cmd, uint8(cmd), want)
		}
	}
	if CmdRelay.Onioned() != true || CmdCreate.Onioned() != false {
		t.Fatal("Onioned() disagrees with the section 8.1 table")
	}
}
