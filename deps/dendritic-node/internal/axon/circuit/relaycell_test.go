package circuit

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestRelayCellRoundTrips(t *testing.T) {
	for _, n := range []int{0, 1, 100, RelayDataSize} {
		in := &RelayCell{Stream: 7, Cmd: RCmdData, Flags: RFlagAckReq,
			Data: bytes.Repeat([]byte{0xAB}, n)}
		inner, err := in.Encode()
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if len(inner) != InnerSize {
			t.Fatalf("len %d: inner is %d bytes, want %d", n, len(inner), InnerSize)
		}
		out, err := DecodeRelay(inner)
		if err != nil {
			t.Fatalf("len %d: %v", n, err)
		}
		if out.Stream != in.Stream || out.Cmd != in.Cmd || out.Flags != in.Flags {
			t.Fatalf("len %d: header round trip failed: %+v", n, out)
		}
		if !bytes.Equal(out.Data, in.Data) {
			t.Fatalf("len %d: data round trip failed", n)
		}
	}
}

// TestRelayCapacityReclaimedFromTheTagStack.
func TestRelayCapacityReclaimedFromTheTagStack(t *testing.T) {
	if RelayDataSize != 984 {
		t.Fatalf("RelayDataSize = %d, want 984 (1008 body - 16 auth - 8 relay header)",
			RelayDataSize)
	}
	// §8.1's original arithmetic gave 936 bytes of relay data.
	if RelayDataSize <= 936 {
		t.Fatalf("RelayDataSize = %d; the withdrawn format gave 936", RelayDataSize)
	}
}

// TestCircuitScopedCommandsRejectStreamIDs is §8.1's rule that scope is what
// stops control commands being confused with stream traffic.
func TestCircuitScopedCommandsRejectStreamIDs(t *testing.T) {
	for _, cmd := range []RCmd{RCmdExtend, RCmdExtended, RCmdTruncate, RCmdTruncated, RCmdDrop} {
		c := &RelayCell{Stream: 5, Cmd: cmd}
		if _, err := c.Encode(); !errors.Is(err, ErrRelayScope) {
			t.Errorf("%s with a stream id was accepted: %v", cmd, err)
		}
	}
	// And stream commands must carry one.
	for _, cmd := range []RCmd{RCmdBegin, RCmdData, RCmdEnd, RCmdConnected} {
		c := &RelayCell{Stream: 0, Cmd: cmd}
		if _, err := c.Encode(); !errors.Is(err, ErrRelayScope) {
			t.Errorf("%s without a stream id was accepted: %v", cmd, err)
		}
	}
	// SENDME is valid at either scope.
	for _, id := range []StreamID{0, 3} {
		c := &RelayCell{Stream: id, Cmd: RCmdSendme}
		if _, err := c.Encode(); err != nil {
			t.Errorf("SENDME at stream %d rejected: %v", id, err)
		}
	}
}

// TestScopeIsCheckedOnDecodeToo: a peer that ignores the rule must not be able
// to smuggle a control command in as stream traffic.
func TestScopeIsCheckedOnDecodeToo(t *testing.T) {
	c := &RelayCell{Stream: 0, Cmd: RCmdDrop}
	inner, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(inner[offStreamID:], 9) // now scope-violating
	if _, err := DecodeRelay(inner); !errors.Is(err, ErrRelayScope) {
		t.Fatalf("a scope violation survived decode: %v", err)
	}
}

func TestRelayDecodeRejectsMalformed(t *testing.T) {
	good := &RelayCell{Stream: 3, Cmd: RCmdData, Data: []byte("x")}
	base, err := good.Encode()
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown command", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offRCmd] = 0x7e
		if _, err := DecodeRelay(b); !errors.Is(err, ErrRelayBadCmd) {
			t.Fatalf("accepted unknown command: %v", err)
		}
	})
	t.Run("unknown flag bits", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offRFlags] = 0xFC
		if _, err := DecodeRelay(b); !errors.Is(err, ErrRelayBadFlags) {
			t.Fatalf("accepted unknown flags: %v", err)
		}
	})
	t.Run("reserved not zero", func(t *testing.T) {
		b := append([]byte(nil), base...)
		b[offRReserved] = 1
		if _, err := DecodeRelay(b); !errors.Is(err, ErrRelayReserved) {
			t.Fatalf("accepted non-zero reserved: %v", err)
		}
	})
	t.Run("length beyond capacity", func(t *testing.T) {
		b := append([]byte(nil), base...)
		binary.BigEndian.PutUint16(b[offRLen:], uint16(RelayDataSize+1))
		if _, err := DecodeRelay(b); !errors.Is(err, ErrRelayBadLen) {
			t.Fatalf("accepted oversize length: %v", err)
		}
	})
	t.Run("short region", func(t *testing.T) {
		if _, err := DecodeRelay(base[:4]); !errors.Is(err, ErrRelayShort) {
			t.Fatalf("accepted a short region: %v", err)
		}
	})
}

// TestPaddingAfterRLenIsNotChecked is §8.6's explicit exception to P2's
// padding-must-be-zero rule.
//
// The tail is inside the permutation, so it cannot be a covert channel to a
// relay -- only the endpoint that decrypts ever sees it. Checking it would cost
// a pass over a kilobyte on every cell to defend against nothing.
func TestPaddingAfterRLenIsNotChecked(t *testing.T) {
	c := &RelayCell{Stream: 3, Cmd: RCmdData, Data: []byte("five")}
	inner, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	for i := offRData + 4; i < len(inner); i++ {
		inner[i] = 0xFF
	}
	out, err := DecodeRelay(inner)
	if err != nil {
		t.Fatalf("a scribbled tail was rejected: %v", err)
	}
	if string(out.Data) != "five" {
		t.Fatalf("data = %q, want %q -- the tail leaked into the payload", out.Data, "five")
	}
}

// TestEncodeClearsTheTail: the whole region is written every time, so a reused
// buffer cannot carry the previous message's plaintext into this one's padding.
func TestEncodeClearsTheTail(t *testing.T) {
	long := &RelayCell{Stream: 1, Cmd: RCmdData, Data: bytes.Repeat([]byte{0x41}, 500)}
	a, err := long.Encode()
	if err != nil {
		t.Fatal(err)
	}
	short := &RelayCell{Stream: 1, Cmd: RCmdData, Data: []byte("hi")}
	b, err := short.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(b[offRData+2:], []byte{0x41, 0x41, 0x41, 0x41}) {
		t.Fatal("the previous message leaked into the padding")
	}
	_ = a
}

// TestStreamIDParity: the initiator uses odd ids, so the two ends of a
// rendezvous-joined circuit cannot collide.
func TestStreamIDParity(t *testing.T) {
	if !StreamID(1).IsInitiator() || StreamID(2).IsInitiator() {
		t.Fatal("stream id parity is backwards")
	}
}

// TestOversizeDataRefused.
func TestOversizeDataRefused(t *testing.T) {
	c := &RelayCell{Stream: 1, Cmd: RCmdData, Data: make([]byte, RelayDataSize+1)}
	if _, err := c.Encode(); !errors.Is(err, ErrRelayBadLen) {
		t.Fatalf("err = %v, want ErrRelayBadLen", err)
	}
}
