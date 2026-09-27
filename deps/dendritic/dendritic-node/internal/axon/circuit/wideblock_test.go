package circuit

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"math/bits"
	"testing"
)

// P5a's exit criteria and tests.

func wideHops(t *testing.T, n int) (clients, relays []*HopWide) {
	t.Helper()
	for i := 0; i < n; i++ {
		static, b := newRelayStatic(t)
		h, createBody, err := NewClientHandshake(rand.Reader, static)
		if err != nil {
			t.Fatal(err)
		}
		relayKeys, reply, err := ServerHandshake(rand.Reader, static, b, createBody)
		if err != nil {
			t.Fatal(err)
		}
		clientKeys, err := h.Complete(reply)
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewHopWide(clientKeys)
		if err != nil {
			t.Fatal(err)
		}
		r, err := NewHopWide(relayKeys)
		if err != nil {
			t.Fatal(err)
		}
		clients = append(clients, c)
		relays = append(relays, r)
	}
	return clients, relays
}

func randBlock(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, BlockSize)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// TestWideBlockRoundTrips is the permutation property.
func TestWideBlockRoundTrips(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	for tweak := uint64(0); tweak < 8; tweak++ {
		plain := randBlock(t)
		block := append([]byte(nil), plain...)
		if err := w.Encipher(block, tweak); err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(block, plain) {
			t.Fatal("enciphering was a no-op")
		}
		if err := w.Decipher(block, tweak); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(block, plain) {
			t.Fatalf("tweak %d: round trip failed", tweak)
		}
	}
}

// TestZeroExpansion: the block does not grow, which is the whole reason a PRP
// was needed rather than nested AEAD.
func TestZeroExpansion(t *testing.T) {
	var key [32]byte
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	block := randBlock(t)
	before := len(block)
	if err := w.Encipher(block, 0); err != nil {
		t.Fatal(err)
	}
	if len(block) != before {
		t.Fatalf("block grew from %d to %d", before, len(block))
	}
	if BlockSize != 1008 {
		t.Fatalf("BlockSize = %d, want 1008 (1024 cell - 16 header)", BlockSize)
	}
	// The reclaimed tag stack shows up as more usable payload.
	if RelayDataSize <= 936 {
		t.Fatalf("RelayDataSize = %d; the withdrawn format allowed 936, so the "+
			"64-byte tag stack was not reclaimed", RelayDataSize)
	}
}

// TestAvalanche is the strong-PRP property that replaces per-hop authentication:
// ANY modification randomises the whole block, so a tagger cannot make a
// targeted change that survives.
func TestAvalanche(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}

	plain := randBlock(t)
	ct := append([]byte(nil), plain...)
	if err := w.Encipher(ct, 7); err != nil {
		t.Fatal(err)
	}

	// Flip one bit of ciphertext at several positions, including the very last,
	// and confirm the recovered plaintext is unrelated to the original.
	for _, pos := range []int{0, 1, lSize - 1, lSize, BlockSize / 2, BlockSize - 1} {
		tampered := append([]byte(nil), ct...)
		tampered[pos] ^= 0x01
		if err := w.Decipher(tampered, 7); err != nil {
			t.Fatal(err)
		}

		diff := 0
		for i := range tampered {
			diff += bits.OnesCount8(tampered[i] ^ plain[i])
		}
		total := BlockSize * 8
		frac := float64(diff) / float64(total)
		if frac < 0.45 || frac > 0.55 {
			t.Fatalf("flipping bit at byte %d changed %.1f%% of plaintext bits; "+
				"a strong PRP should change ~50%%", pos, frac*100)
		}
	}
}

// TestTweakSeparatesCells: without a tweak the permutation is fixed for the life
// of the circuit, so identical plaintexts would produce identical ciphertexts and
// a relay could recognise a repeated cell.
func TestTweakSeparatesCells(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	plain := randBlock(t)

	a := append([]byte(nil), plain...)
	b := append([]byte(nil), plain...)
	if err := w.Encipher(a, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.Encipher(b, 1); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("the same plaintext under two tweaks produced the same ciphertext")
	}
	// And a cell deciphered under the wrong tweak must not come back.
	if err := w.Decipher(a, 1); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, plain) {
		t.Fatal("a cell deciphered under the wrong tweak recovered the plaintext")
	}
}

// TestNoCrossHopChannel is T5a.1 and the direct inverse of
// TestTagStackFillerIsACrossHopChannel: no byte a hop can choose reaches any
// downstream hop unaltered.
func TestNoCrossHopChannel(t *testing.T) {
	clients, relays := wideHops(t, 3)

	msg := []byte("a relay message")
	af, _ := clients[2].fwd, clients[2].bwd
	_ = af
	var terminalAf [32]byte
	block, err := SealInnermost(terminalAf, padInner(msg))
	if err != nil {
		t.Fatal(err)
	}
	if err := WideSealForward(clients, block); err != nil {
		t.Fatal(err)
	}

	// Hop 1 peels, then tries to plant a recognisable mark anywhere it likes.
	if err := WideOpenForwardAtHop(relays[0], block); err != nil {
		t.Fatal(err)
	}
	mark := bytes.Repeat([]byte{0xC0, 0xFF, 0xEE, 0x01}, 4)
	copy(block[BlockSize-len(mark):], mark)

	// Hop 2 peels and forwards to hop 3.
	if err := WideOpenForwardAtHop(relays[1], block); err != nil {
		t.Fatal(err)
	}
	atHop3 := append([]byte(nil), block...)
	if err := WideOpenForwardAtHop(relays[2], block); err != nil {
		t.Fatal(err)
	}

	for name, view := range map[string][]byte{"hop 3 inbound": atHop3, "hop 3 after peel": block} {
		if bytes.Contains(view, mark) {
			t.Fatalf("PAR-01 not closed: hop 1's mark survives to %s", name)
		}
		// Nothing shorter survives either -- a 4-byte run is enough to signal.
		for i := 0; i+4 <= len(mark); i++ {
			if bytes.Contains(view, mark[i:i+4]) {
				t.Fatalf("PAR-01 not closed: a 4-byte fragment of hop 1's mark "+
					"survives to %s", name)
			}
		}
	}
}

// TestEveryHopDoesTheIdenticalOperation is T5a.3: the format carries no evidence
// of circuit length or hop position.
//
// This is stronger than the rotating tag stack it replaces. That construction
// hid the slot INDEX; this one has no slots, no filler, no length-dependent
// field, and every hop calls the same function over the same 1008 bytes with no
// knowledge of the path.
func TestEveryHopDoesTheIdenticalOperation(t *testing.T) {
	for _, n := range []int{1, 2, 3, 4} {
		clients, relays := wideHops(t, n)
		var af [32]byte
		block, err := SealInnermost(af, padInner([]byte("x")))
		if err != nil {
			t.Fatal(err)
		}
		if err := WideSealForward(clients, block); err != nil {
			t.Fatalf("%d hops: %v", n, err)
		}
		if len(block) != BlockSize {
			t.Fatalf("%d hops: block is %d bytes, want %d", n, len(block), BlockSize)
		}
		for i, r := range relays {
			// No index is passed, and none is available to the hop.
			if err := WideOpenForwardAtHop(r, block); err != nil {
				t.Fatalf("%d hops, hop %d: %v", n, i+1, err)
			}
			if len(block) != BlockSize {
				t.Fatalf("%d hops: block changed size at hop %d", n, i+1)
			}
		}
		inner, err := OpenInnermost(af, block)
		if err != nil {
			t.Fatalf("%d hops: terminal could not open: %v", n, err)
		}
		if !bytes.HasPrefix(inner, []byte("x")) {
			t.Fatalf("%d hops: inner = %q", n, inner[:8])
		}
	}
}

// TestCellSizeIdenticalForEveryPathLength is E5a.3, and it is what makes P22's
// variable path length safe to build on this.
func TestCellSizeIdenticalForEveryPathLength(t *testing.T) {
	sizes := map[int]int{}
	for _, n := range []int{1, 2, 3, 4} {
		clients, _ := wideHops(t, n)
		var af [32]byte
		block, err := SealInnermost(af, padInner(bytes.Repeat([]byte{0xAB}, 100)))
		if err != nil {
			t.Fatal(err)
		}
		if err := WideSealForward(clients, block); err != nil {
			t.Fatal(err)
		}
		sizes[n] = len(block)
	}
	for n, s := range sizes {
		if s != BlockSize {
			t.Fatalf("H=%d produced a %d-byte block, want %d", n, s, BlockSize)
		}
	}
}

// TestEndToEndAuthCatchesTampering: the PRP has no authenticator, so the
// terminal's check is what detects corruption. This test also pins the
// REGRESSION: no intermediate hop detects it.
func TestEndToEndAuthCatchesTampering(t *testing.T) {
	clients, relays := wideHops(t, 3)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}

	block, err := SealInnermost(af, padInner([]byte("payload that must not be altered")))
	if err != nil {
		t.Fatal(err)
	}
	if err := WideSealForward(clients, block); err != nil {
		t.Fatal(err)
	}

	// Hop 1 peels and tampers.
	if err := WideOpenForwardAtHop(relays[0], block); err != nil {
		t.Fatal(err)
	}
	block[500] ^= 0x01

	// THE REGRESSION, asserted rather than described: hop 2 does not notice.
	// A PRP has nothing to check, so it forwards randomised bytes.
	if err := WideOpenForwardAtHop(relays[1], block); err != nil {
		t.Fatalf("an intermediate hop reported an error it cannot detect: %v", err)
	}
	if err := WideOpenForwardAtHop(relays[2], block); err != nil {
		t.Fatal(err)
	}

	// The terminal does notice.
	if _, err := OpenInnermost(af, block); !errors.Is(err, ErrIntegrity) {
		t.Fatalf("terminal accepted a tampered cell: %v", err)
	}
}

// TestBackwardRoundTrip.
func TestBackwardRoundTrip(t *testing.T) {
	clients, relays := wideHops(t, 3)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}

	block, err := SealInnermost(af, padInner([]byte("reply")))
	if err != nil {
		t.Fatal(err)
	}
	for i := len(relays) - 1; i >= 0; i-- {
		if err := WideSealBackwardAtHop(relays[i], block); err != nil {
			t.Fatal(err)
		}
	}
	if err := WideOpenBackwardAtClient(clients, block); err != nil {
		t.Fatal(err)
	}
	inner, err := OpenInnermost(af, block)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(inner, []byte("reply")) {
		t.Fatalf("inner = %q, want prefix %q", inner[:8], "reply")
	}
}

// TestReplayFailsOnTheCounter: the counter is the tweak, so a replayed cell is
// deciphered under a permutation that has moved on.
func TestReplayFailsOnTheCounter(t *testing.T) {
	clients, relays := wideHops(t, 1)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}
	block, err := SealInnermost(af, padInner([]byte("once")))
	if err != nil {
		t.Fatal(err)
	}
	if err := WideSealForward(clients, block); err != nil {
		t.Fatal(err)
	}
	captured := append([]byte(nil), block...)

	if err := WideOpenForwardAtHop(relays[0], block); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInnermost(af, block); err != nil {
		t.Fatal(err)
	}

	replay := append([]byte(nil), captured...)
	if err := WideOpenForwardAtHop(relays[0], replay); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenInnermost(af, replay); !errors.Is(err, ErrIntegrity) {
		t.Fatal("a replayed cell was accepted")
	}
}

// TestRoundKeysAreIndependent: four rounds of the SAME function is not four
// independent rounds, and the Luby-Rackoff argument does not apply to it.
func TestRoundKeysAreIndependent(t *testing.T) {
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[[32]byte]int{}
	for i, k := range [][32]byte{w.k1, w.k2, w.k3, w.k4} {
		if prev, dup := seen[k]; dup {
			t.Fatalf("round keys %d and %d are identical", prev+1, i+1)
		}
		seen[k] = i
	}
}

// TestWrongBlockSizeRefused.
func TestWrongBlockSizeRefused(t *testing.T) {
	var key [32]byte
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Encipher(make([]byte, 100), 0); !errors.Is(err, ErrBlockSize) {
		t.Fatalf("err = %v, want ErrBlockSize", err)
	}
}

// TestWrongInnerSizeRefused: the inner region is fixed, and a short one is a bug
// rather than something to pad silently -- padding it here would put a second
// length authority in the code, which is what the relay header's RLEN exists to
// be the only one of.
func TestWrongInnerSizeRefused(t *testing.T) {
	var af [32]byte
	if _, err := SealInnermost(af, make([]byte, InnerSize+1)); err == nil {
		t.Fatal("an oversize inner region was accepted")
	}
	if _, err := SealInnermost(af, make([]byte, InnerSize-1)); err == nil {
		t.Fatal("a short inner region was accepted")
	}
}

// padInner places a short message at the front of a full-size inner region, for
// tests that care about the permutation rather than the relay format.
func padInner(msg []byte) []byte {
	b := make([]byte, InnerSize)
	copy(b, msg)
	return b
}

// TestNoChannelOverMillionCells is E5a.1: over 10^6 cells, no 4-byte-or-longer
// sequence chosen by hop 1 appears anywhere in what hop 3 receives.
//
// Gated behind -soak for the same reason E2.1 is: a criterion worth stating is
// worth running deliberately, and a ten-second test nobody waits for is a test
// nobody runs.
func TestNoChannelOverMillionCells(t *testing.T) {
	if !*soak {
		t.Skip("E5a.1 soak: pass -soak to run 10^6 cells")
	}
	clients, relays := wideHops(t, 3)
	var af [32]byte
	if _, err := rand.Read(af[:]); err != nil {
		t.Fatal(err)
	}

	const cells = 1_000_000
	mark := []byte{0xC0, 0xFF, 0xEE, 0x01}
	hits := 0

	for i := 0; i < cells; i++ {
		block, err := SealInnermost(af, padInner([]byte{byte(i), byte(i >> 8)}))
		if err != nil {
			t.Fatal(err)
		}
		if err := WideSealForward(clients, block); err != nil {
			t.Fatal(err)
		}
		if err := WideOpenForwardAtHop(relays[0], block); err != nil {
			t.Fatal(err)
		}
		// Hop 1 plants its mark at a position that varies, so the test is not
		// checking one offset a million times.
		copy(block[i%(BlockSize-len(mark)):], mark)
		if err := WideOpenForwardAtHop(relays[1], block); err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(block, mark) {
			hits++
		}
	}
	// A 4-byte pattern occurs by chance in 1008 random bytes with probability
	// about 1005/2^32, so a handful of hits across 10^6 cells is arithmetic, not
	// a channel. Anything above that is a channel.
	const chanceBound = 10
	t.Logf("E5a.1: %d/%d cells contained hop 1's 4-byte mark at hop 3 (chance bound %d)",
		hits, cells, chanceBound)
	if hits > chanceBound {
		t.Fatalf("E5a.1 falsified: %d hits over %d cells exceeds the chance bound", hits, cells)
	}
}

// soak gates the long-running exit criteria, mirroring the link package's flag.
var soak = flag.Bool("soak", false, "run the E5a.1 10^6-cell channel soak")

// TestWideBlockGoldenVectors is T5a.5: a parameter change fails the build.
//
// It pins the round-key derivation label, the Feistel round order, the branch
// split, the tweak encoding and the round-index domain separation all at once.
// Any of them changing changes this digest, which is the point: a silent change
// to the permutation produces relays that cannot talk to the deployed network
// and gives no other signal.
func TestWideBlockGoldenVectors(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}
	w, err := NewWideBlock(key)
	if err != nil {
		t.Fatal(err)
	}

	block := make([]byte, BlockSize)
	for i := range block {
		block[i] = byte(i % 251)
	}
	if err := w.Encipher(block, 0x0102030405060708); err != nil {
		t.Fatal(err)
	}
	got := sha256.Sum256(block)

	if hex.EncodeToString(got[:]) != goldenWideBlock {
		t.Fatalf("T5a.5: the wide-block permutation changed.\n got %x\nwant %s\n"+
			"If this was intentional, the wire protocol changed and every deployed "+
			"relay must be updated in lockstep.", got, goldenWideBlock)
	}

	// The round keys are pinned too, so a change to the HKDF label is caught
	// even if it happened to leave the block digest alone.
	rk := sha256.New()
	for _, k := range [][32]byte{w.k1, w.k2, w.k3, w.k4} {
		rk.Write(k[:])
	}
	if hex.EncodeToString(rk.Sum(nil)) != goldenRoundKeys {
		t.Fatal("T5a.5: the round-key derivation changed")
	}
	if wideBlockLabel != "AXON-wideblock-lioness-v1" {
		t.Fatal("T5a.5: the wide-block domain-separation label was renamed")
	}
	// And the branch split, which the Luby-Rackoff argument depends on.
	if lSize != 32 || rSize != BlockSize-32 {
		t.Fatalf("T5a.5: Feistel branch split changed to %d/%d", lSize, rSize)
	}
}
