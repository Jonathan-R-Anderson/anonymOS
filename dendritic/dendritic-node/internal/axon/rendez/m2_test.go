package rendez

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
)

// M2 (§24): client to service through a circuit and a rendezvous point.
//
// Both legs are real 3-hop circuits from internal/axon/circuit, with real
// handshakes, real wide-block onion layers and real relay tables. The RP joins
// them by cookie. What is simulated is only the transport between relays --
// P2 established that separately and repeating it here would test the link
// layer for a fourth time instead of testing the rendezvous.

// leg is one side's 3-hop circuit: the client-side crypto and the relay-side
// crypto for each hop.
type leg struct {
	clients []*circuit.HopWide
	relays  []*circuit.HopWide
	af      [32]byte
}

func newLeg(t *testing.T) *leg {
	t.Helper()
	l := &leg{}
	if _, err := rand.Read(l.af[:]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		c, r := hopPair(t)
		l.clients = append(l.clients, c)
		l.relays = append(l.relays, r)
	}
	return l
}

// hopPair runs one real ntor handshake and returns the matched client and relay
// crypto states.
//
// Built from circuit's exported API rather than a test-only helper exported
// from that package: a `NewHandshakePairForTest` in production code is an API
// somebody eventually calls in production.
func hopPair(t *testing.T) (client, relay *circuit.HopWide) {
	t.Helper()
	var ridBytes, bPriv [32]byte
	if _, err := rand.Read(ridBytes[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(bPriv[:]); err != nil {
		t.Fatal(err)
	}
	bPub, err := curve25519.X25519(bPriv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	var static circuit.RelayStatic
	static.RID = ridBytes
	copy(static.B[:], bPub)

	h, createBody, err := circuit.NewClientHandshake(rand.Reader, static)
	if err != nil {
		t.Fatal(err)
	}
	relayKeys, reply, err := circuit.ServerHandshake(rand.Reader, static, bPriv, createBody)
	if err != nil {
		t.Fatal(err)
	}
	clientKeys, err := h.Complete(reply)
	if err != nil {
		t.Fatal(err)
	}
	if client, err = circuit.NewHopWide(clientKeys); err != nil {
		t.Fatal(err)
	}
	if relay, err = circuit.NewHopWide(relayKeys); err != nil {
		t.Fatal(err)
	}
	return client, relay
}

// send wraps a relay message for the whole leg and peels it hop by hop,
// returning what the far end received.
func (l *leg) send(t *testing.T, msg *circuit.RelayCell) *circuit.RelayCell {
	t.Helper()
	inner, err := msg.Encode()
	if err != nil {
		t.Fatal(err)
	}
	block, err := circuit.SealInnermost(l.af, inner)
	if err != nil {
		t.Fatal(err)
	}
	if err := circuit.WideSealForward(l.clients, block); err != nil {
		t.Fatal(err)
	}
	for _, r := range l.relays {
		if err := circuit.WideOpenForwardAtHop(r, block); err != nil {
			t.Fatal(err)
		}
	}
	got, err := circuit.OpenInnermost(l.af, block)
	if err != nil {
		t.Fatal(err)
	}
	out, err := circuit.DecodeRelay(got)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestM2ClientReachesServiceThroughARendezvousPoint is milestone M2.
func TestM2ClientReachesServiceThroughARendezvousPoint(t *testing.T) {
	svc := newService(t)

	const introCircuitRef = CircuitRef(0xA1)

	// --- the service establishes an intro point over its own circuit ---------
	introLeg := newLeg(t)
	ip := NewIntroPoint()
	ip.Limit = NewRateLimiter(100, 50, nil)

	est := &EstablishIntro{AuthKey: svc.authKey, Cert: []byte("cert"), Sig: []byte("sig")}
	got := introLeg.send(t, RelayCell(circuit.RCmdEstablishIntro, est.Encode()))
	if got.Cmd != circuit.RCmdEstablishIntro || got.Stream != 0 {
		t.Fatalf("ESTABLISH_INTRO arrived as %s on stream %d", got.Cmd, got.Stream)
	}
	parsed, err := DecodeEstablishIntro(got.Data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.AuthKey != svc.authKey {
		t.Fatal("auth key did not survive the circuit")
	}
	ip.Establish(parsed.AuthKey, introCircuitRef)

	// --- the client establishes a rendezvous point over its own circuit ------
	rp := NewRendezvousPoint()
	clientRendLeg := newLeg(t)
	cookie, err := NewCookie(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	er := &EstablishRendezvous{Cookie: cookie}
	got = clientRendLeg.send(t, RelayCell(circuit.RCmdEstablishRendezvous, er.Encode()))
	rec, err := DecodeEstablishRendezvous(got.Data)
	if err != nil {
		t.Fatal(err)
	}
	const clientCircuitAtRP = CircuitRef(0xC1)
	if err := rp.Establish(rec.Cookie, clientCircuitAtRP); err != nil {
		t.Fatal(err)
	}

	// --- the client introduces itself through the intro point ----------------
	pt := &IntroPlaintext{Cookie: cookie, RPRoutingID: rnd32(t), RPOnionKey: rnd32(t)}
	intro, x, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientIntroLeg := newLeg(t)
	got = clientIntroLeg.send(t, RelayCell(circuit.RCmdIntroduce1, intro.Encode()))
	onWire, err := DecodeIntroduce1(got.Data)
	if err != nil {
		t.Fatal(err)
	}

	// The IP admits it and forwards verbatim.
	circ, status, err := ip.Admit(onWire)
	if err != nil || status != AckOK || circ != introCircuitRef {
		t.Fatalf("admission failed: circ=%d status=%s err=%v", circ, status, err)
	}
	fwd := ip.Forward(onWire, status)

	// --- the service opens it and answers at the RP --------------------------
	inner, err := OpenIntro(svc.bEncPriv, svc.bEnc, svc.kSvc, svc.subcred, fwd.Intro)
	if err != nil {
		t.Fatalf("service could not open the introduction: %v", err)
	}
	if inner.Cookie != cookie {
		t.Fatal("the cookie did not reach the service")
	}
	serviceSeed, hs, err := ServiceRendezvous(rand.Reader, svc.bEncPriv, svc.bEnc, svc.kSvc, fwd.Intro.X)
	if err != nil {
		t.Fatal(err)
	}

	serviceRendLeg := newLeg(t)
	r1 := &Rendezvous1{Cookie: inner.Cookie, HS: hs}
	got = serviceRendLeg.send(t, RelayCell(circuit.RCmdRendezvous1, r1.Encode()))
	arrived, err := DecodeRendezvous1(got.Data)
	if err != nil {
		t.Fatal(err)
	}

	// --- the RP splices ------------------------------------------------------
	const serviceCircuitAtRP = CircuitRef(0xC2)
	joined, err := rp.Splice(arrived.Cookie, serviceCircuitAtRP)
	if err != nil {
		t.Fatal(err)
	}
	if joined != clientCircuitAtRP {
		t.Fatalf("RP joined circuit %d, want the client's %d", joined, clientCircuitAtRP)
	}

	// --- the client completes the handshake ----------------------------------
	r2 := &Rendezvous2{HS: arrived.HS}
	got = clientRendLeg.send(t, RelayCell(circuit.RCmdRendezvous2, r2.Encode()))
	back, err := DecodeRendezvous2(got.Data)
	if err != nil {
		t.Fatal(err)
	}
	clientSeed, err := ClientRendezvous(x, svc.bEnc, svc.kSvc, fwd.Intro.X, back.HS)
	if err != nil {
		t.Fatalf("M2 falsified: the client could not verify the service: %v", err)
	}
	if clientSeed != serviceSeed {
		t.Fatal("M2 falsified: the two ends derived different session keys")
	}

	// --- E6.1: neither endpoint holds the other's address --------------------
	//
	// There is nowhere for one to BE: no type in this package has an address
	// field, and the only things that crossed between the legs are a cookie, an
	// ephemeral key and a MAC. Asserted over the bytes that actually moved.
	for name, blob := range map[string][]byte{
		"INTRODUCE1 on the wire":  intro.Encode(),
		"RENDEZVOUS1 on the wire": r1.Encode(),
		"RENDEZVOUS2 on the wire": r2.Encode(),
	} {
		if bytes.Contains(blob, []byte("127.0.0.1")) || bytes.Contains(blob, []byte("::1")) {
			t.Errorf("E6.1 violated: %s carries a literal address", name)
		}
	}
	// The RP is left holding nothing.
	if rp.Len() != 0 {
		t.Fatalf("E6.1: the RP retains %d entries after the join", rp.Len())
	}
	if _, still := rp.Pending(cookie); still {
		t.Fatal("E6.1: the RP still holds the cookie after the join")
	}

	t.Logf("M2: client and service agreed a session key across 6 relay hops and an RP; "+
		"RP retained %d entries and no address crossed the join", rp.Len())
}

// TestL5CommandsAreCircuitScoped: an introduction is a property of the circuit,
// not of a stream on it, and the cell encoder must refuse the confusion.
func TestL5CommandsAreCircuitScoped(t *testing.T) {
	for _, cmd := range []circuit.RCmd{
		circuit.RCmdEstablishIntro, circuit.RCmdIntroEstablished,
		circuit.RCmdIntroduce1, circuit.RCmdIntroduce2, circuit.RCmdIntroduceAck,
		circuit.RCmdEstablishRendezvous, circuit.RCmdRendezvousEstablished,
		circuit.RCmdRendezvous1, circuit.RCmdRendezvous2,
	} {
		if !cmd.CircuitScoped() {
			t.Errorf("%s is not circuit-scoped", cmd)
		}
		c := &circuit.RelayCell{Stream: 5, Cmd: cmd, Data: []byte("x")}
		if _, err := c.Encode(); err == nil {
			t.Errorf("%s was accepted with a stream id", cmd)
		}
	}
}

// TestL5BodiesRoundTripAndBoundTheirLengths.
func TestL5BodiesRoundTripAndBoundTheirLengths(t *testing.T) {
	svc := newService(t)
	pt := &IntroPlaintext{Cookie: Cookie{1}}
	intro, _, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, []byte("pz"))
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodeIntroduce1(intro.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if back.AuthKeyID != intro.AuthKeyID || back.X != intro.X ||
		!bytes.Equal(back.Encrypted, intro.Encrypted) || !bytes.Equal(back.PuzzleProof, intro.PuzzleProof) {
		t.Fatal("INTRODUCE1 did not round trip")
	}

	// A body claiming any other encrypted length is malformed, because the fixed
	// length is what stops the IP sizing a resumption.
	bad := intro.Encode()
	bad = bad[:len(bad)-1]
	if _, err := DecodeIntroduce1(bad); !errors.Is(err, ErrMalformed) {
		t.Fatalf("a truncated INTRODUCE1 was accepted: %v", err)
	}

	for name, tc := range map[string]struct {
		enc []byte
		dec func([]byte) error
	}{
		"EstablishIntro": {(&EstablishIntro{AuthKey: svc.authKey, Cert: []byte("c"), Sig: []byte("s")}).Encode(),
			func(b []byte) error { _, e := DecodeEstablishIntro(b); return e }},
		"IntroEstablished": {(&IntroEstablished{Status: AckOK, RateState: 7}).Encode(),
			func(b []byte) error { _, e := DecodeIntroEstablished(b); return e }},
		"IntroduceAck": {(&IntroduceAck{Status: AckPuzzleRequired, PuzzleParams: []byte("p")}).Encode(),
			func(b []byte) error { _, e := DecodeIntroduceAck(b); return e }},
		"EstablishRendezvous": {(&EstablishRendezvous{Cookie: Cookie{2}, Token: []byte("t")}).Encode(),
			func(b []byte) error { _, e := DecodeEstablishRendezvous(b); return e }},
		"Rendezvous1": {(&Rendezvous1{Cookie: Cookie{3}}).Encode(),
			func(b []byte) error { _, e := DecodeRendezvous1(b); return e }},
		"Rendezvous2": {(&Rendezvous2{}).Encode(),
			func(b []byte) error { _, e := DecodeRendezvous2(b); return e }},
	} {
		t.Run(name, func(t *testing.T) {
			if err := tc.dec(tc.enc); err != nil {
				t.Fatalf("well-formed body rejected: %v", err)
			}
			// Every truncation must be refused, not read past.
			for i := 0; i < len(tc.enc); i++ {
				if err := tc.dec(tc.enc[:i]); err == nil {
					t.Fatalf("a %d-byte truncation was accepted", i)
				}
			}
		})
	}
}

// TestRendezvous2CarriesNoCookie: the RP drops the cookie at the join, so
// handing it back to the client would put it on the wire again for no reason.
func TestRendezvous2CarriesNoCookie(t *testing.T) {
	c := Cookie{9, 9, 9, 9}
	r2 := &Rendezvous2{HS: Handshake{}}
	if bytes.Contains(r2.Encode(), c[:4]) {
		t.Fatal("RENDEZVOUS2 carries the cookie")
	}
	if len(r2.Encode()) != pubKeySize+authTagSize {
		t.Fatalf("RENDEZVOUS2 is %d bytes, want %d", len(r2.Encode()), pubKeySize+authTagSize)
	}
}
