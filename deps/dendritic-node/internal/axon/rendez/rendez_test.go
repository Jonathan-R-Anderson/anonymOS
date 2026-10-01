package rendez

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/curve25519"
)

func kp(t *testing.T) (priv, pub [32]byte) {
	t.Helper()
	if _, err := rand.Read(priv[:]); err != nil {
		t.Fatal(err)
	}
	p, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(pub[:], p)
	return priv, pub
}

func rnd32(t *testing.T) (v [32]byte) {
	t.Helper()
	if _, err := rand.Read(v[:]); err != nil {
		t.Fatal(err)
	}
	return v
}

// service is one anonymous service's key material.
type service struct {
	bEncPriv, bEnc [32]byte
	kSvc           [32]byte
	subcred        [32]byte
	authKey        [32]byte
}

func newService(t *testing.T) *service {
	t.Helper()
	priv, pub := kp(t)
	return &service{bEncPriv: priv, bEnc: pub, kSvc: rnd32(t),
		subcred: rnd32(t), authKey: rnd32(t)}
}

// fullRendezvous runs the whole protocol and returns both key seeds.
func fullRendezvous(t *testing.T, svc *service) (clientSeed, serviceSeed [32]byte, msg *Introduce1) {
	t.Helper()
	cookie, err := NewCookie(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pt := &IntroPlaintext{Cookie: cookie, RPRoutingID: rnd32(t), RPOnionKey: rnd32(t)}

	msg, x, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, []byte("proof"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenIntro(svc.bEncPriv, svc.bEnc, svc.kSvc, svc.subcred, msg)
	if err != nil {
		t.Fatal(err)
	}
	if got.Cookie != cookie {
		t.Fatal("cookie did not survive the introduction")
	}
	serviceSeed, hs, err := ServiceRendezvous(rand.Reader, svc.bEncPriv, svc.bEnc, svc.kSvc, msg.X)
	if err != nil {
		t.Fatal(err)
	}
	clientSeed, err = ClientRendezvous(x, svc.bEnc, svc.kSvc, msg.X, hs)
	if err != nil {
		t.Fatal(err)
	}
	return clientSeed, serviceSeed, msg
}

// TestRendezvousAgrees is the happy path end to end.
func TestRendezvousAgrees(t *testing.T) {
	svc := newService(t)
	c, s, _ := fullRendezvous(t, svc)
	if c != s {
		t.Fatal("client and service derived different KEY_SEEDs")
	}
	var zero [32]byte
	if c == zero {
		t.Fatal("KEY_SEED is zero")
	}
}

// TestT61NoAddressAnywhere is T6.1: an audit of every struct reachable at either
// endpoint after a successful rendezvous finds no IP and no /ip4, /ip6 component.
//
// It walks the types by reflection rather than eyeballing them, so a field added
// later fails the test instead of quietly reintroducing an address.
func TestT61NoAddressAnywhere(t *testing.T) {
	svc := newService(t)
	_, _, msg := fullRendezvous(t, svc)

	ip := NewIntroPoint()
	ip.Establish(svc.authKey, CircuitRef(7))
	rp := NewRendezvousPoint()
	cookie, _ := NewCookie(rand.Reader)
	if err := rp.Establish(cookie, CircuitRef(11)); err != nil {
		t.Fatal(err)
	}
	pend, _ := rp.Pending(cookie)

	banned := []string{"netip", "net.IP", "net.Addr", "multiaddr", "ip4", "ip6",
		"Addr", "Address", "Host", "Port", "Endpoint"}

	var walk func(reflect.Type, string, map[reflect.Type]bool)
	walk = func(ty reflect.Type, path string, seen map[reflect.Type]bool) {
		if seen[ty] {
			return
		}
		seen[ty] = true
		for _, b := range banned {
			if strings.Contains(ty.PkgPath()+"."+ty.Name(), b) {
				t.Errorf("T6.1 violated: %s is of address-bearing type %s", path, ty)
			}
		}
		switch ty.Kind() {
		case reflect.Struct:
			for i := 0; i < ty.NumField(); i++ {
				f := ty.Field(i)
				for _, b := range banned {
					if strings.EqualFold(f.Name, b) {
						t.Errorf("T6.1 violated: %s.%s looks like an address field", path, f.Name)
					}
				}
				walk(f.Type, path+"."+f.Name, seen)
			}
		case reflect.Ptr, reflect.Slice, reflect.Array:
			walk(ty.Elem(), path+"[]", seen)
		}
	}
	seen := map[reflect.Type]bool{}
	// Types, not values: IntroPoint holds a mutex and must not be copied, and
	// the audit is about the SHAPE of what these points can hold anyway.
	for name, ty := range map[string]reflect.Type{
		"Introduce1":      reflect.TypeOf(*msg),
		"IntroPoint":      reflect.TypeOf(ip).Elem(),
		"Pending":         reflect.TypeOf(pend),
		"RendezvousPoint": reflect.TypeOf(rp).Elem(),
		"IntroPlaintext":  reflect.TypeOf(IntroPlaintext{}),
		"Handshake":       reflect.TypeOf(Handshake{}),
	} {
		walk(ty, name, seen)
	}

	// RPLinkHints is an opaque 80-byte blob by design -- it carries whatever a
	// client needs to reach the RP and is NEVER parsed here. Assert it is bytes
	// and not a structured address.
	f, _ := reflect.TypeOf(IntroPlaintext{}).FieldByName("RPLinkHints")
	if f.Type.Kind() != reflect.Array || f.Type.Elem().Kind() != reflect.Uint8 {
		t.Errorf("RPLinkHints is %s; it must stay an opaque byte blob", f.Type)
	}
}

// TestT62RPStateIsTwoCircuitsAndACookie is T6.2, asserted against the struct.
func TestT62RPStateIsTwoCircuitsAndACookie(t *testing.T) {
	ty := reflect.TypeOf(Pending{})
	want := map[string]bool{"Cookie": true, "Client": true, "Service": true, "Spliced": true}
	if ty.NumField() != len(want) {
		t.Fatalf("T6.2: Pending has %d fields, want exactly %d", ty.NumField(), len(want))
	}
	for i := 0; i < ty.NumField(); i++ {
		if !want[ty.Field(i).Name] {
			t.Errorf("T6.2 violated: Pending carries an extra field %q", ty.Field(i).Name)
		}
	}
}

// TestE64SerialisedRPStateCarriesNothing is E6.4: the RP's serialised state at
// the join contains no address and no service identity.
func TestE64SerialisedRPStateCarriesNothing(t *testing.T) {
	svc := newService(t)
	rp := NewRendezvousPoint()
	cookie, _ := NewCookie(rand.Reader)
	if err := rp.Establish(cookie, CircuitRef(11)); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Splice(cookie, CircuitRef(12)); err != nil {
		t.Fatal(err)
	}
	// Serialise everything the RP could possibly hand over.
	pend, _ := rp.Pending(cookie) // spliced entries are dropped; this is empty
	blob, err := json.Marshal(struct {
		Pending Pending
		Count   int
	}{pend, rp.Len()})
	if err != nil {
		t.Fatal(err)
	}
	for name, secret := range map[string][]byte{
		"service identity": svc.kSvc[:], "intro auth key": svc.authKey[:],
		"service enc key": svc.bEnc[:], "subcredential": svc.subcred[:],
	} {
		if bytes.Contains(blob, secret) {
			t.Errorf("E6.4 violated: RP state contains the %s", name)
		}
	}
	if strings.Contains(string(blob), "1.") || strings.Contains(string(blob), "::") {
		t.Errorf("E6.4: RP state looks like it contains an address: %s", blob)
	}
}

// TestT63IntroWithoutPuzzleIsDroppedFirst is T6.3: an INTRODUCE1 without a valid
// puzzle solution is dropped BEFORE any circuit work.
func TestT63IntroWithoutPuzzleIsDroppedFirst(t *testing.T) {
	svc := newService(t)
	_, _, msg := fullRendezvous(t, svc)

	ip := NewIntroPoint()
	ip.Puzzle = &demandingPuzzle{}
	// The circuit IS registered, so a failure here cannot be blamed on lookup.
	ip.Establish(svc.authKey, CircuitRef(7))

	msg.PuzzleProof = nil
	c, st, err := ip.Admit(msg)
	if !errors.Is(err, ErrPuzzleRequired) {
		t.Fatalf("err = %v, want ErrPuzzleRequired", err)
	}
	if st != AckPuzzleRequired {
		t.Fatalf("status = %s, want PUZZLE_REQUIRED", st)
	}
	if c != 0 {
		t.Fatal("T6.3 violated: a circuit was resolved for an unsolved introduction")
	}

	// An invalid proof is refused too, and still before the lookup.
	msg.PuzzleProof = []byte("wrong")
	if _, _, err := ip.Admit(msg); !errors.Is(err, ErrPuzzleInvalid) {
		t.Fatalf("err = %v, want ErrPuzzleInvalid", err)
	}
	// A valid one gets through.
	msg.PuzzleProof = []byte("right")
	if c, st, err := ip.Admit(msg); err != nil || st != AckOK || c != 7 {
		t.Fatalf("valid proof refused: c=%d st=%s err=%v", c, st, err)
	}
}

type demandingPuzzle struct{}

func (demandingPuzzle) Required() bool { return true }
func (demandingPuzzle) Verify(_ [32]byte, proof []byte) error {
	if string(proof) != "right" {
		return errors.New("bad proof")
	}
	return nil
}

// TestNoPuzzleIsADeclaredUnsafeMode: R10 requires a puzzle, P6a builds it, and
// running without one must be visible rather than silent.
func TestNoPuzzleIsADeclaredUnsafeMode(t *testing.T) {
	ip := NewIntroPoint()
	modes := ip.UnsafeModes()
	if len(modes) != 1 || modes[0] != UnsafeNoPuzzle {
		t.Fatalf("unsafe modes = %v, want the no-puzzle declaration", modes)
	}
	ip.Puzzle = &demandingPuzzle{}
	if len(ip.UnsafeModes()) != 0 {
		t.Fatal("a configured puzzle still reports the unsafe mode")
	}
}

// TestT64ReplayedCookieIsRefused is T6.4.
func TestT64ReplayedCookieIsRefused(t *testing.T) {
	rp := NewRendezvousPoint()
	c, _ := NewCookie(rand.Reader)

	if err := rp.Establish(c, CircuitRef(1)); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Splice(c, CircuitRef(2)); err != nil {
		t.Fatal(err)
	}
	// A second service leg presenting the same cookie must not be joined.
	if _, err := rp.Splice(c, CircuitRef(3)); !errors.Is(err, ErrReplay) {
		t.Fatalf("second splice: err = %v, want ErrReplay", err)
	}
	// Nor may the cookie be established again by a new client.
	if err := rp.Establish(c, CircuitRef(4)); !errors.Is(err, ErrReplay) {
		t.Fatalf("re-establish: err = %v, want ErrReplay", err)
	}
	// And a duplicate establish before any splice is refused as in-use.
	c2, _ := NewCookie(rand.Reader)
	if err := rp.Establish(c2, CircuitRef(5)); err != nil {
		t.Fatal(err)
	}
	if err := rp.Establish(c2, CircuitRef(6)); !errors.Is(err, ErrCookieInUse) {
		t.Fatalf("duplicate establish: err = %v, want ErrCookieInUse", err)
	}
}

// TestCookieIsDroppedAtTheJoin: keeping it would leave the RP holding a token
// linking the pair for the life of the session.
func TestCookieIsDroppedAtTheJoin(t *testing.T) {
	rp := NewRendezvousPoint()
	c, _ := NewCookie(rand.Reader)
	if err := rp.Establish(c, CircuitRef(1)); err != nil {
		t.Fatal(err)
	}
	if _, ok := rp.Pending(c); !ok {
		t.Fatal("establish did not record the cookie")
	}
	if _, err := rp.Splice(c, CircuitRef(2)); err != nil {
		t.Fatal(err)
	}
	if _, ok := rp.Pending(c); ok {
		t.Fatal("the cookie survived the join")
	}
	if rp.Len() != 0 {
		t.Fatalf("%d entries outstanding after the join", rp.Len())
	}
}

// TestT65IntroPointCannotImpersonateTheService is T6.5: an intro point can refuse
// to forward and can do nothing else.
func TestT65IntroPointCannotImpersonateTheService(t *testing.T) {
	svc := newService(t)
	cookie, _ := NewCookie(rand.Reader)
	pt := &IntroPlaintext{Cookie: cookie, RPRoutingID: rnd32(t)}
	msg, x, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, nil)
	if err != nil {
		t.Fatal(err)
	}

	// 1. The IP cannot READ the introduction: it holds neither x nor b_enc.
	if _, err := OpenIntro(rnd32(t), svc.bEnc, svc.kSvc, svc.subcred, msg); err == nil {
		t.Fatal("T6.5 violated: the introduction decrypted under a key the IP could hold")
	}

	// 2. The IP cannot ANSWER as the service. It substitutes its own key pair
	//    and produces a handshake; the client must refuse it.
	impostorPriv, impostorPub := kp(t)
	_, hs, err := ServiceRendezvous(rand.Reader, impostorPriv, impostorPub, svc.kSvc, msg.X)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientRendezvous(x, svc.bEnc, svc.kSvc, msg.X, hs); !errors.Is(err, ErrAuthMismatch) {
		t.Fatalf("T6.5 violated: an impostor's AUTH verified (err = %v)", err)
	}

	// 3. Even knowing the real B_enc, without b_enc it cannot produce AUTH.
	_, hs2, err := ServiceRendezvous(rand.Reader, impostorPriv, svc.bEnc, svc.kSvc, msg.X)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ClientRendezvous(x, svc.bEnc, svc.kSvc, msg.X, hs2); !errors.Is(err, ErrAuthMismatch) {
		t.Fatal("T6.5 violated: AUTH verified without the service's private key")
	}
}

// TestIntroPointCannotRedirectTheIntroduction: the header is AAD, so an IP that
// rewrites AuthKeyID or X to point the introduction elsewhere breaks decryption
// rather than silently succeeding.
func TestIntroPointCannotRedirectTheIntroduction(t *testing.T) {
	svc := newService(t)
	pt := &IntroPlaintext{Cookie: Cookie{1}, RPRoutingID: rnd32(t)}
	msg, _, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, nil)
	if err != nil {
		t.Fatal(err)
	}
	tampered := *msg
	tampered.AuthKeyID = rnd32(t)
	if _, err := OpenIntro(svc.bEncPriv, svc.bEnc, svc.kSvc, svc.subcred, &tampered); err == nil {
		t.Fatal("a rewritten auth key still decrypted")
	}
	tampered = *msg
	tampered.X = rnd32(t)
	if _, err := OpenIntro(svc.bEncPriv, svc.bEnc, svc.kSvc, svc.subcred, &tampered); err == nil {
		t.Fatal("a rewritten ephemeral key still decrypted")
	}
}

// TestIntroduce2IsForwardedVerbatim: re-encoding could alter the AAD the
// encryption binds.
func TestIntroduce2IsForwardedVerbatim(t *testing.T) {
	svc := newService(t)
	_, _, msg := fullRendezvous(t, svc)
	ip := NewIntroPoint()
	ip.Establish(svc.authKey, CircuitRef(3))
	fwd := ip.Forward(msg, AckOK)
	if fwd.Intro != msg {
		t.Fatal("the intro point copied the message instead of forwarding it verbatim")
	}
	if _, err := OpenIntro(svc.bEncPriv, svc.bEnc, svc.kSvc, svc.subcred, fwd.Intro); err != nil {
		t.Fatalf("the forwarded introduction no longer decrypts: %v", err)
	}
}

// TestEveryIntroductionIsTheSameSize: the IP must not be able to tell a
// resumption from a fresh introduction, or an authorised client from a public
// one, by length.
func TestEveryIntroductionIsTheSameSize(t *testing.T) {
	svc := newService(t)
	sizes := map[int]int{}
	for _, pt := range []*IntroPlaintext{
		{Cookie: Cookie{1}},
		{Cookie: Cookie{2}, ResumePresent: true, SessionID: [16]byte{9}, SessionCtr: 42,
			SessionProof: rnd32(t)},
		{Cookie: Cookie{3}, ClientAuthProof: rnd32(t)},
		{Cookie: Cookie{4}, ResumePresent: true, ClientAuthProof: rnd32(t),
			RPLinkHints: [80]byte{7}, FlowControl: 1234},
	} {
		if n := len(pt.Encode()); n != IntroPlaintextSize {
			t.Fatalf("plaintext is %d bytes, want %d", n, IntroPlaintextSize)
		}
		msg, _, err := SealIntro(rand.Reader, svc.bEnc, svc.kSvc, svc.authKey, svc.subcred, pt, nil)
		if err != nil {
			t.Fatal(err)
		}
		sizes[len(msg.Encrypted)]++
	}
	if len(sizes) != 1 {
		t.Fatalf("introductions came in %d distinct sizes: %v", len(sizes), sizes)
	}
}

// TestIntroPlaintextRoundTrips.
func TestIntroPlaintextRoundTrips(t *testing.T) {
	in := &IntroPlaintext{Cookie: Cookie{1, 2, 3}, RPRoutingID: rnd32(t),
		RPOnionKey: rnd32(t), RPLinkHints: [80]byte{9, 8, 7}, ResumePresent: true,
		SessionID: [16]byte{4}, SessionCtr: 99, SessionProof: rnd32(t),
		ClientAuthProof: rnd32(t), FlowControl: 4242}
	out, err := DecodeIntroPlaintext(in.Encode())
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("round trip failed:\n in = %+v\nout = %+v", in, out)
	}
	if _, err := DecodeIntroPlaintext(make([]byte, IntroPlaintextSize-1)); !errors.Is(err, ErrPlaintextSize) {
		t.Fatal("a short plaintext was accepted")
	}
}

// TestRateLimiterBoundsOneAuthKey: the flood defence that exists while the
// puzzle does not.
func TestRateLimiterBoundsOneAuthKey(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := NewRateLimiter(10, 5, func() time.Time { return now })
	var k, other [32]byte
	k[0], other[0] = 1, 2

	allowed := 0
	for i := 0; i < 20; i++ {
		if l.Allow(k) {
			allowed++
		}
	}
	if allowed != 5 {
		t.Fatalf("burst admitted %d, want 5", allowed)
	}
	// A different service is unaffected -- the budget is per auth key, so one
	// service being flooded does not deny every other service on the same IP.
	if !l.Allow(other) {
		t.Fatal("a flood against one auth key denied another")
	}
	// Tokens refill.
	now = now.Add(time.Second)
	if !l.Allow(k) {
		t.Fatal("the bucket did not refill")
	}
}

// TestLowOrderPointRejected.
func TestLowOrderPointRejected(t *testing.T) {
	svc := newService(t)
	var zero [32]byte
	if _, _, err := ServiceRendezvous(rand.Reader, svc.bEncPriv, svc.bEnc, svc.kSvc, zero); !errors.Is(err, ErrLowOrderPoint) {
		t.Fatalf("err = %v, want ErrLowOrderPoint", err)
	}
}
