package peer

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeGateway is a PCP gateway on loopback. It speaks the real wire format,
// because a test against a mock of my own parser would only prove the parser
// agrees with itself -- and F3's whole risk is disagreeing with somebody else's
// router firmware.
type fakeGateway struct {
	conn *net.UDPConn
	addr netip.AddrPort

	// mu guards everything below it.
	//
	// serve() runs on its own goroutine and READS every knob on each request,
	// while the tests WRITE them between requests -- and lastRequest goes the
	// other way. Unsynchronised, that is a data race on eight fields, which
	// `go test -race` reports for five tests in this file and which made the
	// race detector unusable for the WHOLE package: any real race in the
	// peerbook or the annotator was hidden behind this harness's noise.
	//
	// It went unnoticed because -race needs cgo, and cgo needs a C compiler
	// that is not present in every environment this tree is built in.
	mu sync.Mutex

	// knobs
	resultCode  uint8
	grantedLife uint32
	epoch       uint32
	forgeNonce  bool
	extPort     uint16
	version     uint8
	truncate    bool

	lastRequest []byte
}

func newFakeGateway(t *testing.T) *fakeGateway {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	g := &fakeGateway{
		conn:        conn,
		grantedLife: 1800,
		epoch:       100,
		extPort:     41234,
		version:     pcpVersion,
	}
	ap := conn.LocalAddr().(*net.UDPAddr).AddrPort()
	g.addr = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	t.Cleanup(func() { conn.Close() })
	go g.serve()
	return g
}

// set changes a knob under the lock. A closure rather than eight setters: the
// knobs are a test's vocabulary and adding one should not mean adding a method.
func (g *fakeGateway) set(change func(*fakeGateway)) {
	g.mu.Lock()
	defer g.mu.Unlock()
	change(g)
}

// request returns a COPY of the last request seen.
func (g *fakeGateway) request() []byte {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]byte(nil), g.lastRequest...)
}

func (g *fakeGateway) serve() {
	buf := make([]byte, 1500)
	for {
		n, from, err := g.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		req := append([]byte(nil), buf[:n]...)

		// One snapshot per request, so a knob changed mid-response cannot
		// produce a reply that is half one setting and half another.
		g.mu.Lock()
		g.lastRequest = req
		version, resultCode := g.version, g.resultCode
		grantedLife, epoch := g.grantedLife, g.epoch
		forgeNonce, extPort, truncate := g.forgeNonce, g.extPort, g.truncate
		g.mu.Unlock()

		resp := make([]byte, pcpResponseLen)
		resp[0] = version
		resp[1] = 0x80 | pcpOpcodeMAP // R bit set
		resp[3] = resultCode
		binary.BigEndian.PutUint32(resp[4:8], grantedLife)
		binary.BigEndian.PutUint32(resp[8:12], epoch)
		if forgeNonce {
			for i := 24; i < 36; i++ {
				resp[i] = 0xff
			}
		} else if len(req) >= 36 {
			copy(resp[24:36], req[24:36])
		}
		if len(req) >= 42 {
			copy(resp[40:42], req[40:42]) // internal port echoed
		}
		binary.BigEndian.PutUint16(resp[42:44], extPort)
		// External address 198.51.100.7 as IPv4-mapped IPv6, per RFC 6887 §5.
		ext := netip.MustParseAddr("198.51.100.7").As16()
		copy(resp[44:60], ext[:])
		if truncate {
			resp = resp[:20]
		}
		g.conn.WriteToUDP(resp, from)
	}
}

// mapperTo builds a PCP mapper pointed at the fake gateway. The gateway is on a
// loopback port rather than 5351, so the mapper's port is overridden for the
// test via a dial helper.
func (g *fakeGateway) mapper(t *testing.T) *pcpMapper {
	t.Helper()
	m, err := NewPCPMapper(g.addr.Addr(), netip.MustParseAddr("192.168.1.65"))
	if err != nil {
		t.Fatal(err)
	}
	p := m.(*pcpMapper)
	p.port = g.addr.Port()
	return p
}

func ctx3s(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return c
}

// TestPCPMapsAndReportsTheGrantedLease is the happy path and RFC 6887 §11.2.
func TestPCPMapsAndReportsTheGrantedLease(t *testing.T) {
	g := newFakeGateway(t)
	g.set(func(f *fakeGateway) { f.grantedLife = 600 }) // gateway SHORTENS the lease
	p := g.mapper(t)

	m, err := p.Map(ctx3s(t), 4001, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if m.Protocol != MappingPCP {
		t.Fatalf("mapping reports protocol %s", m.Protocol)
	}
	if m.Protocol.String() != "pcp" {
		t.Fatalf("PCP stringifies as %q; an operator cannot tell which protocol "+
			"was spoken", m.Protocol.String())
	}
	if m.ExternalPort != 41234 {
		t.Fatalf("external port %d", m.ExternalPort)
	}
	if m.External != netip.MustParseAddr("198.51.100.7") {
		t.Fatalf("external address %v; an IPv4-mapped form would not compare equal "+
			"to a plain IPv4 address in §5's quorum", m.External)
	}
	// THE GRANTED LEASE, NOT THE REQUESTED ONE. Refreshing on the requested
	// figure would refresh after the mapping had already expired.
	if m.Lease != 600*time.Second {
		t.Fatalf("lease recorded as %v, but the gateway granted 600s; the node would "+
			"refresh at %v, long after the mapping had gone", m.Lease, m.RefreshAt())
	}
}

// TestPCPRequestIsRFC6887Shaped pins the wire format against the RFC, not
// against my own parser.
func TestPCPRequestIsRFC6887Shaped(t *testing.T) {
	nonce := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	b := pcpRequest(netip.MustParseAddr("192.168.1.65"), nonce, 4001, 4001, 30*time.Minute)

	if len(b) != 60 {
		t.Fatalf("MAP request is %d bytes, RFC 6887 §11.1 says 60", len(b))
	}
	if b[0] != 2 {
		t.Fatalf("version byte is %d, not 2; a version-0 datagram is NAT-PMP and a "+
			"NAT-PMP gateway would answer it as one", b[0])
	}
	if b[1] != pcpOpcodeMAP {
		t.Fatalf("opcode byte is %#x; the R bit must be clear on a request", b[1])
	}
	if got := binary.BigEndian.Uint32(b[4:8]); got != 1800 {
		t.Fatalf("lifetime is %d seconds, want 1800", got)
	}
	// Client address as IPv4-mapped IPv6 (RFC 6887 §5).
	want := netip.MustParseAddr("192.168.1.65").As16()
	for i := range want {
		if b[8+i] != want[i] {
			t.Fatalf("client address is not the IPv4-mapped form at byte %d", i)
		}
	}
	for i, n := range nonce {
		if b[24+i] != n {
			t.Fatalf("nonce is not at bytes 24:36")
		}
	}
	if b[36] != 17 {
		t.Fatalf("protocol byte is %d, want IANA UDP (17)", b[36])
	}
	if got := binary.BigEndian.Uint16(b[40:42]); got != 4001 {
		t.Fatalf("internal port is %d", got)
	}
	for _, x := range b[44:60] {
		if x != 0 {
			t.Fatal("suggested external address is non-zero; an ordinary NAT client " +
				"has no address to ask for and should let the gateway choose")
		}
	}
}

// TestPCPRejectsAForgedNonce is RFC 6887 §11.1 and the reason the nonce exists.
//
// Without it, an off-path attacker spraying UDP at port 5351 convinces this node
// it holds a mapping on an external address the ATTACKER chose — and §5's
// reachability machine then advertises that address.
func TestPCPRejectsAForgedNonce(t *testing.T) {
	g := newFakeGateway(t)
	g.set(func(f *fakeGateway) { f.forgeNonce = true })
	p := g.mapper(t)

	if _, err := p.Map(ctx3s(t), 4001, time.Minute); !errors.Is(err, ErrPCPNonceMismatch) {
		t.Fatalf("a response with the wrong nonce was accepted: %v", err)
	}
}

// TestPCPNonceIsStableAcrossRefreshes is why the nonce is per-mapper.
//
// The nonce identifies the MAPPING. A refresh carrying a fresh nonce creates a
// SECOND mapping instead of extending the first, so the node leaks one mapping
// per refresh until the gateway runs out of them.
func TestPCPNonceIsStableAcrossRefreshes(t *testing.T) {
	g := newFakeGateway(t)
	p := g.mapper(t)

	if _, err := p.Map(ctx3s(t), 4001, time.Minute); err != nil {
		t.Fatal(err)
	}
	first := append([]byte(nil), g.request()[24:36]...)

	if _, err := p.Map(ctx3s(t), 4001, time.Minute); err != nil {
		t.Fatal(err)
	}
	second := g.request()[24:36]

	for i := range first {
		if first[i] != second[i] {
			t.Fatal("the nonce changed between refreshes; each refresh creates a new " +
				"mapping and the node leaks one per cycle until the gateway is full")
		}
	}

	// Two DIFFERENT mappers must not share a nonce, or two nodes behind one
	// gateway would be refreshing each other's mapping.
	other := g.mapper(t)
	if other.nonce == p.nonce {
		t.Fatal("two mappers drew the same nonce")
	}
}

// TestPCPDetectsGatewayRestart is RFC 6887 §8.5.
//
// A restarted gateway has lost every mapping but will happily keep answering,
// because the response is generated from the request. §5 demotes on a FAILED
// refresh, and a refresh that succeeds against a restarted gateway never fails —
// so without this the node advertises a MAPPED address that stopped working.
func TestPCPDetectsGatewayRestart(t *testing.T) {
	g := newFakeGateway(t)
	g.set(func(f *fakeGateway) { f.epoch = 5000 })
	p := g.mapper(t)

	if _, err := p.Map(ctx3s(t), 4001, time.Minute); err != nil {
		t.Fatal(err)
	}
	// Epoch moving forward is normal.
	g.set(func(f *fakeGateway) { f.epoch = 5100 })
	if _, err := p.Map(ctx3s(t), 4001, time.Minute); err != nil {
		t.Fatalf("a forward epoch was treated as a restart: %v", err)
	}
	// Epoch going backwards means the gateway restarted.
	g.set(func(f *fakeGateway) { f.epoch = 3 })
	if _, err := p.Map(ctx3s(t), 4001, time.Minute); !errors.Is(err, ErrPCPEpochReset) {
		t.Fatalf("a gateway restart went undetected: %v", err)
	}
}

// TestPCPSurfacesAddressMismatch is result code 12, the double-NAT signature.
func TestPCPSurfacesAddressMismatch(t *testing.T) {
	g := newFakeGateway(t)
	g.set(func(f *fakeGateway) { f.resultCode = 12 })
	p := g.mapper(t)

	_, err := p.Map(ctx3s(t), 4001, time.Minute)
	if err == nil {
		t.Fatal("ADDRESS_MISMATCH was accepted as success")
	}
	var re pcpResultError
	if !errors.As(err, &re) || re.Code != 12 {
		t.Fatalf("the result code was lost: %v", err)
	}
	if got := err.Error(); !contains(got, "second NAT") {
		t.Fatalf("the error does not explain what an operator should do: %q", got)
	}
}

// TestPCPRejectsMalformedResponses covers the cheap checks.
func TestPCPRejectsMalformedResponses(t *testing.T) {
	nonce := [12]byte{9}
	good := make([]byte, pcpResponseLen)
	good[0] = pcpVersion
	good[1] = 0x80 | pcpOpcodeMAP
	copy(good[24:36], nonce[:])

	if _, err := parsePCPResponse(good, nonce); err != nil {
		t.Fatalf("a well-formed response was refused: %v", err)
	}

	short := good[:20]
	if _, err := parsePCPResponse(short, nonce); !errors.Is(err, ErrPCPShortResponse) {
		t.Fatalf("short: %v", err)
	}
	v0 := append([]byte(nil), good...)
	v0[0] = 0 // NAT-PMP
	if _, err := parsePCPResponse(v0, nonce); !errors.Is(err, ErrPCPBadVersion) {
		t.Fatalf("a NAT-PMP datagram was parsed as PCP: %v", err)
	}
	req := append([]byte(nil), good...)
	req[1] = pcpOpcodeMAP // R bit clear
	if _, err := parsePCPResponse(req, nonce); !errors.Is(err, ErrPCPNotResponse) {
		t.Fatalf("a request was parsed as a response: %v", err)
	}
	wrongOp := append([]byte(nil), good...)
	wrongOp[1] = 0x80 | 2 // PEER
	if _, err := parsePCPResponse(wrongOp, nonce); !errors.Is(err, ErrPCPWrongOpcode) {
		t.Fatalf("a PEER response was parsed as MAP: %v", err)
	}
}

// TestPCPIsADistinctProtocolFromNATPMP is F3's actual finding.
func TestPCPIsADistinctProtocolFromNATPMP(t *testing.T) {
	if MappingPCP == MappingNATPMP {
		t.Fatal("PCP and NAT-PMP share a constant; an operator reading a log cannot " +
			"tell which protocol was spoken, and RFC 6887 is not RFC 6886")
	}
	if MappingPCP.String() == MappingNATPMP.String() {
		t.Fatalf("both stringify as %q", MappingPCP.String())
	}
	// PCP is attempted BEFORE NAT-PMP: they share port 5351 and PCP is the
	// successor, so a gateway speaking both should be spoken to in the better
	// one (RFC 6887 §16 specifies this fallback direction).
	order := MappingConfig{}.protocols()
	pcpAt, pmpAt := -1, -1
	for i, p := range order {
		switch p {
		case MappingPCP:
			pcpAt = i
		case MappingNATPMP:
			pmpAt = i
		}
	}
	if pcpAt < 0 {
		t.Fatal("PCP is not in the default protocol order, so it is implemented and " +
			"never used")
	}
	if pcpAt > pmpAt {
		t.Fatal("NAT-PMP is tried before PCP; a gateway speaking both answers the " +
			"weaker protocol first and PCP never gets asked")
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestMappersAreNotBuiltWithoutOptIn is §6.5's opt-in, at the factory.
//
// The factory performs DISCOVERY — UPnP discovery broadcasts on the local
// network — so the check has to be here as well as in the manager. "A node that
// silently reconfigures the user's router is not a node an operator can reason
// about", and one that silently probes it is not much better.
func TestMappersAreNotBuiltWithoutOptIn(t *testing.T) {
	if _, err := NewMappersFor(context.Background(), MappingConfig{}); !errors.Is(err, ErrMappingDisabled) {
		t.Fatalf("the zero-value config built mappers: %v", err)
	}
	if _, err := NewMappersFor(context.Background(), MappingConfig{
		Protocols: []MappingProtocol{MappingPCP},
	}); !errors.Is(err, ErrMappingDisabled) {
		t.Fatal("naming a protocol was treated as opting in; the opt-in is Enabled")
	}
}

// TestDefaultGatewayDoesNotGuess is why defaultGateway reads the route table.
//
// Assuming the .1 of the local /24 is wrong often enough to matter, and a wrong
// guess sends PCP requests to an unrelated host that never consented to one.
func TestDefaultGatewayDoesNotGuess(t *testing.T) {
	gw, err := defaultGateway(context.Background())
	if err != nil {
		t.Skipf("no default route here: %v", err)
	}
	if !gw.Is4() {
		t.Fatalf("gateway %v is not IPv4", gw)
	}
	if gw.IsUnspecified() {
		t.Fatal("0.0.0.0 was returned as a gateway")
	}
	local, err := localAddrFor(context.Background())
	if err != nil {
		t.Skip(err)
	}
	// If it had guessed .1 it would match this by construction on most networks;
	// the point is only that a REAL answer was read, so log both for the record.
	t.Logf("route table gateway %v, local %v", gw, local)
}
