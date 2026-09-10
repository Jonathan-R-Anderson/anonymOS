package peer

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
)

// PCP — Port Control Protocol, RFC 6887. Closes F3.
//
// WHAT WAS ACTUALLY MISSING. §5's table said "UPnP + NAT-PMP, off by default.
// PCP is not implemented", and the code agreed -- but the ENUM did not: a single
// MappingNATPMP constant was commented "NAT-PMP / PCP" and stringified as
// "nat-pmp". Those are two protocols, not one with two names. NAT-PMP is
// RFC 6886 and PCP is RFC 6887; they share UDP port 5351 and a lineage and
// nothing else, and a gateway that answers one need not answer the other. The
// conflation meant an operator reading "nat-pmp" in a log could not tell which
// had been spoken, and the roadmap could describe PCP as covered by a constant.
// MappingPCP is now its own protocol and the comment no longer claims otherwise.
//
// WHY PCP AND NOT JUST NAT-PMP. NAT-PMP has no IPv6, no way to ask for a
// specific external address, and no mapping nonce -- so it cannot tell its own
// response from an off-path forgery, and it cannot survive the CGNAT that a
// large share of residential and every mobile network now runs. PCP is the
// successor the IETF published for exactly those reasons.
//
// THE NONCE IS A SECURITY PROPERTY, NOT A FORMALITY. RFC 6887 §11.1 requires a
// random 96-bit mapping nonce echoed in the response. Without it an off-path
// attacker who can guess the transaction need only spray UDP at port 5351 to
// convince this node it holds a mapping on an external address the attacker
// chose -- and §5's whole reachability machine would then advertise it. The
// nonce is generated per client, checked on every response, and a mismatch is a
// hard error rather than a retry.

// MappingPCP is RFC 6887. It is DISTINCT from MappingNATPMP.
const MappingPCP MappingProtocol = 2

const (
	// pcpPort is PCP's UDP port. Shared with NAT-PMP, which is why the two get
	// conflated and why the version byte is the only thing distinguishing them
	// on the wire: NAT-PMP is version 0, PCP is version 2.
	pcpPort = 5351
	// pcpVersion is RFC 6887's version 2.
	pcpVersion = 2
	// pcpOpcodeMAP is the MAP opcode (RFC 6887 §11.1).
	pcpOpcodeMAP = 1
	// pcpProtoUDP is IANA's UDP number, carried in the MAP request.
	pcpProtoUDP = 17

	pcpHeaderLen   = 24
	pcpMapDataLen  = 36
	pcpRequestLen  = pcpHeaderLen + pcpMapDataLen
	pcpResponseLen = pcpHeaderLen + pcpMapDataLen

	// pcpResultSuccess is result code 0.
	pcpResultSuccess = 0
)

var (
	ErrPCPNonceMismatch = errors.New("axon/peer: PCP response carries a different mapping nonce; a response for another mapping, or an off-path forgery (RFC 6887 §11.1)")
	ErrPCPShortResponse = errors.New("axon/peer: PCP response is too short")
	ErrPCPBadVersion    = errors.New("axon/peer: PCP response is not version 2")
	ErrPCPNotResponse   = errors.New("axon/peer: PCP datagram is a request, not a response")
	ErrPCPWrongOpcode   = errors.New("axon/peer: PCP response is for a different opcode")
	ErrPCPWrongSource   = errors.New("axon/peer: PCP response came from an address other than the gateway")
	ErrPCPEpochReset    = errors.New("axon/peer: PCP gateway epoch went backwards; the gateway restarted and every mapping is gone (RFC 6887 §8.5)")
)

// pcpResultError is a gateway refusal, with the code preserved.
type pcpResultError struct{ Code uint8 }

func (e pcpResultError) Error() string {
	return fmt.Sprintf("axon/peer: PCP gateway refused with result code %d (%s)", e.Code, pcpResultName(e.Code))
}

// pcpResultName names the codes an operator will actually hit. RFC 6887 §7.4.
//
// ADDRESS_MISMATCH is the one worth naming loudly: it means the client IP in the
// request is not the source the gateway saw, which is the signature of a SECOND
// layer of NAT. That is not a bug to retry -- it is the network telling the node
// that a mapping here cannot make it reachable, and §5's state machine should
// leave it un-MAPPED rather than keep asking.
func pcpResultName(c uint8) string {
	switch c {
	case 0:
		return "SUCCESS"
	case 1:
		return "UNSUPP_VERSION"
	case 2:
		return "NOT_AUTHORIZED -- the operator's gateway has PCP disabled"
	case 3:
		return "MALFORMED_REQUEST"
	case 4:
		return "UNSUPP_OPCODE"
	case 8:
		return "NO_RESOURCES"
	case 12:
		return "ADDRESS_MISMATCH -- this node is behind a second NAT, so no mapping here can make it reachable"
	case 13:
		return "EXCESSIVE_REMOTE_PEERS"
	default:
		return "see RFC 6887 §7.4"
	}
}

// pcpRequest builds a MAP request. RFC 6887 §11.1, field for field.
//
// Built by hand rather than by a struct encoder for the reason every wire format
// in this tree is: the layout is the interoperability contract with somebody
// else's router firmware, and a field-order change from a library upgrade would
// be a silent failure on a device nobody here can debug.
func pcpRequest(client netip.Addr, nonce [12]byte, internalPort, suggestedExternal uint16, lifetime time.Duration) []byte {
	b := make([]byte, pcpRequestLen)
	b[0] = pcpVersion
	b[1] = pcpOpcodeMAP // R bit clear: this is a request
	// b[2:4] reserved
	binary.BigEndian.PutUint32(b[4:8], uint32(lifetime.Seconds()))
	a16 := client.As16()
	copy(b[8:24], a16[:])
	copy(b[24:36], nonce[:])
	b[36] = pcpProtoUDP
	// b[37:40] reserved
	binary.BigEndian.PutUint16(b[40:42], internalPort)
	binary.BigEndian.PutUint16(b[42:44], suggestedExternal)
	// b[44:60] suggested external IP: all zeros means "you choose", which is
	// what a node behind an ordinary NAT wants. Asking for a specific address
	// is how a node that has been assigned one keeps it across a gateway
	// restart, and nothing here has one to ask for.
	return b
}

// pcpResponse is a parsed MAP response.
type pcpResponse struct {
	Lifetime     time.Duration
	Epoch        uint32
	ExternalPort uint16
	ExternalAddr netip.Addr
	InternalPort uint16
}

// parsePCPResponse validates and decodes a MAP response.
//
// It checks, IN THIS ORDER, everything that could make the datagram somebody
// else's: length, version, the R bit, the opcode, the result code, and the
// nonce. The nonce check is last because it is the only one that costs a
// comparison against per-client state, and first-cheapest ordering means a
// flood of malformed datagrams is rejected without touching it.
func parsePCPResponse(b []byte, wantNonce [12]byte) (pcpResponse, error) {
	var r pcpResponse
	if len(b) < pcpResponseLen {
		return r, fmt.Errorf("%w: %d bytes, want %d", ErrPCPShortResponse, len(b), pcpResponseLen)
	}
	if b[0] != pcpVersion {
		return r, fmt.Errorf("%w: version %d", ErrPCPBadVersion, b[0])
	}
	if b[1]&0x80 == 0 {
		return r, ErrPCPNotResponse
	}
	if b[1]&0x7f != pcpOpcodeMAP {
		return r, fmt.Errorf("%w: opcode %d", ErrPCPWrongOpcode, b[1]&0x7f)
	}
	if code := b[3]; code != pcpResultSuccess {
		return r, pcpResultError{Code: code}
	}
	var gotNonce [12]byte
	copy(gotNonce[:], b[24:36])
	if gotNonce != wantNonce {
		return r, ErrPCPNonceMismatch
	}

	r.Lifetime = time.Duration(binary.BigEndian.Uint32(b[4:8])) * time.Second
	r.Epoch = binary.BigEndian.Uint32(b[8:12])
	r.InternalPort = binary.BigEndian.Uint16(b[40:42])
	r.ExternalPort = binary.BigEndian.Uint16(b[42:44])
	var ext [16]byte
	copy(ext[:], b[44:60])
	addr := netip.AddrFrom16(ext)
	// RFC 6887 §5: IPv4 addresses travel as IPv4-mapped IPv6. Unmapping them
	// keeps the rest of §5 comparing like with like -- an IPv4-mapped form and
	// a plain IPv4 form of the same address are different netip.Addr values and
	// would defeat the reachability quorum's equality checks.
	r.ExternalAddr = addr.Unmap()
	return r, nil
}

// pcpMapper maps over PCP.
type pcpMapper struct {
	gateway netip.Addr
	local   netip.Addr
	nonce   [12]byte
	// port is pcpPort in production. It is a field only so a test can point a
	// mapper at a loopback gateway; nothing configures it.
	port uint16

	mu    sync.Mutex
	epoch uint32
	seen  bool
}

// NewPCPMapper builds a PCP client for a gateway.
//
// The nonce is drawn ONCE per mapper and reused across refreshes, which is
// RFC 6887's design: the nonce identifies the MAPPING, so a refresh carrying a
// fresh nonce would create a second mapping rather than extend the first, and
// the node would leak a mapping per refresh until the gateway ran out.
func NewPCPMapper(gateway, local netip.Addr) (Mapper, error) {
	if !gateway.IsValid() {
		return nil, errors.New("axon/peer: PCP needs a gateway address")
	}
	m := &pcpMapper{gateway: gateway, local: local, port: pcpPort}
	if _, err := rand.Read(m.nonce[:]); err != nil {
		return nil, err
	}
	return m, nil
}

func (p *pcpMapper) Protocol() MappingProtocol { return MappingPCP }

// checkEpoch implements RFC 6887 §8.5's restart detection.
//
// The gateway's epoch counts seconds since IT started. If it goes BACKWARDS the
// gateway restarted, and every mapping it held is gone -- including this one,
// which the gateway will happily keep answering about because the response is
// generated from the request. Without this check a node keeps advertising a
// MAPPED address that stopped working, which is worse than never having mapped:
// §5's state machine demotes on a failed refresh, and a refresh that succeeds
// against a restarted gateway never fails.
func (p *pcpMapper) checkEpoch(epoch uint32) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.seen && epoch < p.epoch {
		p.epoch = epoch
		return fmt.Errorf("%w: %d then %d", ErrPCPEpochReset, p.epoch, epoch)
	}
	p.epoch, p.seen = epoch, true
	return nil
}

// exchange sends one PCP request and reads the response.
func (p *pcpMapper) exchange(ctx context.Context, req []byte) (pcpResponse, error) {
	gw := net.UDPAddrFromAddrPort(netip.AddrPortFrom(p.gateway, p.port))
	conn, err := net.DialUDP("udp", nil, gw)
	if err != nil {
		return pcpResponse{}, err
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(req); err != nil {
		return pcpResponse{}, err
	}
	buf := make([]byte, 1100) // RFC 6887 §7: responses are at most 1100 bytes
	n, from, err := conn.ReadFromUDP(buf)
	if err != nil {
		return pcpResponse{}, err
	}
	// The socket is connected so the kernel already filters, but PCP's threat
	// model is an off-path attacker and belt-and-braces here costs one compare.
	if fa, ok := netip.AddrFromSlice(from.IP); !ok || fa.Unmap() != p.gateway {
		return pcpResponse{}, ErrPCPWrongSource
	}
	return parsePCPResponse(buf[:n], p.nonce)
}

// Map requests a UDP mapping.
func (p *pcpMapper) Map(ctx context.Context, internalPort uint16, lease time.Duration) (Mapping, error) {
	req := pcpRequest(p.local, p.nonce, internalPort, internalPort, lease)
	resp, err := p.exchange(ctx, req)
	if err != nil {
		return Mapping{}, err
	}
	if err := p.checkEpoch(resp.Epoch); err != nil {
		return Mapping{}, err
	}
	// THE GRANTED LIFETIME IS THE GATEWAY'S, NOT THE ONE ASKED FOR. RFC 6887
	// §11.2 allows it to shorten the lease, and a node that refreshed on its own
	// requested figure would refresh after the mapping had already expired --
	// which looks exactly like a working mapping right up until it does not.
	return Mapping{
		Protocol:     MappingPCP,
		InternalPort: resp.InternalPort,
		ExternalPort: resp.ExternalPort,
		External:     resp.ExternalAddr,
		Lease:        resp.Lifetime,
		Acquired:     time.Now(),
	}, nil
}

// Unmap releases the mapping by requesting a zero lifetime (RFC 6887 §15).
func (p *pcpMapper) Unmap(ctx context.Context, m Mapping) error {
	req := pcpRequest(p.local, p.nonce, m.InternalPort, 0, 0)
	_, err := p.exchange(ctx, req)
	return err
}
