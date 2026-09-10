package frontend

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// PROXY protocol v2, as published by HAProxy. The volunteer cannot add an
// X-Forwarded-For header to a stream it deliberately cannot decrypt, so the
// client's address has to travel AHEAD of the TLS bytes. This header is the
// only mechanism compatible with passthrough.
//
// The origin must accept this header ONLY from verified gateway addresses.
// Anyone permitted to send it can claim to be any IP, which would forge the
// address the site uses for bans, geoip and the bot-token lock.

// The v2 signature is fixed by the specification.
var proxyV2Signature = []byte{
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
}

const (
	proxyV2VersionCommand = 0x21 // version 2, command PROXY (real connection)
	proxyV2TCPOverIPv4    = 0x11
	proxyV2TCPOverIPv6    = 0x21
)

var (
	// ErrAddressFamilyMismatch guards against emitting a header whose declared
	// family disagrees with its address block — a malformed header is worse than
	// no header, because the receiver may accept it and attribute the connection
	// to a garbage address.
	ErrAddressFamilyMismatch = errors.New("frontend: source and destination address families differ")
	// ErrInvalidAddress rejects unset or non-IP endpoints.
	ErrInvalidAddress = errors.New("frontend: invalid PROXY protocol address")
)

// ProxyHeaderV2 builds the header announcing that `client` opened a connection
// which this node is forwarding to `origin`.
//
// Both endpoints must be the same family. A v4-mapped v6 address is unmapped
// first, so a client arriving on a dual-stack listener as ::ffff:198.51.100.7 is
// announced as TCP4 — otherwise the origin records a v6 address for a v4 client
// and every downstream IP comparison silently fails to match.
func ProxyHeaderV2(client, origin netip.AddrPort) ([]byte, error) {
	clientAddr := client.Addr().Unmap()
	originAddr := origin.Addr().Unmap()
	if !clientAddr.IsValid() || !originAddr.IsValid() {
		return nil, ErrInvalidAddress
	}
	if clientAddr.Is4() != originAddr.Is4() {
		return nil, ErrAddressFamilyMismatch
	}

	var (
		familyProtocol byte
		addressSize    int
	)
	if clientAddr.Is4() {
		familyProtocol, addressSize = proxyV2TCPOverIPv4, 4
	} else {
		familyProtocol, addressSize = proxyV2TCPOverIPv6, 16
	}

	// signature(12) + version/command(1) + family/protocol(1) + length(2)
	header := make([]byte, 0, 16+2*addressSize+4)
	header = append(header, proxyV2Signature...)
	header = append(header, proxyV2VersionCommand, familyProtocol)
	header = binary.BigEndian.AppendUint16(header, uint16(2*addressSize+4))

	clientBytes := clientAddr.As16()
	originBytes := originAddr.As16()
	if addressSize == 4 {
		clientSlice := clientAddr.As4()
		originSlice := originAddr.As4()
		header = append(header, clientSlice[:]...)
		header = append(header, originSlice[:]...)
	} else {
		header = append(header, clientBytes[:]...)
		header = append(header, originBytes[:]...)
	}
	header = binary.BigEndian.AppendUint16(header, client.Port())
	header = binary.BigEndian.AppendUint16(header, origin.Port())
	return header, nil
}
