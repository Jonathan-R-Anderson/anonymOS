package frontend

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"
)

func mustAddrPort(t *testing.T, value string) netip.AddrPort {
	t.Helper()
	parsed, err := netip.ParseAddrPort(value)
	if err != nil {
		t.Fatalf("parse %q: %v", value, err)
	}
	return parsed
}

func TestProxyHeaderV2IPv4IsByteExact(t *testing.T) {
	header, err := ProxyHeaderV2(
		mustAddrPort(t, "198.51.100.7:54321"),
		mustAddrPort(t, "51.79.71.153:443"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []byte{
		0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
		0x21,       // v2, PROXY
		0x11,       // TCP over IPv4
		0x00, 0x0C, // 12 bytes follow
		198, 51, 100, 7,
		51, 79, 71, 153,
		0xD4, 0x31, // 54321
		0x01, 0xBB, // 443
	}
	if !bytes.Equal(header, want) {
		t.Fatalf("header mismatch\n got %v\nwant %v", header, want)
	}
}

func TestProxyHeaderV2IPv6Length(t *testing.T) {
	header, err := ProxyHeaderV2(
		mustAddrPort(t, "[2001:db8::7]:54321"),
		mustAddrPort(t, "[2001:db8::1]:443"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(header[:12], proxyV2Signature) {
		t.Fatal("signature mismatch")
	}
	if header[13] != proxyV2TCPOverIPv6 {
		t.Fatalf("family/protocol = %#x, want %#x", header[13], proxyV2TCPOverIPv6)
	}
	if got := int(header[14])<<8 | int(header[15]); got != 36 {
		t.Fatalf("declared length = %d, want 36", got)
	}
	if len(header) != 16+36 {
		t.Fatalf("header length = %d, want %d", len(header), 16+36)
	}
}

// A v4-mapped v6 client must be announced as TCP4. Announcing ::ffff:198.51.100.7
// would make the origin record a v6 address for a v4 client, and every IP ban,
// geoip lookup and bot-token comparison downstream would quietly stop matching.
func TestProxyHeaderV2UnmapsV4MappedClients(t *testing.T) {
	header, err := ProxyHeaderV2(
		mustAddrPort(t, "[::ffff:198.51.100.7]:54321"),
		mustAddrPort(t, "51.79.71.153:443"),
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if header[13] != proxyV2TCPOverIPv4 {
		t.Fatalf("family/protocol = %#x, want TCP4 %#x", header[13], proxyV2TCPOverIPv4)
	}
	if !bytes.Equal(header[16:20], []byte{198, 51, 100, 7}) {
		t.Fatalf("client address = %v, want 198.51.100.7", header[16:20])
	}
}

func TestProxyHeaderV2RejectsMixedFamilies(t *testing.T) {
	_, err := ProxyHeaderV2(
		mustAddrPort(t, "198.51.100.7:54321"),
		mustAddrPort(t, "[2001:db8::1]:443"),
	)
	if !errors.Is(err, ErrAddressFamilyMismatch) {
		t.Fatalf("mixed families gave %v, want ErrAddressFamilyMismatch", err)
	}
}

func TestProxyHeaderV2RejectsInvalidAddresses(t *testing.T) {
	_, err := ProxyHeaderV2(netip.AddrPort{}, mustAddrPort(t, "51.79.71.153:443"))
	if !errors.Is(err, ErrInvalidAddress) {
		t.Fatalf("zero address gave %v, want ErrInvalidAddress", err)
	}
}
