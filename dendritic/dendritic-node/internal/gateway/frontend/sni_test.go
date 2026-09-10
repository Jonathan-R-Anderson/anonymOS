package frontend

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// realClientHello captures the bytes Go's own TLS stack puts on the wire for a
// given server name. Hand-written fixtures encode the author's belief about the
// format; this encodes the format.
func realClientHello(t testing.TB, serverName string) []byte {
	t.Helper()
	client, server := net.Pipe()
	captured := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 4096)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := server.Read(buffer)
		captured <- append([]byte(nil), buffer[:n]...)
		server.Close()
	}()
	conn := tls.Client(client, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = conn.Handshake() // fails: the peer never answers. The hello is already sent.
	client.Close()
	select {
	case hello := <-captured:
		if len(hello) == 0 {
			t.Fatal("captured an empty ClientHello")
		}
		return hello
	case <-time.After(5 * time.Second):
		t.Fatal("timed out capturing the ClientHello")
		return nil
	}
}

func TestPeekSNIReadsARealClientHello(t *testing.T) {
	for _, name := range []string{"syndichan.org", "gw-abc123.syndichan.org"} {
		hello := realClientHello(t, name)
		got, raw, err := PeekSNI(bytes.NewReader(hello))
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		if got != name {
			t.Fatalf("SNI = %q, want %q", got, name)
		}
		// Passthrough depends on this: every consumed byte must come back so the
		// handshake can be replayed to the backend unmodified.
		if !bytes.Equal(raw, hello[:len(raw)]) {
			t.Fatal("returned bytes are not a prefix of the original hello")
		}
		if len(raw) == 0 {
			t.Fatal("no bytes returned for replay")
		}
	}
}

func TestPeekSNINormalizesCaseAndTrailingDot(t *testing.T) {
	// Go's stack rejects a trailing dot in ServerName, so exercise the
	// normalizer directly rather than pretending the wire can carry one.
	for _, tc := range []struct{ in, want string }{
		{"SYNDICHAN.ORG", "syndichan.org"},
		{"syndichan.org.", "syndichan.org"},
		{"GW-ABC.Syndichan.Org.", "gw-abc.syndichan.org"},
		{"", ""},
		{"host name", ""},
		{"host/name", ""},
		{"host\x00name", ""},
	} {
		if got := normalizeHost(tc.in); got != tc.want {
			t.Fatalf("normalizeHost(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestPeekSNIRejectsNonTLS(t *testing.T) {
	_, _, err := PeekSNI(bytes.NewReader([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")))
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("plaintext HTTP gave %v, want ErrNotTLS", err)
	}
}

func TestPeekSNIRejectsHelloWithoutSNI(t *testing.T) {
	// Go refuses to build a hello with neither ServerName nor InsecureSkipVerify,
	// so the no-SNI case needs the latter. This is the shape a client dialling a
	// bare IP produces, and it must be refused rather than routed by default.
	client, server := net.Pipe()
	captured := make(chan []byte, 1)
	go func() {
		buffer := make([]byte, 4096)
		_ = server.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, _ := server.Read(buffer)
		captured <- append([]byte(nil), buffer[:n]...)
		server.Close()
	}()
	conn := tls.Client(client, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_ = conn.Handshake()
	client.Close()

	var hello []byte
	select {
	case hello = <-captured:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out capturing the ClientHello")
	}
	if len(hello) == 0 {
		t.Fatal("captured an empty ClientHello")
	}
	name, _, err := PeekSNI(bytes.NewReader(hello))
	if !errors.Is(err, ErrNoSNI) {
		t.Fatalf("hello without SNI gave (%q, %v), want ErrNoSNI", name, err)
	}
}

// Truncation at EVERY offset must produce an error, never a panic and never a
// partial host. This is the property that matters for a parser fed by anyone on
// the internet.
func TestPeekSNITruncatedAtEveryOffset(t *testing.T) {
	hello := realClientHello(t, "syndichan.org")
	for cut := 0; cut < len(hello); cut++ {
		func() {
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("panic at truncation offset %d: %v", cut, p)
				}
			}()
			name, _, err := PeekSNI(bytes.NewReader(hello[:cut]))
			if err == nil {
				t.Fatalf("offset %d parsed successfully, want an error", cut)
			}
			if name != "" {
				t.Fatalf("offset %d returned host %q on error", cut, name)
			}
		}()
	}
}

// Every single-byte corruption must either error or yield one syntactically
// valid hostname. Mutating an SNI byte can legitimately turn one hostname into
// another; the caller's exact allowlist is the security boundary that refuses
// that new name.
func TestPeekSNICorruptionNeverYieldsMalformedName(t *testing.T) {
	hello := realClientHello(t, "syndichan.org")
	for i := 0; i < len(hello); i++ {
		for _, mask := range []byte{0xFF, 0x01, 0x80} {
			mutated := append([]byte(nil), hello...)
			mutated[i] ^= mask
			func() {
				defer func() {
					if p := recover(); p != nil {
						t.Fatalf("panic on corruption at %d: %v", i, p)
					}
				}()
				name, _, err := PeekSNI(bytes.NewReader(mutated))
				if err == nil && normalizeHost(name) != name {
					t.Fatalf("corruption at byte %d produced malformed host %q", i, name)
				}
			}()
		}
	}
}

func TestServerNameListUsesFirstHostName(t *testing.T) {
	payload := []byte{
		0x00, 0x26, // list length
		0x00, 0x00, 0x0d, // host_name, length 13
		's', 'y', 'n', 'd', 'i', 'c', 'h', 'a', 'n', '.', 'o', 'r', 'g',
		0x00, 0x00, 0x13, // duplicate host_name, length 19
		'a', 't', 't', 'a', 'c', 'k', 'e', 'r', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o',
	}
	name, err := hostFromServerNameList(payload)
	if err != nil {
		t.Fatal(err)
	}
	if name != "syndichan.org" {
		t.Fatalf("selected %q, want first host_name", name)
	}
}

func TestPeekSNIRejectsOversizedRecord(t *testing.T) {
	header := []byte{0x16, 0x03, 0x01, 0xFF, 0xFF} // 65535 > maxHelloBytes
	_, _, err := PeekSNI(bytes.NewReader(header))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("oversized record gave %v, want ErrTooLarge", err)
	}
}

func TestPeekSNIRejectsZeroLengthRecord(t *testing.T) {
	_, _, err := PeekSNI(bytes.NewReader([]byte{0x16, 0x03, 0x01, 0x00, 0x00}))
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("zero-length record gave %v, want ErrTooLarge", err)
	}
}

func TestPeekSNIRejectsEmptyHostName(t *testing.T) {
	// A hello whose host_name entry has length zero: legal framing, no name.
	// Returning "" here would let the caller match a wildcard allowlist entry.
	extensions := []byte{
		0x00, 0x00, // server_name
		0x00, 0x05, // extension length
		0x00, 0x03, // list length
		0x00,       // host_name
		0x00, 0x00, // name length 0
	}
	_, err := sniFromExtensions(extensions)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("empty host_name gave %v, want ErrMalformed", err)
	}
}

func TestPeekSNIRejectsLyingExtensionLength(t *testing.T) {
	extensions := []byte{
		0x00, 0x00, // server_name
		0x7F, 0xFF, // claims 32767 bytes that are not present
		0x00,
	}
	_, err := sniFromExtensions(extensions)
	if !errors.Is(err, ErrMalformed) {
		t.Fatalf("lying extension length gave %v, want ErrMalformed", err)
	}
}

func TestPeekSNIStopsAtShortReader(t *testing.T) {
	_, _, err := PeekSNI(io.LimitReader(bytes.NewReader([]byte{0x16, 0x03}), 2))
	if !errors.Is(err, ErrNotTLS) {
		t.Fatalf("short header gave %v, want ErrNotTLS", err)
	}
}

func FuzzPeekSNI(f *testing.F) {
	f.Add(realClientHello(f, "syndichan.org"))
	f.Add([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0x01})
	f.Add([]byte("not tls at all"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		// The only contract under fuzz: never panic, and never return a name
		// together with an error.
		name, _, err := PeekSNI(bytes.NewReader(data))
		if err != nil && name != "" {
			t.Fatalf("returned host %q alongside error %v", name, err)
		}
	})
}
