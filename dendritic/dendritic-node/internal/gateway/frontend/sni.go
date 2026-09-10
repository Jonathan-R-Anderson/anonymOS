// Package frontend contains the edge half of the volunteer gateway: the pieces
// needed to accept a public TLS connection, decide where it belongs from the
// ClientHello alone, and hand it on WITHOUT decrypting it.
//
// Nothing here terminates TLS. The volunteer must never hold a private key for
// the site's public hostname, so the routing decision has to be made from the
// only thing visible before the handshake completes: the SNI extension.
package frontend

import (
	"errors"
	"io"
	"strings"
)

// A ClientHello large enough to exceed this is not one we intend to serve. The
// TLS record layer allows 16 KiB of plaintext per record; the handshake may
// legally span several, but a hello that needs more than one oversized record
// is either an attack or a client we cannot route anyway.
const maxHelloBytes = 16 << 10

var (
	// ErrNotTLS is returned for bytes that are not a TLS handshake record. It is
	// deliberately distinct from a malformed hello: a plaintext HTTP request on
	// 443 is a common operator mistake and deserves its own log line.
	ErrNotTLS = errors.New("frontend: not a TLS handshake record")
	// ErrNoSNI is returned for a well-formed hello carrying no server name.
	// This is FATAL for routing, not a fallback: without a name there is no safe
	// backend to choose, and guessing turns the proxy into an open relay.
	ErrNoSNI = errors.New("frontend: ClientHello carries no SNI")
	// ErrMalformed covers truncation and internal length inconsistencies.
	ErrMalformed = errors.New("frontend: malformed ClientHello")
	// ErrTooLarge guards the read bound.
	ErrTooLarge = errors.New("frontend: ClientHello exceeds the size bound")
)

// PeekSNI reads just enough of r to extract the SNI host, and returns BOTH the
// name and every byte consumed.
//
// Returning the consumed bytes is the whole point. The connection is going to be
// spliced to a backend that must receive an unmodified handshake, so the caller
// replays `raw` ahead of the rest of the stream. A parser that swallowed the
// hello would make passthrough impossible.
//
// The returned name is lower-cased and stripped of a trailing dot. It is NOT
// validated against any allowlist here — routing policy is the caller's job, and
// keeping parsing free of policy is what makes both testable.
func PeekSNI(r io.Reader) (name string, raw []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", nil, ErrNotTLS
	}
	raw = append(raw, header...)
	// 0x16 = handshake. A TLS 1.3 client still sends a legacy 0x0301/0x0303
	// record version here, so the version bytes are read but not enforced.
	if header[0] != 0x16 {
		return "", raw, ErrNotTLS
	}
	length := int(header[3])<<8 | int(header[4])
	if length == 0 || length > maxHelloBytes {
		return "", raw, ErrTooLarge
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", raw, ErrMalformed
	}
	raw = append(raw, body...)
	host, err := sniFromHandshake(body)
	if err != nil {
		return "", raw, err
	}
	return host, raw, nil
}

// cursor is a bounds-checked reader over the handshake body. Every read is
// length-checked, so a truncated or lying length field yields ErrMalformed
// rather than a panic or an out-of-bounds slice.
type cursor struct {
	data []byte
	pos  int
}

func (c *cursor) bytes(n int) ([]byte, bool) {
	if n < 0 || c.pos+n > len(c.data) {
		return nil, false
	}
	out := c.data[c.pos : c.pos+n]
	c.pos += n
	return out, true
}

func (c *cursor) u8() (int, bool) {
	value, ok := c.bytes(1)
	if !ok {
		return 0, false
	}
	return int(value[0]), true
}

func (c *cursor) u16() (int, bool) {
	value, ok := c.bytes(2)
	if !ok {
		return 0, false
	}
	return int(value[0])<<8 | int(value[1]), true
}

func (c *cursor) skip(n int) bool {
	_, ok := c.bytes(n)
	return ok
}

func sniFromHandshake(body []byte) (string, error) {
	c := &cursor{data: body}

	messageType, ok := c.u8()
	if !ok {
		return "", ErrMalformed
	}
	if messageType != 0x01 { // client_hello
		return "", ErrNotTLS
	}
	// 24-bit handshake length. Read it to advance, but trust the record bound
	// above rather than this field: a hello spanning several records would
	// declare more than we hold, and we refuse those rather than buffering.
	rawLength, ok := c.bytes(3)
	if !ok {
		return "", ErrMalformed
	}
	declared := int(rawLength[0])<<16 | int(rawLength[1])<<8 | int(rawLength[2])
	if declared > len(body)-c.pos {
		return "", ErrMalformed
	}
	if !c.skip(2 + 32) { // legacy_version + random
		return "", ErrMalformed
	}
	sessionLength, ok := c.u8()
	if !ok || !c.skip(sessionLength) {
		return "", ErrMalformed
	}
	cipherLength, ok := c.u16()
	if !ok || !c.skip(cipherLength) {
		return "", ErrMalformed
	}
	compressionLength, ok := c.u8()
	if !ok || !c.skip(compressionLength) {
		return "", ErrMalformed
	}
	extensionsLength, ok := c.u16()
	if !ok {
		// No extension block at all is legal TLS and simply means no SNI.
		return "", ErrNoSNI
	}
	extensions, ok := c.bytes(extensionsLength)
	if !ok {
		return "", ErrMalformed
	}
	return sniFromExtensions(extensions)
}

func sniFromExtensions(extensions []byte) (string, error) {
	c := &cursor{data: extensions}
	for c.pos < len(c.data) {
		extensionType, ok := c.u16()
		if !ok {
			return "", ErrMalformed
		}
		extensionLength, ok := c.u16()
		if !ok {
			return "", ErrMalformed
		}
		payload, ok := c.bytes(extensionLength)
		if !ok {
			return "", ErrMalformed
		}
		if extensionType != 0x0000 { // server_name
			continue
		}
		return hostFromServerNameList(payload)
	}
	return "", ErrNoSNI
}

func hostFromServerNameList(payload []byte) (string, error) {
	c := &cursor{data: payload}
	listLength, ok := c.u16()
	if !ok {
		return "", ErrMalformed
	}
	list, ok := c.bytes(listLength)
	if !ok {
		return "", ErrMalformed
	}
	inner := &cursor{data: list}
	for inner.pos < len(inner.data) {
		nameType, ok := inner.u8()
		if !ok {
			return "", ErrMalformed
		}
		nameLength, ok := inner.u16()
		if !ok {
			return "", ErrMalformed
		}
		value, ok := inner.bytes(nameLength)
		if !ok {
			return "", ErrMalformed
		}
		if nameType != 0x00 { // host_name
			continue
		}
		// RFC 6066 permits only one host_name, and duplicates have been used to
		// desynchronise a router from the server that later reads the same
		// hello. Take the FIRST and never merge, but reject an empty one rather
		// than returning "" and letting the caller treat it as a wildcard.
		host := normalizeHost(string(value))
		if host == "" {
			return "", ErrMalformed
		}
		return host, nil
	}
	return "", ErrNoSNI
}

// normalizeHost lower-cases and drops one trailing dot so "SYNDICHAN.ORG." and
// "syndichan.org" compare equal against an allowlist. Anything containing a NUL,
// a slash, or whitespace is rejected by returning "": those cannot appear in a
// legitimate host_name and are a classic way to smuggle a second value past a
// naive comparison.
func normalizeHost(value string) string {
	if value == "" || len(value) > 253 {
		return ""
	}
	if strings.ContainsAny(value, "\x00 \t\r\n/\\") {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(value), ".")
}
