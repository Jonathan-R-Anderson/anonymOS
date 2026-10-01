package dht

import (
	"errors"
	"fmt"
	"net/netip"
)

// The FIND_VALUE wire protocol carried over a circuit (item 2.10b, R4(b)).
//
// A lookup path's circuit ends at a relay. The client sends that relay one
// LookupRequest -- which contact to ask, for which key -- and the relay asks it
// AS ITSELF and returns the LookupResponse. The storing node sees the relay's
// address and the key; the client's address never reaches it. That is the whole
// of R4(b), and the binding that keeps the d paths on d different relays is
// CircuitRPC's, not this file's.
//
// Both messages are canonical CBOR in the same deterministic mode as the
// records. Every length is bounded on decode: these arrive from a relay or a
// client, neither trusted, and an unbounded list is how a parser becomes an
// allocator for somebody else.

// MaxLookupWire bounds a returned record. Descriptors are the largest record
// class (8 KiB, §7); twice that leaves room without inviting abuse.
const MaxLookupWire = 16 << 10

// MaxLookupMessage bounds an encoded LookupResponse: BucketSize contacts of at
// most ~120 bytes each, plus the record, plus framing.
const MaxLookupMessage = MaxLookupWire + BucketSize*160 + 64

var ErrLookupWire = errors.New("axon/dht: malformed lookup message")

type wireContact struct {
	NodeIDPub []byte `cbor:"1,keyasint"`
	KadID     []byte `cbor:"2,keyasint"`
	Addr      []byte `cbor:"3,keyasint"` // 4 or 16 bytes
	PFamily   uint8  `cbor:"4,keyasint"`
	PBytes    []byte `cbor:"5,keyasint"`
	ASN       uint32 `cbor:"6,keyasint"`
}

type wireRequest struct {
	To  wireContact `cbor:"1,keyasint"`
	Key []byte      `cbor:"2,keyasint"`
}

type wireResponse struct {
	Closer  []wireContact `cbor:"1,keyasint"`
	Wire    []byte        `cbor:"2,keyasint,omitempty"`
	Refused bool          `cbor:"3,keyasint,omitempty"`
}

func toWire(c Contact) wireContact {
	return wireContact{
		NodeIDPub: append([]byte(nil), c.NodeIDPub[:]...),
		KadID:     append([]byte(nil), c.KadID[:]...),
		Addr:      c.Addr.AsSlice(),
		PFamily:   c.Prefix.Family,
		PBytes:    append([]byte(nil), c.Prefix.Bytes...),
		ASN:       c.ASN,
	}
}

// fromWire decodes a contact. Verified is ALWAYS false: a contact that arrived
// in a lookup reply was mentioned, not met (§7.3 rule (c)), and may make routing
// progress but never count toward a replica set.
func fromWire(w wireContact) (Contact, error) {
	var c Contact
	if len(w.NodeIDPub) != 32 || len(w.KadID) != 32 {
		return c, fmt.Errorf("%w: contact id sizes", ErrLookupWire)
	}
	copy(c.NodeIDPub[:], w.NodeIDPub)
	copy(c.KadID[:], w.KadID)
	addr, ok := netip.AddrFromSlice(w.Addr)
	if !ok {
		return c, fmt.Errorf("%w: contact address", ErrLookupWire)
	}
	c.Addr = addr.Unmap()
	if (w.PFamily != 0x04 || len(w.PBytes) != 3) && (w.PFamily != 0x06 || len(w.PBytes) != 6) {
		return c, fmt.Errorf("%w: contact prefix", ErrLookupWire)
	}
	c.Prefix = NetworkPrefix{Family: w.PFamily, Bytes: append([]byte(nil), w.PBytes...)}
	c.ASN = w.ASN
	c.Verified = false
	return c, nil
}

// EncodeLookupRequest is the client's message to the terminal relay.
func EncodeLookupRequest(to Contact, key Key) ([]byte, error) {
	return encMode.Marshal(wireRequest{To: toWire(to), Key: append([]byte(nil), key[:]...)})
}

// DecodeLookupRequest is the terminal relay's side.
func DecodeLookupRequest(b []byte) (Contact, Key, error) {
	var w wireRequest
	var key Key
	if len(b) > 512 {
		return Contact{}, key, fmt.Errorf("%w: request is %d bytes", ErrLookupWire, len(b))
	}
	if err := decMode.Unmarshal(b, &w); err != nil {
		return Contact{}, key, fmt.Errorf("%w: %v", ErrLookupWire, err)
	}
	if len(w.Key) != len(key) {
		return Contact{}, key, fmt.Errorf("%w: key size", ErrLookupWire)
	}
	copy(key[:], w.Key)
	c, err := fromWire(w.To)
	return c, key, err
}

// EncodeLookupResponse is the terminal relay's answer.
func EncodeLookupResponse(r Response) ([]byte, error) {
	if len(r.Closer) > BucketSize || len(r.Wire) > MaxLookupWire {
		return nil, fmt.Errorf("%w: response over its bounds", ErrLookupWire)
	}
	w := wireResponse{Wire: r.Wire, Refused: r.Refused}
	for _, c := range r.Closer {
		w.Closer = append(w.Closer, toWire(c))
	}
	return encMode.Marshal(w)
}

// DecodeLookupResponse is the client's side.
func DecodeLookupResponse(b []byte) (Response, error) {
	var w wireResponse
	if len(b) > MaxLookupMessage {
		return Response{}, fmt.Errorf("%w: response is %d bytes", ErrLookupWire, len(b))
	}
	if err := decMode.Unmarshal(b, &w); err != nil {
		return Response{}, fmt.Errorf("%w: %v", ErrLookupWire, err)
	}
	if len(w.Closer) > BucketSize || len(w.Wire) > MaxLookupWire {
		return Response{}, fmt.Errorf("%w: response over its bounds", ErrLookupWire)
	}
	r := Response{Wire: w.Wire, Refused: w.Refused}
	for _, wc := range w.Closer {
		c, err := fromWire(wc)
		if err != nil {
			return Response{}, err
		}
		r.Closer = append(r.Closer, c)
	}
	return r, nil
}
