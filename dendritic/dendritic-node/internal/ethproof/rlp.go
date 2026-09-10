// Package ethproof verifies Ethereum state against a block header — P12-2.
//
// WHAT THIS IS FOR
// ----------------
// A watchtower has to answer "what does the chain say about this channel"
// without believing whoever told it. An `eth_call` answers the question and
// requires trusting the answer; a Merkle-Patricia proof answers it in a form
// that can be checked against a block header's state root.
//
//	block header
//	     |  stateRoot
//	     v
//	account proof        ->  the contract's storageRoot
//	     |
//	     v
//	storage proof        ->  one slot's value
//
// Verifying that chain is the difference between "Alchemy says the nonce is 5"
// and "the nonce is 5, and here is why". P12-5 supplies the missing half — a
// trustworthy header — and until it exists this narrows the trust to the header
// alone rather than removing it.
//
// WHY THE RLP DECODER IS HAND-WRITTEN
// -----------------------------------
// The same reason the ABI encoder in internal/channel is: pulling in go-ethereum
// for two hundred lines of decoding would bring a very large dependency into a
// module that deliberately has few, and the encoding is small, frozen and
// checkable against published vectors.
//
// Decoding only. Nothing here constructs RLP, because nothing here needs to.
package ethproof

import (
	"errors"
	"fmt"
)

// ErrMalformedRLP means the bytes are not RLP at all.
var ErrMalformedRLP = errors.New("ethproof: malformed RLP")

// rlpItem is either a byte string or a list. Exactly one is meaningful, which
// is what IsList distinguishes.
type rlpItem struct {
	IsList bool
	Bytes  []byte
	List   []rlpItem
}

// decodeRLP parses one item and returns it with the number of bytes consumed.
//
// Strict about trailing data at the top level — see DecodeRLP. A decoder that
// silently ignores what it did not understand is a decoder that can be fed two
// meanings in one payload.
func decodeRLP(b []byte) (rlpItem, int, error) {
	if len(b) == 0 {
		return rlpItem{}, 0, fmt.Errorf("%w: empty input", ErrMalformedRLP)
	}
	prefix := b[0]

	switch {
	// A single byte below 0x80 encodes itself.
	case prefix < 0x80:
		return rlpItem{Bytes: b[:1]}, 1, nil

	// Short string, 0-55 bytes.
	case prefix <= 0xB7:
		size := int(prefix - 0x80)
		if len(b) < 1+size {
			return rlpItem{}, 0, fmt.Errorf("%w: short string overruns", ErrMalformedRLP)
		}
		// Canonical form: a one-byte string below 0x80 must use the single-byte
		// encoding above. Accepting both would give one value two encodings, and
		// therefore two hashes.
		if size == 1 && b[1] < 0x80 {
			return rlpItem{}, 0, fmt.Errorf("%w: non-canonical single byte", ErrMalformedRLP)
		}
		return rlpItem{Bytes: b[1 : 1+size]}, 1 + size, nil

	// Long string: the prefix says how many bytes hold the length.
	case prefix <= 0xBF:
		lenOfLen := int(prefix - 0xB7)
		size, err := readLength(b, lenOfLen)
		if err != nil {
			return rlpItem{}, 0, err
		}
		start := 1 + lenOfLen
		if len(b) < start+size {
			return rlpItem{}, 0, fmt.Errorf("%w: long string overruns", ErrMalformedRLP)
		}
		return rlpItem{Bytes: b[start : start+size]}, start + size, nil

	// Short list.
	case prefix <= 0xF7:
		size := int(prefix - 0xC0)
		return decodeList(b, 1, size)

	// Long list.
	default:
		lenOfLen := int(prefix - 0xF7)
		size, err := readLength(b, lenOfLen)
		if err != nil {
			return rlpItem{}, 0, err
		}
		return decodeList(b, 1+lenOfLen, size)
	}
}

func readLength(b []byte, lenOfLen int) (int, error) {
	if lenOfLen < 1 || lenOfLen > 8 || len(b) < 1+lenOfLen {
		return 0, fmt.Errorf("%w: bad length prefix", ErrMalformedRLP)
	}
	if b[1] == 0 {
		// Leading zero in the length is non-canonical, and again would give one
		// value two encodings.
		return 0, fmt.Errorf("%w: non-canonical length", ErrMalformedRLP)
	}
	size := 0
	for _, c := range b[1 : 1+lenOfLen] {
		size = size<<8 | int(c)
	}
	if size < 0 {
		return 0, fmt.Errorf("%w: length overflows", ErrMalformedRLP)
	}
	return size, nil
}

func decodeList(b []byte, start, size int) (rlpItem, int, error) {
	end := start + size
	if size < 0 || len(b) < end {
		return rlpItem{}, 0, fmt.Errorf("%w: list overruns", ErrMalformedRLP)
	}
	out := rlpItem{IsList: true}
	for pos := start; pos < end; {
		item, used, err := decodeRLP(b[pos:end])
		if err != nil {
			return rlpItem{}, 0, err
		}
		out.List = append(out.List, item)
		pos += used
	}
	return out, end, nil
}

// DecodeRLP parses exactly one item and refuses trailing bytes.
func DecodeRLP(b []byte) (rlpItem, error) {
	item, used, err := decodeRLP(b)
	if err != nil {
		return rlpItem{}, err
	}
	if used != len(b) {
		return rlpItem{}, fmt.Errorf("%w: %d trailing bytes", ErrMalformedRLP, len(b)-used)
	}
	return item, nil
}
