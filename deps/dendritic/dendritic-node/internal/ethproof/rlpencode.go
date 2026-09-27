package ethproof

// RLP encoding — roadmap P14.5.
//
// WHY THIS IS A SEPARATE FILE FROM rlp.go
// ---------------------------------------
// rlp.go decodes and says so: "Decoding only. Nothing here constructs RLP,
// because nothing here needs to." That stopped being true when the watchtower
// needed to REBUILD a receipts trie rather than walk a proof through one.
//
// The tempting shortcut is to run the decoder backwards — take the rlpItem tree
// and re-emit it. That is wrong for a reason worth stating: a decoder that
// accepts a non-canonical encoding and an encoder derived from it will
// reproduce the input it was given rather than the canonical form, and the
// whole point of rebuilding a trie is to compute what Ethereum WOULD have
// computed. An encoder must have exactly one output per value. So this is
// written forwards, from the specification, and the round-trip property is
// tested against real mainnet data rather than against the decoder.
//
// CANONICAL FORM IS THE ENTIRE JOB
// --------------------------------
// Every rule here exists because breaking it produces a different hash:
//
//	a single byte below 0x80        encodes as itself, never as 0x81 0xNN
//	zero                            is the EMPTY string 0x80, never 0x00
//	an integer                      is minimal big-endian, no leading zeros
//	a length below 56               uses the short form
//
// A violation does not fail loudly. It produces a self-consistent trie that
// matches no block on Ethereum, which looks exactly like a provider lying.

import "math/big"

// EncodeRLPBytes encodes a byte string.
func EncodeRLPBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return []byte{b[0]}
	}
	out := rlpLengthPrefix(0x80, len(b))
	return append(out, b...)
}

// EncodeRLPList wraps items that are ALREADY encoded.
//
// It does not encode its arguments, and that is deliberate: a list of
// heterogeneous things — strings, nested lists, node references that are
// sometimes a hash and sometimes an inlined node — has no single encoding rule,
// so the caller states what each item is and this only frames them.
func EncodeRLPList(items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	out := rlpLengthPrefix(0xC0, n)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// EncodeRLPUint encodes an integer as a minimal big-endian byte string.
//
// Zero is the empty string. This is the single commonest RLP mistake: 0x00 is a
// one-byte string containing zero, which is a DIFFERENT value from the integer
// zero and hashes differently.
func EncodeRLPUint(v uint64) []byte {
	if v == 0 {
		return []byte{0x80}
	}
	var be [8]byte
	i := 8
	for x := v; x > 0; x >>= 8 {
		i--
		be[i] = byte(x)
	}
	return EncodeRLPBytes(be[i:])
}

// EncodeRLPBig encodes a big integer the same way, for header fields that do
// not fit in 64 bits.
//
// Negative values are impossible in every Ethereum field this encodes, and are
// treated as zero rather than silently producing a two's-complement byte string
// that would encode as an enormous positive number.
func EncodeRLPBig(v *big.Int) []byte {
	if v == nil || v.Sign() <= 0 {
		return []byte{0x80}
	}
	return EncodeRLPBytes(v.Bytes())
}

// rlpLengthPrefix builds a header. base is 0x80 for strings and 0xC0 for lists;
// the long form is base+55+len(lengthBytes), which lands on 0xB7 and 0xF7.
func rlpLengthPrefix(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	var be [8]byte
	i := 8
	for x := n; x > 0; x >>= 8 {
		i--
		be[i] = byte(x)
	}
	out := make([]byte, 0, 1+(8-i)+n)
	out = append(out, base+55+byte(8-i))
	return append(out, be[i:]...)
}
