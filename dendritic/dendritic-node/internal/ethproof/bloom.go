package ethproof

// The logs bloom, used as a NEGATIVE filter only — roadmap P14.5.
//
// THE ASYMMETRY THAT MAKES THIS SAFE
// ----------------------------------
// A bloom filter has false positives and NO false negatives. So exactly one
// direction of its answer is authoritative:
//
//	bloom says ABSENT   ->  the contract emitted nothing in this block. Certain.
//	bloom says PRESENT  ->  it might have. Evidence of nothing.
//
// The watchtower is allowed to skip a block on the first answer and is NEVER
// allowed to act on the second. Measured on mainnet, 82% of blocks are skipped
// outright and every positive in the sample was false — so treating a positive
// as an event would have manufactured events out of an idle contract.
//
// WHY THE BLOOM MAY BE TRUSTED AT ALL
// -----------------------------------
// Only because it is authenticated. ExecutionPayloadHeader carries LogsBloom and
// merkleises it into the payload root alongside StateRoot and ReceiptsRoot, so
// the same SSZ branch that authenticates the state authenticates this. A bloom
// taken from an RPC response would be worthless here: a provider could clear the
// bits and the watchtower would skip the very block it needed to see. Hence
// MayContain takes a Bloom2048 obtained from an authenticated payload, and there
// is no constructor that takes one from JSON.

// Bloom2048 is Ethereum's 2048-bit log filter.
type Bloom2048 = [256]byte

// bloomPositions returns the three bit positions an item sets.
//
// The low eleven bits of each of the first three 16-bit big-endian pairs of
// keccak(item), indexed from the END of the array — Ethereum numbers these bits
// from the low end, and getting the direction wrong yields a filter that is
// self-consistent and disagrees with every block.
func bloomPositions(item []byte) [3]uint {
	h := Keccak256(item)
	var out [3]uint
	for i := 0; i < 3; i++ {
		out[i] = (uint(h[2*i])<<8 | uint(h[2*i+1])) & 0x7FF
	}
	return out
}

// MayContain reports whether an item might be in the bloom.
//
// FALSE is a proof of absence. TRUE is not a proof of anything, and callers must
// treat it only as permission to go and look.
func MayContain(bloom Bloom2048, item []byte) bool {
	for _, bit := range bloomPositions(item) {
		if bloom[255-bit/8]&(1<<(bit%8)) == 0 {
			return false
		}
	}
	return true
}

// AddToBloom sets an item's bits. Used to derive a bloom from logs so that a
// rebuilt one can be checked against the authenticated one.
func AddToBloom(bloom *Bloom2048, item []byte) {
	for _, bit := range bloomPositions(item) {
		bloom[255-bit/8] |= 1 << (bit % 8)
	}
}

// BloomFromLogs derives the bloom a set of logs produces: every address and
// every topic.
func BloomFromLogs(logs []Log) Bloom2048 {
	var out Bloom2048
	for _, l := range logs {
		addr := l.Address
		AddToBloom(&out, addr[:])
		for i := range l.Topics {
			AddToBloom(&out, l.Topics[i][:])
		}
	}
	return out
}

// BloomBitsSet counts set bits, for reporting saturation. A filter at 57% is
// the mainnet norm and puts the three-hash false-positive rate near 19%.
func BloomBitsSet(bloom Bloom2048) int {
	n := 0
	for _, b := range bloom {
		for i := 0; i < 8; i++ {
			n += int(b>>i) & 1
		}
	}
	return n
}
