package dht

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

// Descriptor replica positions (T7.5, §7.4, §5).
//
// A service descriptor is published at DescriptorReplicaPositions INDEPENDENT
// keyspace points, each of which then has its own r=8 holder set. A client
// fetches ONE position, chosen at random; the publisher writes all of them.
//
// §7 AND §5 DISAGREE ABOUT HOW MANY, AND §5 WINS. §7.4 gives
//
//	hsdir_index(j) = SHA256("axon:hsdir-index:v1" ‖ K_blind ‖ u8(j)
//	                        ‖ LE64(period_num) ‖ SRV)   for j ∈ {0,1}
//
// which is Tor's two-replica scheme, and describes the result as "two replica
// indices, each written to the DHT's r=8 closest holders → 16 holders". But §5
// declares DescriptorReplicaPositions = 8 and explains what it buys: "with
// replica_index in the pre-image the 8 replicas sit at 8 unrelated keyspace
// points, so eclipsing a descriptor means eclipsing eight unrelated regions."
// T7.5 states the test in §5's terms -- "publication reaches all 8 replica
// positions and a client fetching any 1 of 8 succeeds" -- so the criterion this
// code is written against is 8, and §7's `j ∈ {0,1}` is the superseded figure.
//
// The costs differ and are worth stating rather than discovering: 8 positions is
// 8 publish lookups per period instead of 2, and at §7's 8 KiB descriptor
// republished hourly that is 64 holders per period rather than 16. Fetch cost is
// unchanged at one lookup, because the client picks a single index.

// ErrBadReplicaIndex is returned for j outside the declared range.
var ErrBadReplicaIndex = errors.New("axon/dht: replica index is outside 0..DescriptorReplicaPositions-1")

// ErrNoBlindedKey is returned when the blinded service key is missing.
var ErrNoBlindedKey = errors.New("axon/dht: hsdir index needs the blinded service key")

// HSDirIndex is §7.4's hsdir_index(j), widened to §5's eight positions.
//
// The pre-image is built by hand, in the order the specification writes it, for
// the reason every signed or hashed encoding in this tree is: a hash over
// "whatever the encoder produced" is a hash over an encoder version, and a
// publisher and a client that disagree about it disagree silently -- here that
// means a descriptor published where nobody looks.
//
// PERIOD AND SRV ARE BOTH IN THE PRE-IMAGE, which is what makes the position
// move every period. Without the period a descriptor would sit at the same
// eight points forever, and the holders for a given service would be a stable,
// enumerable set -- exactly the standing eclipse target the rotation exists to
// deny. SRV binds it to the consensus randomness so the mapping cannot be
// predicted far ahead and pre-positioned against.
func HSDirIndex(kBlind []byte, j uint8, periodNum uint64, srv []byte) (Key, error) {
	if len(kBlind) == 0 {
		return Key{}, ErrNoBlindedKey
	}
	if int(j) >= DescriptorReplicaPositions {
		return Key{}, ErrBadReplicaIndex
	}
	h := sha256.New()
	h.Write([]byte("axon:hsdir-index:v1"))
	h.Write(kBlind)
	h.Write([]byte{j})
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], periodNum)
	h.Write(b[:])
	h.Write(srv)
	var k Key
	copy(k[:], h.Sum(nil))
	return k, nil
}

// HSDirPositions is every position a publisher must write for one period.
//
// Returned as a slice rather than left to the caller to loop, because "publish
// to all of them" is the property T7.5 tests and a caller that looped to the
// wrong bound would satisfy no test until a client failed to find a descriptor.
func HSDirPositions(kBlind []byte, periodNum uint64, srv []byte) ([]Key, error) {
	out := make([]Key, 0, DescriptorReplicaPositions)
	for j := 0; j < DescriptorReplicaPositions; j++ {
		k, err := HSDirIndex(kBlind, uint8(j), periodNum, srv)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}
