package channel

// Key helpers a running node needs — roadmap P15.
//
// These existed only in the test file until the payment stack was actually
// mounted in a binary, which is a good illustration of the gap this phase
// closed: everything worked in tests and nothing was reachable in production.
//
// The signature layout is r‖s‖v over the EIP-191 wrapping, which is what
// personal_sign returns and what ChannelManagerV2._recover expects. Getting the
// order or the wrapping wrong produces signatures that verify perfectly in Go
// and are rejected on chain.

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

// PubkeyAddress derives the Ethereum address of a public key.
func PubkeyAddress(pub *secp256k1.PublicKey) Address {
	raw := pub.SerializeUncompressed()
	var a Address
	copy(a[:], keccak(raw[1:])[12:])
	return a
}

// SignDigest signs a RAW state digest the way a wallet would.
//
// It applies EIP-191 itself rather than trusting the caller to have done it:
// the wrapping is the step most easily forgotten, and forgetting it is silent
// until a transaction reverts.
func SignDigest(key *secp256k1.PrivateKey, raw [32]byte) ([]byte, error) {
	d := PersonalDigest(raw)
	compact := ecdsa.SignCompact(key, d[:], false) // v‖r‖s
	out := make([]byte, 65)
	copy(out[0:32], compact[1:33])
	copy(out[32:64], compact[33:65])
	out[64] = compact[0]
	return out, nil
}
