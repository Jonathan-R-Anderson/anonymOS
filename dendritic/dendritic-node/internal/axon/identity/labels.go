// Package identity implements the eight cryptographic identity classes and the
// derivations that relate them.
//
// The governing rule, from the roadmap's Constitution section 3: no two classes
// are ever the same key, and every relationship between them is either a
// one-way hash or an explicit signed delegation. TestNoTwoClassesCollide is the
// executable form of that rule.
package identity

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"io"

	"golang.org/x/crypto/hkdf"
)

// HKDF labels, from section 5.3 Table 1. Every label carries a mandatory -vN
// suffix and is never reused across layers; adding a field to a context without
// bumping the version is a protocol break, so these strings are frozen and a
// change to one must fail its golden vector.
const (
	LabelNodeSeed        = "AXON-node-seed-v1"
	LabelRoutingEd       = "AXON-routing-ed-v1"
	LabelRoutingX        = "AXON-routing-x-v1"
	LabelDescriptorBlind = "AXON-descriptor-blind-v1"
	LabelDescOuter       = "AXON-desc-outer-v1"
	LabelDescInner       = "AXON-desc-inner-v1"
	LabelKeyfile         = "AXON-keyfile-v1"
)

// SHA-256 / signature domain-separation prefixes, from section 5.3 Table 2.
// These are NOT HKDF: the label is prefixed to the hashed or signed bytes with
// a 0x00 separator.
const (
	LabelKadID            = "AXON-kadid-v1"
	LabelHSDirIndex       = "AXON-hsdir-index-v1"
	LabelCredential       = "AXON-credential-v1"
	LabelSubcredential    = "AXON-subcredential-v1"
	LabelAddressChecksum  = "AXON-address-checksum-v1"
	LabelRotationOld      = "AXON-rotation-old-v1"
	LabelRotationNew      = "AXON-rotation-new-v1"
	LabelRevocation       = "AXON-revocation-v1"
	LabelDelegationIssuer = "AXON-delegation-issuer-v1"
	LabelDelegationSubj   = "AXON-delegation-subject-v1"
	LabelBlindNonce       = "AXON-descriptor-blind-nonce-v1"
)

// AllHKDFLabels and AllPrefixLabels exist so the golden-vector test can assert
// it covers every label rather than only the ones someone remembered.
var AllHKDFLabels = []string{
	LabelNodeSeed, LabelRoutingEd, LabelRoutingX, LabelDescriptorBlind,
	LabelDescOuter, LabelDescInner, LabelKeyfile,
}

var AllPrefixLabels = []string{
	LabelKadID, LabelHSDirIndex, LabelCredential, LabelSubcredential,
	LabelAddressChecksum, LabelRotationOld, LabelRotationNew, LabelRevocation,
	LabelDelegationIssuer, LabelDelegationSubj, LabelBlindNonce,
}

// zeroSalt is the 32 zero bytes section 5.3 specifies as the default HKDF salt.
var zeroSalt = make([]byte, 32)

// derive is the single HKDF-SHA256 entry point. Every key derivation in this
// package goes through it, so the info construction -- label ‖ 0x00 ‖ context --
// is written once and cannot drift between call sites.
func derive(label string, ikm, context []byte, length int) []byte {
	info := make([]byte, 0, len(label)+1+len(context))
	info = append(info, label...)
	info = append(info, 0x00)
	info = append(info, context...)

	out := make([]byte, length)
	r := hkdf.New(sha256.New, ikm, zeroSalt, info)
	if _, err := io.ReadFull(r, out); err != nil {
		// HKDF-SHA256 only fails when length exceeds 255*32 bytes, which is a
		// caller bug rather than a runtime condition.
		panic("identity: hkdf read: " + err.Error())
	}
	return out
}

// hashPrefixed applies a Table 2 domain separator: label ‖ 0x00 ‖ body.
func hashPrefixed(h hash.Hash, label string, parts ...[]byte) []byte {
	h.Write([]byte(label))
	h.Write([]byte{0x00})
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// sha256Prefixed is the common case of hashPrefixed.
func sha256Prefixed(label string, parts ...[]byte) [32]byte {
	var out [32]byte
	copy(out[:], hashPrefixed(sha256.New(), label, parts...))
	return out
}

// sha512Prefixed is used by the blinding nonce derivation.
func sha512Prefixed(label string, parts ...[]byte) [64]byte {
	var out [64]byte
	copy(out[:], hashPrefixed(sha512.New(), label, parts...))
	return out
}

// u64be encodes a context integer. The blinding KDF hashes these, so the
// encoding is part of the protocol and is written once here.
func u64be(v uint64) []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	return b[:]
}
