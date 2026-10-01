package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
)

// A libp2p peer ID for an Ed25519 key is the base58 of an identity multihash (code 0x00) whose
// digest is the protobuf-encoded public key: field 1 (type) = 1 (Ed25519), field 2 = 32 key bytes.
// The heartbeat is signed with that key, so the ID itself is the verifying key.

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func base58Decode(s string) ([]byte, error) {
	n := new(big.Int)
	for _, c := range s {
		i := strings.IndexRune(base58Alphabet, c)
		if i < 0 {
			return nil, errors.New("invalid base58")
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(int64(i)))
	}
	out := n.Bytes()
	lead := len(s) - len(strings.TrimLeft(s, "1"))
	return append(make([]byte, lead), out...), nil
}

func readUvarint(b []byte, off int) (uint64, int, error) {
	var x uint64
	var shift uint
	for i := off; i < len(b) && i < off+10; i++ {
		x |= uint64(b[i]&0x7f) << shift
		if b[i]&0x80 == 0 {
			return x, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, errors.New("invalid varint")
}

// peerPublicKey returns the Ed25519 key embedded in a libp2p peer ID.
func peerPublicKey(peerID string) (ed25519.PublicKey, error) {
	b, err := base58Decode(peerID)
	if err != nil {
		return nil, err
	}
	code, off, err := readUvarint(b, 0)
	if err != nil {
		return nil, err
	}
	length, off, err := readUvarint(b, off)
	if err != nil {
		return nil, err
	}
	if code != 0 || int(length) != len(b)-off {
		return nil, errors.New("peer ID does not embed an identity public key")
	}
	msg := b[off:]
	if len(msg) != 36 || msg[0] != 0x08 || msg[1] != 0x01 || msg[2] != 0x12 || msg[3] != 0x20 {
		return nil, errors.New("peer ID is not an embedded Ed25519 identity")
	}
	return ed25519.PublicKey(msg[4:]), nil
}

// decodeB64 accepts standard base64 with or without padding (the node sends it unpadded).
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	return base64.RawStdEncoding.DecodeString(s)
}
