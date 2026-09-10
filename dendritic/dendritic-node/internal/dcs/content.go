package dcs

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/nacl/box"
)

// The coordinator's content blob format (backend/services/content_keys.py):
//
//	"SCE1" | oid_len(2) | oid | R(33) | wrap_nonce(12) | wrappedK_len(2) | wrappedK
//	       | content_nonce(12) | AES-256-GCM(content_key, plaintext, aad=oid)
//
// The worker never derives keys; it is handed the content_key (sealed) and only
// needs the object id (for the GCM AAD), the content nonce and the ciphertext.
var contentMagic = []byte("SCE1")

var errShortContentBlob = errors.New("dcs: truncated content blob")

// SealContentKey seals a raw content key to a worker's base64 Curve25519 content
// key (libsodium crypto_box_seal, which PyNaCl's SealedBox produced and Go's
// box.OpenAnonymous opens). The bridge calls this so the raw key never reaches
// the worker -- only the sealed form the worker alone can open.
func SealContentKey(contentKey []byte, workerContentPubKeyB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(workerContentPubKeyB64)
	if err != nil || len(raw) != 32 {
		return "", errors.New("dcs: worker has no valid content key")
	}
	var pub [32]byte
	copy(pub[:], raw)
	sealed, err := box.SealAnonymous(nil, contentKey, &pub, rand.Reader)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// DecryptContent parses a coordinator content blob and AES-256-GCM-decrypts its
// payload with the granted content key, returning the plaintext (the packed
// build context). Content-addressing upstream already guarantees the bytes are
// the ones the deployer asked for; this recovers them.
func DecryptContent(blob, contentKey []byte) ([]byte, error) {
	if len(blob) < 4 || string(blob[:4]) != string(contentMagic) {
		return nil, errors.New("dcs: not a content blob")
	}
	pos := 4
	remaining := func(n int) bool { return pos+n <= len(blob) }

	if !remaining(2) {
		return nil, errShortContentBlob
	}
	oidLen := int(binary.BigEndian.Uint16(blob[pos:]))
	pos += 2
	if !remaining(oidLen) {
		return nil, errShortContentBlob
	}
	oid := blob[pos : pos+oidLen]
	pos += oidLen

	// Skip the ECIES header the worker does not need: R(33) + wrap_nonce(12) +
	// wrappedK_len(2) + wrappedK.
	if !remaining(33 + 12 + 2) {
		return nil, errShortContentBlob
	}
	pos += 33 + 12
	wrappedLen := int(binary.BigEndian.Uint16(blob[pos:]))
	pos += 2
	if !remaining(wrappedLen + 12) {
		return nil, errShortContentBlob
	}
	pos += wrappedLen
	nonce := blob[pos : pos+12]
	pos += 12
	ciphertext := blob[pos:]

	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, oid)
}
