package runtime

import (
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"

	"github.com/syndichan/maniwani/storage-client/internal/axon/dht"
	"github.com/syndichan/maniwani/storage-client/internal/axon/identity"
)

// A hidden service's descriptor, as this runtime writes it.
//
// The outer record is dht.ServiceDescriptor: blinded key, period, replica
// index, revision, lifetime, and the blinded key's signature. Its holders can
// validate it and learn nothing else -- the blinded key is unlinkable to the
// service's address without the address.
//
// The Inner field, whose format the record leaves open, is this:
//
//	nonce(12) ‖ ChaCha20-Poly1305(K, nonce, AAD = blinded ‖ BE64(period),
//	        count u8 ‖ count × ( relayLen u16 ‖ RelayDescriptor ‖ authKey(32) ‖ encKey(32) ))
//	K = HKDF-SHA256(salt = blinded, ikm = subcredential, "axon:desc:inner:v1")
//
// The subcredential needs the service's public key, so only a client that knows
// the address can open it (§9.5's descriptor confidentiality). Each intro point
// carries its relay's own signed descriptor, so a client can reach it even if
// its directory has not caught up, and the auth key and X25519 encryption key
// INTRODUCE1 is sealed to.

const maxIntroPoints = 10

type introEntry struct {
	relay   *RelayInfo
	authKey [32]byte
	encKey  [32]byte
}

var errDescriptor = errors.New("axon/runtime: malformed service descriptor")

func innerAEAD(blinded []byte, subcred [32]byte) (cipher.AEAD, error) {
	var k [32]byte
	r := hkdf.New(sha256.New, subcred[:], blinded, []byte("axon:desc:inner:v1"))
	if _, err := io.ReadFull(r, k[:]); err != nil {
		return nil, err
	}
	return chacha20poly1305.New(k[:])
}

func innerAAD(blinded []byte, period uint64) []byte {
	return binary.BigEndian.AppendUint64(append([]byte(nil), blinded...), period)
}

func sealInner(blinded []byte, period uint64, subcred [32]byte, intros []introEntry) ([]byte, error) {
	aead, err := innerAEAD(blinded, subcred)
	if err != nil {
		return nil, err
	}
	pt := []byte{byte(len(intros))}
	for _, ip := range intros {
		pt = binary.BigEndian.AppendUint16(pt, uint16(len(ip.relay.wire)))
		pt = append(pt, ip.relay.wire...)
		pt = append(pt, ip.authKey[:]...)
		pt = append(pt, ip.encKey[:]...)
	}
	nonce := make([]byte, chacha20poly1305.NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, pt, innerAAD(blinded, period)), nil
}

func (d *Directory) openInner(blinded []byte, period uint64, subcred [32]byte, inner []byte) ([]introEntry, error) {
	aead, err := innerAEAD(blinded, subcred)
	if err != nil {
		return nil, err
	}
	if len(inner) < chacha20poly1305.NonceSize {
		return nil, errDescriptor
	}
	pt, err := aead.Open(nil, inner[:chacha20poly1305.NonceSize], inner[chacha20poly1305.NonceSize:], innerAAD(blinded, period))
	if err != nil {
		return nil, errDescriptor
	}
	if len(pt) < 1 {
		return nil, errDescriptor
	}
	n := int(pt[0])
	pt = pt[1:]
	if n > maxIntroPoints {
		return nil, errDescriptor
	}
	var out []introEntry
	for i := 0; i < n; i++ {
		if len(pt) < 2 {
			return nil, errDescriptor
		}
		l := int(binary.BigEndian.Uint16(pt))
		if len(pt) < 2+l+64 {
			return nil, errDescriptor
		}
		ri, err := d.Add(pt[2 : 2+l])
		if err != nil {
			return nil, err
		}
		var e introEntry
		e.relay = ri
		copy(e.authKey[:], pt[2+l:])
		copy(e.encKey[:], pt[2+l+32:])
		out = append(out, e)
		pt = pt[2+l+64:]
	}
	return out, nil
}

// descriptorKey is where replica j of a service's descriptor for a period
// lives: the dht record's own key derivation, which is what its holders
// validate against.
func descriptorKey(blinded []byte, period uint64, j uint8) (dht.Key, error) {
	d := &dht.ServiceDescriptor{BlindedPub: blinded, TimePeriod: period, ReplicaIndex: j}
	return d.DerivedKey()
}

// blindedFor is the blinded public key and subcredential for a period.
func blindedFor(pub ed25519.PublicKey, period uint64) ([]byte, [32]byte, error) {
	b, err := identity.Blind(pub, period)
	if err != nil {
		return nil, [32]byte{}, err
	}
	return []byte(b), identity.Subcredential(pub, b), nil
}

// hsdirSpread is how many relays hold each of the 8 replicas. §7 sets r = 8,
// which is 64 holders a period; this runtime uses 3 (24), Tor's scale, until
// the DHT replaces the directory and placement is checked against r = 8.
const hsdirSpread = 3

func (d *Directory) hsdirReplicas() int {
	n := len(d.Relays())
	if n < hsdirSpread {
		return n
	}
	return hsdirSpread
}

func nowUnix() int64 { return time.Now().Unix() }
