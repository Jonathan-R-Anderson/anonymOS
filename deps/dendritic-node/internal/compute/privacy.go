package compute

// M9 — privacy: what a volunteer can learn about the work they run.
//
// THE THING THIS CANNOT DO, STATED FIRST
// --------------------------------------
// A CPU computes on plaintext. There is no arrangement of keys that lets a
// volunteer's processor add two numbers it cannot see. So "encrypted work
// units" must not be read as "the volunteer cannot see the data" — during
// execution, plaintext exists in the guest's memory, and anyone with sufficient
// access to that memory can read it.
//
// What encryption here actually buys:
//
//   - at rest in the DHT: storage nodes hold ciphertext. A node that stores a
//     shard learns nothing from it, which matters because storage is replicated
//     to strangers who never run the job.
//   - in transit: already true over I2P, and true again independently, so a
//     transport compromise is not a data compromise.
//   - after the job: the guest is destroyed (M2 layer 11) and the plaintext
//     dies with it. Nothing is left on disk for the next job or the operator.
//
// The part that closes the remaining gap is NOT cryptography, it is M2. The
// plaintext lives inside a microVM the host cannot read into — hardware
// virtualisation, not policy. Encryption protects the data everywhere except
// the one place it must be readable; isolation protects it there.
//
// So the honest claim is: *the volunteer's node process handles only
// ciphertext, and the plaintext exists only inside a VM that the volunteer's
// own operating system cannot read.* Making a stronger claim than that would
// require homomorphic encryption or a trusted enclave, both of which are out of
// scope and neither of which is free.
//
// WHY PADDING IS HERE AND NOT AN OPTIONAL EXTRA
// ---------------------------------------------
// Encrypted payloads leak their length, and length is often the whole secret.
// A 400-byte job and a 40 MB job are visibly different work; a recurring job
// whose size steps up each week describes a growing dataset. Since every unit
// is content-addressed and its size is visible to every storage node holding a
// shard, unpadded ciphertext publishes a usable fingerprint of what somebody is
// computing on. Padding is applied to the PLAINTEXT before sealing, so the
// ciphertext length reveals only which bucket it fell in.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// KeySize is 32 bytes — AES-256. Chosen over AES-128 not because 128 is
// breakable but because the key is generated per unit and never reused, so the
// larger key costs nothing anyone will notice.
const KeySize = 32

// lengthPrefix is how many bytes record the true plaintext length inside the
// padded buffer. Eight, so a unit larger than 4 GiB is representable — the
// scheduler will refuse it long before this does, but a format that cannot
// express a size is a format that has to change later.
const lengthPrefix = 8

var (
	ErrKeySize    = errors.New("compute: key must be 32 bytes")
	ErrCiphertext = errors.New("compute: ciphertext is corrupt or was not sealed with this key")
	ErrPadding    = errors.New("compute: padded buffer is malformed")
	ErrTooLarge   = errors.New("compute: payload exceeds the largest bucket")
)

// MaxPayload is the largest plaintext this will pad. Beyond it, a caller should
// be splitting the work into units rather than encrypting one enormous blob —
// and a hard ceiling here is what forces that conversation instead of silently
// producing a 2 GiB allocation on a volunteer's laptop.
const MaxPayload = 1 << 30 // 1 GiB

// NewKey generates a per-unit key.
//
// Per UNIT, not per node or per submitter. A key that covers many units means
// one leaked key exposes all of them, and units are already independently
// addressed, so there is nothing to gain from sharing.
func NewKey() ([KeySize]byte, error) {
	var key [KeySize]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("compute: generating key: %w", err)
	}
	return key, nil
}

// buckets are the padded plaintext sizes, in bytes.
//
// Powers of four rather than powers of two: two doubles the worst-case waste
// but halves the number of distinguishable classes, and the point of the
// exercise is to have FEW classes. A scheme with a hundred buckets identifies
// a payload almost as precisely as its exact length does.
//
// The smallest bucket is 4 KiB because below that the fixed costs dominate
// anyway, and a 12-byte job padded to 12 bytes is a very loud 12-byte job.
var buckets = []int{
	4 << 10,   // 4 KiB
	16 << 10,  // 16 KiB
	64 << 10,  // 64 KiB
	256 << 10, // 256 KiB
	1 << 20,   // 1 MiB
	4 << 20,   // 4 MiB
	16 << 20,  // 16 MiB
	64 << 20,  // 64 MiB
	256 << 20, // 256 MiB
	1 << 30,   // 1 GiB
}

// BucketFor returns the padded size a payload of n bytes will occupy.
func BucketFor(n int) (int, error) {
	if n < 0 {
		return 0, ErrPadding
	}
	need := n + lengthPrefix
	for _, b := range buckets {
		if need <= b {
			return b, nil
		}
	}
	return 0, ErrTooLarge
}

// Pad expands a payload to its bucket size.
//
// The true length is recorded in the first eight bytes so Unpad is exact.
// Trailing bytes are zero rather than random: they are encrypted before anyone
// sees them, so their content carries no information, and zeros make a
// malformed buffer obvious in a hex dump instead of looking like data.
func Pad(payload []byte) ([]byte, error) {
	size, err := BucketFor(len(payload))
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	binary.BigEndian.PutUint64(out[:lengthPrefix], uint64(len(payload)))
	copy(out[lengthPrefix:], payload)
	return out, nil
}

// Unpad recovers the original payload.
//
// Validates the recorded length against the buffer before slicing. A corrupt
// or hostile length would otherwise panic on a slice bound, and this runs on
// data that arrived over the network from someone untrusted.
func Unpad(padded []byte) ([]byte, error) {
	if len(padded) < lengthPrefix {
		return nil, ErrPadding
	}
	n := binary.BigEndian.Uint64(padded[:lengthPrefix])
	if n > uint64(len(padded)-lengthPrefix) {
		return nil, ErrPadding
	}
	out := make([]byte, n)
	copy(out, padded[lengthPrefix:lengthPrefix+int(n)])
	return out, nil
}

// Seal pads and encrypts a payload.
//
// AES-256-GCM: authenticated, so a storage node that flips a byte is detected
// rather than producing garbage the guest then computes on. The nonce is
// random per call and prepended — never derived from the unit id, because two
// units with the same id and key would then share a nonce, which is the one
// mistake GCM does not survive.
func Seal(key [KeySize]byte, payload []byte) ([]byte, error) {
	padded, err := Pad(payload)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("compute: nonce: %w", err)
	}
	// Sealed in place after the nonce, so the result is nonce‖ciphertext‖tag.
	return gcm.Seal(nonce, nonce, padded, nil), nil
}

// Open decrypts and unpads.
//
// A failure here is authentication failing, which means the ciphertext was
// altered or the key is wrong. Those are deliberately not distinguished: the
// error message a caller can act on is the same, and reporting which one it was
// tells an attacker whether a guessed key was closer.
func Open(key [KeySize]byte, sealed []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, ErrCiphertext
	}
	nonce, body := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	padded, err := gcm.Open(nil, nonce, body, nil)
	if err != nil {
		return nil, ErrCiphertext
	}
	return Unpad(padded)
}

func newGCM(key [KeySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, ErrKeySize
	}
	return cipher.NewGCM(block)
}
