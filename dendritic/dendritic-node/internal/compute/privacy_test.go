package compute

import (
	"bytes"
	"testing"
)

func testKey(t *testing.T) [KeySize]byte {
	t.Helper()
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestSealOpenRoundTrip(t *testing.T) {
	key := testKey(t)
	for _, payload := range [][]byte{
		nil,
		[]byte(""),
		[]byte("one"),
		bytes.Repeat([]byte("x"), 4<<10), // exactly at a bucket edge
		bytes.Repeat([]byte("y"), 100<<10),
	} {
		sealed, err := Seal(key, payload)
		if err != nil {
			t.Fatalf("seal %d bytes: %v", len(payload), err)
		}
		got, err := Open(key, sealed)
		if err != nil {
			t.Fatalf("open %d bytes: %v", len(payload), err)
		}
		if !bytes.Equal(got, payload) && !(len(got) == 0 && len(payload) == 0) {
			t.Errorf("round trip changed %d bytes", len(payload))
		}
	}
}

// The point of padding: two payloads of very different size must be
// indistinguishable by ciphertext length when they share a bucket. Without this
// every storage node holding a shard can size the job it is storing.
func TestCiphertextLengthRevealsOnlyTheBucket(t *testing.T) {
	key := testKey(t)
	small, err := Seal(key, []byte("a"))
	if err != nil {
		t.Fatal(err)
	}
	// 3 KiB and 1 byte both fit the 4 KiB bucket.
	larger, err := Seal(key, bytes.Repeat([]byte("b"), 3<<10))
	if err != nil {
		t.Fatal(err)
	}
	if len(small) != len(larger) {
		t.Errorf("1 byte sealed to %d, 3 KiB sealed to %d — length leaks the payload size",
			len(small), len(larger))
	}
}

func TestBucketsAreCoarse(t *testing.T) {
	// A scheme with many buckets identifies a payload nearly as precisely as
	// its exact length. Assert the classes stay few and widely spaced.
	if len(buckets) > 12 {
		t.Errorf("%d buckets is too many to hide anything", len(buckets))
	}
	for i := 1; i < len(buckets); i++ {
		if buckets[i] <= buckets[i-1] {
			t.Fatalf("buckets are not increasing at %d", i)
		}
		if ratio := buckets[i] / buckets[i-1]; ratio < 4 {
			t.Errorf("bucket %d is only %dx the previous — too fine-grained", i, ratio)
		}
	}
}

func TestWrongKeyIsRejected(t *testing.T) {
	sealed, err := Seal(testKey(t), []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(testKey(t), sealed); err == nil {
		t.Fatal("a different key opened the ciphertext")
	}
}

// Authentication is the property that matters for work units: a storage node
// that alters a byte must be DETECTED, not produce plausible garbage that a
// guest then computes on and returns as a confident wrong answer.
func TestTamperingIsDetected(t *testing.T) {
	key := testKey(t)
	sealed, err := Seal(key, bytes.Repeat([]byte("z"), 512))
	if err != nil {
		t.Fatal(err)
	}
	for _, pos := range []int{0, len(sealed) / 2, len(sealed) - 1} {
		altered := append([]byte(nil), sealed...)
		altered[pos] ^= 0x01
		if _, err := Open(key, altered); err == nil {
			t.Errorf("a flipped bit at %d went undetected", pos)
		}
	}
}

// Nonces must not repeat. Sealing identical plaintext twice with the same key
// must produce different ciphertext — a deterministic nonce is the one mistake
// GCM does not survive.
func TestSealIsNotDeterministic(t *testing.T) {
	key := testKey(t)
	payload := []byte("same input")
	a, err := Seal(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Seal(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, b) {
		t.Fatal("sealing the same payload twice produced identical ciphertext — nonce reuse")
	}
}

// Unpad runs on data that arrived from an untrusted peer. A hostile length
// field must produce an error, never a panic on a slice bound.
func TestUnpadRejectsHostileLength(t *testing.T) {
	cases := [][]byte{
		{},                    // too short for the prefix
		{0, 0, 0, 0, 0, 0, 0}, // still too short
		{255, 255, 255, 255, 255, 255, 255, 255, 1, 2}, // length far beyond the buffer
		{0, 0, 0, 0, 0, 0, 0, 9, 1, 2},                 // length 9 in a 2-byte body
	}
	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			if _, err := Unpad(in); err == nil {
				t.Errorf("case %d: accepted a malformed buffer", i)
			}
		}()
	}
}

func TestPayloadBeyondTheLargestBucketIsRefused(t *testing.T) {
	if _, err := BucketFor(MaxPayload + 1); err == nil {
		t.Fatal("accepted a payload larger than the largest bucket")
	}
	// The refusal must name the ceiling rather than failing obscurely, because
	// the right fix is to split the work into units.
	if _, err := BucketFor(MaxPayload + 1); err != ErrTooLarge {
		t.Errorf("got %v, want ErrTooLarge", err)
	}
}

func TestBucketAccountsForTheLengthPrefix(t *testing.T) {
	// A payload of exactly the bucket size does NOT fit that bucket — the
	// 8-byte length prefix has to live somewhere. Getting this wrong produces
	// a buffer overrun in Pad for exactly one input size, which is the kind of
	// bug that survives casual testing.
	size, err := BucketFor(4 << 10)
	if err != nil {
		t.Fatal(err)
	}
	if size == 4<<10 {
		t.Fatal("a 4 KiB payload was placed in the 4 KiB bucket, leaving no room for the prefix")
	}
	padded, err := Pad(bytes.Repeat([]byte("q"), 4<<10))
	if err != nil {
		t.Fatal(err)
	}
	if len(padded) != size {
		t.Errorf("padded to %d, bucket said %d", len(padded), size)
	}
}

func TestOpenRejectsTruncatedInput(t *testing.T) {
	key := testKey(t)
	sealed, _ := Seal(key, []byte("hello"))
	for _, n := range []int{0, 1, 11} {
		if _, err := Open(key, sealed[:n]); err == nil {
			t.Errorf("opened a %d-byte truncated ciphertext", n)
		}
	}
}
