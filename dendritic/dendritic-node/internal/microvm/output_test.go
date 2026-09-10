//go:build linux

package microvm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func image(t *testing.T, size int64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "out.img")
	if err := CreateOutputImage(p, size); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRoundTrip(t *testing.T) {
	p := image(t, 1<<20)
	payload := []byte("the answer, computed elsewhere")
	if err := WriteResult(p, payload); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResult(p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("got %q", got)
	}
}

// An untouched drive must report "no result", distinct from an empty one — the
// job producing nothing and the job writing nothing are different failures.
func TestUntouchedImageReportsNoResult(t *testing.T) {
	if _, err := ReadResult(image(t, 1<<20)); !errors.Is(err, ErrNoResult) {
		t.Fatalf("got %v, want ErrNoResult", err)
	}
}

func TestEmptyResultIsNotNoResult(t *testing.T) {
	p := image(t, 1<<20)
	if err := WriteResult(p, []byte{}); err != nil {
		t.Fatal(err)
	}
	got, err := ReadResult(p)
	if err != nil {
		t.Fatalf("an empty result was rejected: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d bytes", len(got))
	}
}

// THE hostile case: a guest declaring an enormous length must not make the host
// allocate. That would be the guest escaping its memory limit through the one
// channel it is allowed.
func TestHostileLengthDoesNotAllocate(t *testing.T) {
	p := image(t, 4096)
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	header := make([]byte, outputHeaderSize)
	copy(header, outputMagic[:])
	binary.BigEndian.PutUint64(header[8:16], 1<<62) // absurd
	f.WriteAt(header, 0)
	f.Close()

	if _, err := ReadResult(p); !errors.Is(err, ErrResultTooBig) {
		t.Fatalf("got %v, want ErrResultTooBig", err)
	}
}

// A length within the cap but beyond the image must also be refused.
func TestLengthBeyondTheImageIsRefused(t *testing.T) {
	p := image(t, 4096)
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	header := make([]byte, outputHeaderSize)
	copy(header, outputMagic[:])
	binary.BigEndian.PutUint64(header[8:16], 1<<20) // < cap, > image
	f.WriteAt(header, 0)
	f.Close()

	if _, err := ReadResult(p); !errors.Is(err, ErrResultCorrupt) {
		t.Fatalf("got %v, want ErrResultCorrupt", err)
	}
}

// A job killed mid-write leaves a plausible prefix. Without the checksum a
// truncated result reads as a complete one, and a verifier comparing replicas
// sees a disagreement it cannot explain.
func TestTruncatedResultIsDetected(t *testing.T) {
	p := image(t, 1<<20)
	payload := bytes.Repeat([]byte("x"), 4096)
	if err := WriteResult(p, payload); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	f.WriteAt([]byte("corrupted"), outputHeaderSize+100)
	f.Close()

	if _, err := ReadResult(p); !errors.Is(err, ErrResultCorrupt) {
		t.Fatalf("a corrupted result was returned as valid: %v", err)
	}
}

// The header is written last, so a reader arriving mid-write sees no magic
// rather than a half-written result.
func TestHeaderIsWrittenAfterThePayload(t *testing.T) {
	p := image(t, 1<<20)
	f, _ := os.OpenFile(p, os.O_WRONLY, 0)
	f.WriteAt(bytes.Repeat([]byte("z"), 500), outputHeaderSize) // payload only
	f.Close()
	if _, err := ReadResult(p); !errors.Is(err, ErrNoResult) {
		t.Fatal("a payload with no header was read as a result")
	}
}

func TestOversizedWriteIsRefused(t *testing.T) {
	p := image(t, 4096)
	if err := WriteResult(p, make([]byte, MaxResultBytes+1)); !errors.Is(err, ErrResultTooBig) {
		t.Fatalf("got %v", err)
	}
}

func TestTinyImageIsRefused(t *testing.T) {
	if err := CreateOutputImage(filepath.Join(t.TempDir(), "x.img"), 8); err == nil {
		t.Fatal("created an image too small to hold a header")
	}
}
