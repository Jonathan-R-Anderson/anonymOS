//go:build linux

package microvm

// Getting results out of a guest.
//
// WHY NOT A FILESYSTEM
// --------------------
// The obvious design gives the guest a writable ext4 image, has it write files,
// and mounts that image on the host afterwards. Mounting needs root — or a loop
// device and CAP_SYS_ADMIN — which means the node would have to run privileged
// to collect the output of a job it deliberately confined. Confining a payload
// in a VM and then escalating the host to read its answer is a poor trade.
//
// The alternatives are worse in their own ways: `debugfs` from e2fsprogs reads
// ext4 unprivileged but is an external binary parsing an attacker-influenced
// filesystem, and a FUSE mount is another privileged component.
//
// So the output drive carries NO FILESYSTEM. It is a raw block device the guest
// writes a length-prefixed blob to, and the host reads back with an ordinary
// file read. No mount, no root, no parser, and nothing between the bytes and
// the reader that an untrusted guest can confuse.
//
// THE FORMAT, AND WHY EVERY FIELD IS CHECKED
// ------------------------------------------
//	[0:8]   magic          identifies a written result vs an untouched image
//	[8:16]  length         big-endian, bytes of payload following
//	[16:24] declared CRC   of the payload
//	[24:N]  payload
//
// A guest is untrusted, so every one of those is adversarial input. The length
// is checked against the image size before allocating (a 2^63 length would
// otherwise be an out-of-memory kill on the volunteer's machine), and the CRC
// is checked because a partially-written result is indistinguishable from a
// complete one otherwise — a job killed at its deadline mid-write leaves a
// plausible prefix.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc64"
	"os"
)

// outputMagic marks a drive a guest actually wrote to. Chosen so an all-zero or
// uninitialised image cannot be mistaken for an empty-but-valid result.
var outputMagic = [8]byte{'S', 'Y', 'N', 'D', 'O', 'U', 'T', 1}

const outputHeaderSize = 24

// MaxResultBytes caps what a job may return.
//
// A guest that writes its whole output drive is returning a result nobody asked
// for and the host must not allocate for. The cap is enforced on the DECLARED
// length before any allocation, not after reading.
const MaxResultBytes = 64 << 20 // 64 MiB

var (
	ErrNoResult      = errors.New("microvm: the guest wrote no result")
	ErrResultTooBig  = errors.New("microvm: declared result exceeds the limit")
	ErrResultCorrupt = errors.New("microvm: result failed its checksum")
)

var crcTable = crc64.MakeTable(crc64.ISO)

// CreateOutputImage makes an empty, filesystem-less output drive.
//
// Sparse: truncating to a size allocates no blocks until written, so a 64 MiB
// output drive costs nothing for a job that returns 12 bytes.
func CreateOutputImage(path string, size int64) error {
	if size <= outputHeaderSize {
		return fmt.Errorf("microvm: output image too small: %d", size)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Truncate(size)
}

// ReadResult extracts what the guest wrote.
//
// Every read is bounded by the FILE's size as well as the declared length, so a
// guest cannot make the host read past the image by lying in the header.
func ReadResult(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	header := make([]byte, outputHeaderSize)
	if _, err := f.ReadAt(header, 0); err != nil {
		// A drive too short to hold a header cannot hold a result either.
		return nil, ErrNoResult
	}
	for i := range outputMagic {
		if header[i] != outputMagic[i] {
			// Untouched image. Distinguished from an empty result so a caller
			// can tell "the job produced nothing" from "the job wrote nothing",
			// which are different failures.
			return nil, ErrNoResult
		}
	}

	length := binary.BigEndian.Uint64(header[8:16])
	declared := binary.BigEndian.Uint64(header[16:24])

	// Checked BEFORE allocating. A hostile length of 2^63 would otherwise be an
	// out-of-memory kill on the volunteer's machine — the guest escaping its
	// resource limits through the one channel it is allowed.
	if length > MaxResultBytes {
		return nil, ErrResultTooBig
	}
	if int64(length)+outputHeaderSize > info.Size() {
		return nil, ErrResultCorrupt
	}

	payload := make([]byte, length)
	if _, err := f.ReadAt(payload, outputHeaderSize); err != nil {
		return nil, ErrResultCorrupt
	}
	if crc64.Checksum(payload, crcTable) != declared {
		// A job killed mid-write leaves a plausible prefix. Without this check
		// a truncated result is returned as a complete one, and a verifier
		// comparing replicas sees a disagreement it cannot explain.
		return nil, ErrResultCorrupt
	}
	return payload, nil
}

// WriteResult produces the format a guest agent writes. Exported so the guest
// side and the host side cannot drift: they are the same code.
func WriteResult(path string, payload []byte) error {
	if len(payload) > MaxResultBytes {
		return ErrResultTooBig
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()

	header := make([]byte, outputHeaderSize)
	copy(header, outputMagic[:])
	binary.BigEndian.PutUint64(header[8:16], uint64(len(payload)))
	binary.BigEndian.PutUint64(header[16:24], crc64.Checksum(payload, crcTable))

	if _, err := f.WriteAt(payload, outputHeaderSize); err != nil {
		return err
	}
	// Header LAST. A reader that arrives mid-write sees no magic and reports
	// "no result" rather than a half-written one — the same discipline the DHT
	// uses writing its shard index after the shards.
	if _, err := f.WriteAt(header, 0); err != nil {
		return err
	}
	return f.Sync()
}
