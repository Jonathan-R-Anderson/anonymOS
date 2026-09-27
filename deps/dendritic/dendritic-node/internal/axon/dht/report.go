package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// G4 — the decentralised report protocol (§89).
//
// A REPORT IS A PUBLICATION, NOT A SUBMISSION. It is a DHT record like every
// other class here, not a POST to a moderation server. §89 is explicit about
// why: a private report is a denunciation nobody can audit, and §90 cannot score
// the accuracy of a claim it cannot see. Reporter reputation is the whole
// mechanism that stops 10 000 fresh identities dominating the system, and it is
// only possible if reports are public and attributed.
//
// THE PRIVACY COST, STATED. A report identifies its reporter to everyone. That
// is deliberate and it means REPORTING IS NOT AN ANONYMOUS ACT. A user in a
// jurisdiction where reporting certain content is itself dangerous should not
// use this until §96's anonymous credentials exist, and they do not.
//
// R-89.1: EVIDENCE IS CONTENT-ADDRESSED AND STORED, NEVER LINKED. `Evidence` is
// a list of CIDs in the network's own store (§10). A report whose evidence lived
// at an external URL is a report whose evidence can be withdrawn after the vote,
// leaving a governance record that says a thing happened with nothing behind it.
//
// The key is derived from the SUBJECT and the REPORTER, so:
//   - every report about one name lands in the same neighbourhood, which is what
//     makes them findable and countable without a server;
//   - one reporter cannot occupy the whole neighbourhood by filing the same
//     report repeatedly, because their own identity is in the key and a repeat
//     is the SAME key rather than a new one.

const (
	// MaxReportReason bounds the free-text field. §89 calls it "bounded free
	// text" and this is the bound: long enough for a sentence explaining what
	// was seen, short enough that the record is not a payload channel.
	MaxReportReason = 512
	// MaxReportEvidence caps the CID list. Evidence lives in the store; this is
	// only a list of pointers, and a report needing more than eight is a report
	// that should be several.
	MaxReportEvidence = 8
)

// ContentReport is class `report`, keyed on subject ‖ reporter.
type ContentReport struct {
	Ver uint8 `cbor:"1,keyasint"`
	// NameHash is §85's subject: what this accumulates against.
	NameHash []byte `cbor:"2,keyasint"`
	// ManifestCID is the VERSION observed (R-85.1). Evidence about content that
	// cannot name the content is not evidence.
	ManifestCID []byte `cbor:"3,keyasint"`
	// Category is §86's vocabulary, as its numeric value.
	Category uint8 `cbor:"4,keyasint"`
	// Reason is bounded free text.
	Reason string `cbor:"5,keyasint"`
	// Evidence is a list of CIDs in the DCS. NEVER a URL (R-89.1).
	Evidence [][]byte `cbor:"6,keyasint"`
	// Reporter is the Ed25519 public key of whoever filed it.
	Reporter []byte `cbor:"7,keyasint"`
	// StakeRef points at the reporter's bond (§15). Reports from an unbonded
	// identity are cheap, and §90 weighs them accordingly.
	StakeRef []byte `cbor:"8,keyasint"`
	// Sequence lets a reporter correct their own report without filing a
	// second one at a second key.
	Sequence  uint64 `cbor:"9,keyasint"`
	IssuedAt  int64  `cbor:"10,keyasint"`
	ExpiresAt int64  `cbor:"11,keyasint"`
	Sig       []byte `cbor:"12,keyasint"`
}

var (
	ErrReportNoSubject  = errors.New("axon/dht: report names no subject")
	ErrReportNoVersion  = errors.New("axon/dht: report names no version")
	ErrReportNoReporter = errors.New("axon/dht: report has no reporter")
	ErrReportReasonLong = errors.New("axon/dht: report reason exceeds the bound")
	ErrReportEvidence   = errors.New("axon/dht: report evidence is not a list of CIDs")
	ErrReportURL        = errors.New("axon/dht: report evidence looks like a URL; evidence must be content-addressed and stored (R-89.1)")
	ErrReportSig        = errors.New("axon/dht: report signature does not verify")
)

// Class implements Record.
func (r *ContentReport) Class() RecordClass { return ClassReport }

// Seq implements Record.
func (r *ContentReport) Seq() uint64 { return r.Sequence }

// Expiry implements Record.
func (r *ContentReport) Expiry() time.Time { return time.Unix(r.ExpiresAt, 0) }

// DerivedKey recomputes the key from the record's own fields.
//
// SUBJECT ‖ REPORTER, in that order. Subject first so every report about one
// name shares a prefix in the pre-image and the neighbourhood is about the
// SUBJECT; reporter second so one identity filing repeatedly rewrites its own
// record instead of filling the neighbourhood with copies.
func (r *ContentReport) DerivedKey() (Key, error) {
	if len(r.NameHash) == 0 {
		return Key{}, ErrReportNoSubject
	}
	if len(r.Reporter) == 0 {
		return Key{}, ErrReportNoReporter
	}
	in := make([]byte, 0, len(r.NameHash)+len(r.Reporter))
	in = append(in, r.NameHash...)
	in = append(in, r.Reporter...)
	return DeriveKey(ClassReport, in)
}

// reportSigningBytes is the canonical pre-image the reporter signs.
//
// Built by hand for the same reason every other signed encoding here is: a
// signature over "whatever the encoder produced" is a signature over an encoder
// version. Evidence is included ORDER-SENSITIVELY, so a report cannot have its
// evidence list reordered or trimmed with the signature intact.
func (r *ContentReport) reportSigningBytes() []byte {
	h := sha256.New()
	h.Write([]byte("axon-content-report-v1"))
	h.Write([]byte{r.Ver, r.Category})
	h.Write(r.NameHash)
	h.Write(r.ManifestCID)
	h.Write([]byte(r.Reason))
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(r.Evidence)))
	h.Write(n[:])
	for _, e := range r.Evidence {
		binary.BigEndian.PutUint64(n[:], uint64(len(e)))
		h.Write(n[:])
		h.Write(e)
	}
	h.Write(r.Reporter)
	h.Write(r.StakeRef)
	binary.BigEndian.PutUint64(n[:], r.Sequence)
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.IssuedAt))
	h.Write(n[:])
	binary.BigEndian.PutUint64(n[:], uint64(r.ExpiresAt))
	h.Write(n[:])
	return h.Sum(nil)
}

// SignReport fills in the reporter and signature. The only way to make one that
// ValidateReport accepts.
func SignReport(r *ContentReport, priv ed25519.PrivateKey) error {
	r.Reporter = append([]byte(nil), priv.Public().(ed25519.PublicKey)...)
	if err := r.checkShape(); err != nil {
		return err
	}
	r.Sig = ed25519.Sign(priv, r.reportSigningBytes())
	return nil
}

// looksLikeURL is R-89.1's refusal, applied to every evidence entry.
//
// A CID is 32 opaque bytes. Anything printable that starts with a scheme is
// somebody putting a link where a content address belongs, and the whole point
// is that evidence cannot be withdrawn after the vote.
func looksLikeURL(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	for _, prefix := range []string{"http:", "https", "ipfs:", "ftp:/", "//"} {
		if len(b) >= len(prefix) && string(b[:len(prefix)]) == prefix {
			return true
		}
	}
	return false
}

func (r *ContentReport) checkShape() error {
	if len(r.NameHash) != 32 {
		return ErrReportNoSubject
	}
	if len(r.ManifestCID) != 32 {
		return ErrReportNoVersion
	}
	if len(r.Reporter) != ed25519.PublicKeySize {
		return ErrReportNoReporter
	}
	if len(r.Reason) > MaxReportReason {
		return fmt.Errorf("%w: %d > %d", ErrReportReasonLong, len(r.Reason), MaxReportReason)
	}
	if len(r.Evidence) > MaxReportEvidence {
		return fmt.Errorf("%w: %d entries", ErrTooManyEntries, len(r.Evidence))
	}
	for i, e := range r.Evidence {
		if looksLikeURL(e) {
			return fmt.Errorf("%w: entry %d", ErrReportURL, i)
		}
		if len(e) != 32 {
			return fmt.Errorf("%w: entry %d is %d bytes, want a 32-byte CID",
				ErrReportEvidence, i, len(e))
		}
	}
	return nil
}

// ValidateReport is the class validator: shape, then signature.
//
// A report is NOT rejected for naming an unregistered name or an unknown
// category value. §90 weighs reports and §93 votes on them; a validator that
// silently dropped reports it disagreed with would be doing moderation at the
// storage layer, where nobody can see it.
func ValidateReport(r *ContentReport) error {
	if err := r.checkShape(); err != nil {
		return err
	}
	if len(r.Sig) == 0 {
		return ErrReportSig
	}
	if !ed25519.Verify(ed25519.PublicKey(r.Reporter), r.reportSigningBytes(), r.Sig) {
		return ErrReportSig
	}
	return nil
}
