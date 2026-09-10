// Package content is G1: the identity that reports, labels and prunes attach to.
//
// THE REQUIREMENT (§85). A domain must not escape moderation by moving to
// another host. So the thing being reported is the CONTENT, not the location —
// and §10 and §12 already supply almost all of it. An object is addressed by a
// BLAKE3 CID; a site is an ObjectManifest; a name is bound on chain. What was
// missing is the JOIN: a stable identity that survives a content update, so a
// report is not voided by publishing one new byte.
//
// THE RULING IT IMPLEMENTS (R-85.1). A report NAMES A VERSION and ACCUMULATES
// AGAINST THE NAME.
//
//	manifest_cid   what the reporter actually saw. Evidence about content that
//	               cannot name the content is not evidence.
//	name_hash      what the report counts against. Otherwise every report is
//	               voided by a republish and the system does nothing.
//
// The two are kept distinct so an APPEAL CAN POINT AT THE DIFFERENCE: "that CID
// is no longer what this name serves" is a real, checkable defence, and a design
// that tracked only the name could not express it.
//
// WHAT THIS DOES NOT SOLVE, and it is the hard case: content that is legitimate
// at publication and abusive afterwards under an UNCHANGED CID, because the
// abuse is in what the site does rather than in what it is. The identity layer
// cannot see behaviour. §91's confidence estimates are the partial answer and
// they are not a good one.
package content

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

// ServiceType is what a name serves. Coarse on purpose: a finer taxonomy would
// be a claim about content, and §86 is where claims about content live.
type ServiceType uint8

const (
	ServiceUnknown ServiceType = iota
	ServiceSite
	ServiceAPI
	ServiceStream
	ServiceStore
	ServiceOther
)

func (s ServiceType) String() string {
	switch s {
	case ServiceSite:
		return "site"
	case ServiceAPI:
		return "api"
	case ServiceStream:
		return "stream"
	case ServiceStore:
		return "store"
	case ServiceOther:
		return "other"
	default:
		return "unknown"
	}
}

// CID is a BLAKE3 content address from §10.
type CID [32]byte

// IsZero reports an absent CID.
func (c CID) IsZero() bool { return c == CID{} }

func (c CID) String() string { return hex.EncodeToString(c[:]) }

// Address is the on-chain owner at the time of observation.
type Address [20]byte

// ContentIdentity is what a report, a label or a prune attaches to.
//
// Both keys are present and neither is optional. A struct that let one be
// omitted would let a caller build the object that R-85.1 exists to forbid:
// a report against a name with no version, or a version with no name.
type ContentIdentity struct {
	// NameHash is the keccak namehash from §11.3 — the ANCHOR. Reports
	// accumulate here and survive a republish.
	NameHash [32]byte
	// ZoneID is §11.3.2's SHA-256 over the normalised name. Carried because the
	// DHT keys on it and a resolver holding one should not have to recompute
	// the other.
	ZoneID [32]byte
	// Owner is the on-chain owner AT THE TIME OF OBSERVATION. Recorded rather
	// than looked up later: R-93.3 keeps a seizure in the history precisely so
	// a new owner is judged on their own content, and a claim that resolved the
	// owner at read time would silently re-attribute every old report.
	Owner Address
	// ManifestCID is the VERSION observed. Evidence names this.
	ManifestCID CID
	// Service is what the name served when observed.
	Service ServiceType
	// ObservedAt is the block height the observation is anchored to. A
	// timestamp would be the observer's word; a height is checkable.
	ObservedAt uint64
}

var (
	// ErrNoName means the identity has no name hash to accumulate against.
	ErrNoName = errors.New("axon/content: identity has no name hash")
	// ErrNoVersion means it names no version, so it is not evidence about
	// anything in particular.
	ErrNoVersion = errors.New("axon/content: identity has no manifest CID")
	// ErrNoHeight means the observation is not anchored in time.
	ErrNoHeight = errors.New("axon/content: identity has no observation height")
)

// Validate refuses an identity that cannot carry a claim.
func (c ContentIdentity) Validate() error {
	if c.NameHash == [32]byte{} {
		return ErrNoName
	}
	if c.ManifestCID.IsZero() {
		return ErrNoVersion
	}
	if c.ObservedAt == 0 {
		return ErrNoHeight
	}
	return nil
}

// For builds an identity for a normalised name and an observed version.
//
// It takes a name.Name rather than a string, so an unnormalised name cannot
// reach a report. §11.3.2's normalisation is total and idempotent, and two
// spellings of one name must not produce two identities — that would let a
// publisher shed reports by changing case.
func For(n name.Name, manifest CID, owner Address, service ServiceType, height uint64) (ContentIdentity, error) {
	// THE SUBJECT IS THE REGISTRABLE NAME, even for a subordinate.
	//
	// §11 gives an on-chain namehash only to a registrable name; a subordinate
	// has none, and NameHash() says so rather than inventing one. That forces a
	// ruling, because §85 requires reports to accumulate against a name hash and
	// subordinates would otherwise accumulate against nothing.
	//
	// RULING: a subordinate's reports count against its REGISTRABLE PARENT. The
	// chain is what governance can act on -- §93 can prune or seize a registered
	// name and has no handle on `blog.acme.lab.axon` -- and the registrant
	// controls their own subordinates, so attributing them upward is where the
	// responsibility already sits. The alternative is a namespace where anyone
	// sheds a report history by publishing under a fresh subdomain.
	//
	// The full name is not lost: ZoneID below is computed over the name AS
	// GIVEN, so two subordinates of one parent share a subject and remain
	// distinguishable within it.
	registrable := n
	if !n.IsRegistrable() {
		reg, rerr := name.Normalise(n.Registrable() + "." + n.Namespace() + "." + n.Root())
		if rerr != nil {
			return ContentIdentity{}, fmt.Errorf("axon/content: registrable parent of %s: %w", n, rerr)
		}
		registrable = reg
	}
	nameHash, err := registrable.NameHash()
	if err != nil {
		return ContentIdentity{}, fmt.Errorf("axon/content: %w", err)
	}
	id := ContentIdentity{
		NameHash:    nameHash,
		ZoneID:      n.ZoneID(),
		Owner:       owner,
		ManifestCID: manifest,
		Service:     service,
		ObservedAt:  height,
	}
	return id, id.Validate()
}

// SameSubject reports whether two identities accumulate together.
//
// THIS IS R-85.1. It compares the registrable NAME, not the version — which is what makes a
// report survive a republish. Two observations of one name at different content
// are the same subject; the versions they name are recorded separately and are
// what an appeal argues about.
func SameSubject(a, b ContentIdentity) bool { return a.NameHash == b.NameHash }

// SameVersion reports whether two identities observed the same content.
func SameVersion(a, b ContentIdentity) bool {
	return a.NameHash == b.NameHash && a.ManifestCID == b.ManifestCID
}

// Subject is the accumulation key: reports are counted per subject.
func (c ContentIdentity) Subject() [32]byte { return c.NameHash }

// VersionKey identifies one observed version of one name, for the evidence
// side of a report.
func (c ContentIdentity) VersionKey() string {
	return hex.EncodeToString(c.NameHash[:8]) + ":" + c.ManifestCID.String()[:16]
}

// Superseded reports whether this identity names a version the name no longer
// serves.
//
// It is the appeal's defence, made computable: "that CID is not what this name
// serves now". It is deliberately NOT a reason to discard the report — §93's
// appeal is a governance decision, and a system that silently dropped reports
// whenever content changed would let a publisher clear its record by
// republishing. What this answers is whether the defence is AVAILABLE.
func (c ContentIdentity) Superseded(current CID) bool {
	if current.IsZero() || c.ManifestCID.IsZero() {
		return false
	}
	return c.ManifestCID != current
}
