package content

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// G2 — classification (§86).
//
// R-86.1: A LABEL IS A CLAIM BY AN IDENTIFIED PARTY, NEVER A FACT.
//
// Every label carries who says so and a signature over the saying. There is no
// unattributed label anywhere in this package and no field that asserts "this
// content IS malware" without naming the claimant.
//
// The reason is not epistemic tidiness. An unattributed label is a censorship
// primitive with no accountability: whoever can write one can suppress content
// and nobody can be held to it. Attribution is also what makes §90's reporter
// reputation possible at all — you cannot score the accuracy of an anonymous
// claim, so an anonymous label is not merely unpolite, it is unscoreable and
// therefore unweightable.
//
// UNKNOWN IS NOT A CATEGORY. It is the absence of one, and it is spelled out
// here so that no caller ever signs a claim that content "is" unknown.

// Category is §86's vocabulary, adopted as given.
type Category uint8

const (
	// CategoryUnknown is the ZERO VALUE and means NOTHING HAS BEEN CLAIMED.
	// It is never a valid label subject; see Label.Validate.
	CategoryUnknown Category = iota
	CategoryGeneral
	CategoryTechnology
	CategorySocial
	CategoryPolitical
	CategoryAdult
	CategoryGambling
	CategoryMalware
	CategoryPhishing
	CategorySpam
	CategoryIllegal
	CategoryExtremist
	CategoryCopyright
)

var categoryNames = map[Category]string{
	CategoryUnknown:    "unknown",
	CategoryGeneral:    "general",
	CategoryTechnology: "technology",
	CategorySocial:     "social",
	CategoryPolitical:  "political",
	CategoryAdult:      "adult",
	CategoryGambling:   "gambling",
	CategoryMalware:    "malware",
	CategoryPhishing:   "phishing",
	CategorySpam:       "spam",
	CategoryIllegal:    "illegal",
	CategoryExtremist:  "extremist",
	CategoryCopyright:  "copyright",
}

func (c Category) String() string {
	if s, ok := categoryNames[c]; ok {
		return s
	}
	return "invalid"
}

// Valid reports whether a category may be CLAIMED. `unknown` may not.
func (c Category) Valid() bool {
	_, ok := categoryNames[c]
	return ok && c != CategoryUnknown
}

// ParseCategory is the only way a string becomes a Category, so an unrecognised
// label cannot enter the system as a novel category nobody defined.
func ParseCategory(s string) (Category, error) {
	want := strings.ToLower(strings.TrimSpace(s))
	for cat, name := range categoryNames {
		if name == want && cat != CategoryUnknown {
			return cat, nil
		}
	}
	return CategoryUnknown, fmt.Errorf("%w: %q", ErrUnknownCategory, s)
}

// Jurisdictional reports whether a category is a matter of law rather than of
// fact — the same bytes being lawful in one place and not another.
//
// §94 rules that the DAO may NOT globally prune on these grounds: the network
// spans legal systems that disagree, and a majority vote does not resolve a
// conflict of laws, it exports one jurisdiction's answer to everyone. They
// remain LABELS, and remain usable as local policy (§87), which is where a
// jurisdiction-specific decision belongs.
func (c Category) Jurisdictional() bool {
	switch c {
	case CategoryIllegal, CategoryExtremist, CategoryCopyright:
		return true
	default:
		return false
	}
}

// PruneEligible reports whether §93 may act on this category network-wide.
//
// Only MALWARE and PHISHING. They are attacks on the network's own users and
// are not a matter of opinion; everything else is either taste or jurisdiction.
func (c Category) PruneEligible() bool {
	return c == CategoryMalware || c == CategoryPhishing
}

// ClaimantID is the identity making a claim. 32 bytes: an Ed25519 public key.
type ClaimantID [32]byte

// IsZero reports an unattributed claim, which is the thing R-86.1 forbids.
func (c ClaimantID) IsZero() bool { return c == ClaimantID{} }

// Label is one attributed, signed claim about one subject.
type Label struct {
	// Subject is the ContentIdentity this is about. Both of its keys travel
	// with it: a claim naming no version is not evidence (R-85.1).
	Subject ContentIdentity
	// Category is what is claimed. Never CategoryUnknown.
	Category Category
	// Confidence in [0,1]. §91 rules that a confidence may inform a HOST
	// decision and may NEVER inform a prune, because the two errors are not
	// comparable and do not get the same evidentiary standard.
	Confidence float32
	// Claimant is WHO SAYS SO. Never zero.
	Claimant ClaimantID
	// At is the block height the claim is anchored to.
	At uint64
	// Signature is over SigningBytes. Never empty.
	Signature []byte
}

var (
	ErrUnknownCategory = errors.New("axon/content: not a defined category")
	// ErrUnattributed is R-86.1's refusal.
	ErrUnattributed = errors.New("axon/content: label has no claimant; an unattributed label is a censorship primitive with no accountability")
	ErrUnsigned     = errors.New("axon/content: label has no signature")
	ErrBadSignature = errors.New("axon/content: label signature does not verify")
	ErrNotClaimable = errors.New("axon/content: category cannot be claimed")
	ErrConfidence   = errors.New("axon/content: confidence is outside [0,1]")
)

// SigningBytes is the canonical encoding a claimant signs.
//
// Built by hand rather than by a struct encoder, for the same reason
// release.signingBytes is: a signature over "whatever the encoder produced" is a
// signature over an encoder version, and two library versions that order or pad
// differently would make every honest label fail to verify — which presents as
// forgery.
//
// The SUBJECT'S BOTH KEYS are inside it. Signing the category alone would let a
// label be moved from one name to another with its signature intact.
func (l Label) SigningBytes() []byte {
	b := make([]byte, 0, 160)
	b = append(b, "axon-content-label-v1\n"...)
	b = append(b, l.Subject.NameHash[:]...)
	b = append(b, l.Subject.ZoneID[:]...)
	b = append(b, l.Subject.ManifestCID[:]...)
	b = append(b, byte(l.Category))
	// Confidence to 4 decimal places as an integer, so the signed bytes do not
	// depend on float formatting.
	var conf [4]byte
	binary.BigEndian.PutUint32(conf[:], uint32(l.Confidence*10000))
	b = append(b, conf[:]...)
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], l.At)
	b = append(b, at[:]...)
	b = append(b, l.Claimant[:]...)
	return b
}

// Sign produces a signed label. The only way to make one this package accepts.
func Sign(subject ContentIdentity, cat Category, confidence float32, at uint64, priv ed25519.PrivateKey) (Label, error) {
	l := Label{Subject: subject, Category: cat, Confidence: confidence, At: at}
	copy(l.Claimant[:], priv.Public().(ed25519.PublicKey))
	if err := l.validateClaim(); err != nil {
		return Label{}, err
	}
	l.Signature = ed25519.Sign(priv, l.SigningBytes())
	return l, nil
}

// validateClaim checks everything except the signature.
func (l Label) validateClaim() error {
	if err := l.Subject.Validate(); err != nil {
		return err
	}
	if !l.Category.Valid() {
		// Catches CategoryUnknown specifically: "unknown" is the absence of a
		// claim, and signing one would assert that content IS unclassified,
		// which is a different and unfalsifiable thing.
		return fmt.Errorf("%w: %s", ErrNotClaimable, l.Category)
	}
	if l.Confidence < 0 || l.Confidence > 1 {
		return fmt.Errorf("%w: %v", ErrConfidence, l.Confidence)
	}
	if l.Claimant.IsZero() {
		return ErrUnattributed
	}
	if l.At == 0 {
		return ErrNoHeight
	}
	return nil
}

// Verify checks a label completely. This is the ONLY admission path.
func (l Label) Verify() error {
	if err := l.validateClaim(); err != nil {
		return err
	}
	if len(l.Signature) == 0 {
		return ErrUnsigned
	}
	if !ed25519.Verify(ed25519.PublicKey(l.Claimant[:]), l.SigningBytes(), l.Signature) {
		return ErrBadSignature
	}
	return nil
}

// LabelSet is the labels held about one subject, from many claimants.
//
// It deliberately does NOT reduce them to a verdict. §91 rules that a
// confidence estimate may inform a host's own policy and may never inform a
// prune; a type that collapsed claims into "this is malware" would erase the
// attribution R-86.1 exists to keep.
type LabelSet struct {
	subject [32]byte
	labels  []Label
}

// NewLabelSet starts an empty set for a subject.
func NewLabelSet(subject [32]byte) *LabelSet { return &LabelSet{subject: subject} }

// Add admits a label after full verification.
//
// A label about a different subject is refused rather than re-filed: silently
// moving a claim from the name it was signed for to the one being asked about
// is exactly what the signature covers both keys to prevent.
func (s *LabelSet) Add(l Label) error {
	if err := l.Verify(); err != nil {
		return err
	}
	if l.Subject.Subject() != s.subject {
		return fmt.Errorf("axon/content: label is about another subject")
	}
	s.labels = append(s.labels, l)
	return nil
}

// Len is how many claims are held.
func (s *LabelSet) Len() int { return len(s.labels) }

// Claimants returns the distinct claimants, sorted.
//
// The count matters more than it looks: §90's corroboration factor must be
// SUBLINEAR in identity count, and a set that reported ten labels from one
// claimant as ten opinions would defeat that before the weighting ran.
func (s *LabelSet) Claimants() []ClaimantID {
	seen := map[ClaimantID]bool{}
	var out []ClaimantID
	for _, l := range s.labels {
		if !seen[l.Claimant] {
			seen[l.Claimant] = true
			out = append(out, l.Claimant)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return string(out[i][:]) < string(out[j][:])
	})
	return out
}

// ByCategory returns the claims for one category, with their claimants intact.
func (s *LabelSet) ByCategory(c Category) []Label {
	var out []Label
	for _, l := range s.labels {
		if l.Category == c {
			out = append(out, l)
		}
	}
	return out
}
