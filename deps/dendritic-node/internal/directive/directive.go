// Package directive verifies the signed statement of where this network lives.
//
// DNS is what breaks in every situation this exists for -- a seized name, a
// registrar dispute, a dead server -- so DNS is not the authority. A document
// signed by the operator's wallet is, and this node prefers the last one it
// verified over anything a name resolves to.
//
// WHY THIS IS IN GO AND NOT IN THE BACKEND
// The backend verifies wallet signatures by asking the renderer, which lives in
// the origin cluster. That works only while the origin is up, which is exactly
// when none of this is needed. A node has to be able to learn that the origin
// moved WITHOUT the origin -- so it verifies here, by itself, with no network
// call to anything the directive might be replacing.
//
// AND WHY THE WALLET IS PINNED IN CONFIG
// The authorised address is set when the node is installed. It is never fetched
// from the origin, because fetching the authority from the thing being replaced
// is not authentication -- whoever took the domain would simply serve their own
// address alongside their own directive.
package directive

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// Header is the first line of every canonical message. A document that does not
// begin with it is not a directive, whatever else it may parse as.
const Header = "syndichan network directive v1"

// Kinds. A freeze pins the network where it is and refuses everything except a
// resume; it is deliberately the cheapest directive to issue, because its
// failure mode is an outage and the alternative's is losing the project.
const (
	KindMove   = "move"
	KindFreeze = "freeze"
	KindResume = "resume"
)

// signedFields is the order the canonical message uses. It MUST match
// SIGNED_FIELDS in backend/services/network_directive.py: the two sides sign
// and verify the same bytes, and a mismatch would surface as "your signature is
// invalid" on a machine nobody can reach.
var signedFields = []string{
	"kind", "sequence", "issued_at", "not_before", "emergency",
	"origin_domain", "origin_address", "origin_key", "note",
}

// Directive is one signed statement. Only the fields above are covered by the
// signature; anything else that arrives alongside is not trusted.
type Directive struct {
	Kind          string `json:"kind"`
	Sequence      uint64 `json:"sequence"`
	IssuedAt      int64  `json:"issued_at"`
	NotBefore     int64  `json:"not_before"`
	Emergency     bool   `json:"emergency"`
	OriginDomain  string `json:"origin_domain"`
	OriginAddress string `json:"origin_address"`
	OriginKey     string `json:"origin_key"`
	Note          string `json:"note"`
}

// Document is the JSON served at /.well-known/syndichan/network.json.
type Document struct {
	Directive *Directive `json:"directive"`
	Canonical string     `json:"canonical"`
	Signature string     `json:"signature"`
	// Signer and Wallet are advisory only. They are served by the same host
	// that served the directive, so they can confirm what this node already
	// knows and can never establish who is allowed to sign.
	Signer string `json:"signer"`
	Wallet string `json:"wallet"`
}

var (
	ErrNotADirective = errors.New("not a network directive")
	ErrMalformed     = errors.New("malformed directive")
	ErrBadSignature  = errors.New("signature did not verify")
	ErrWrongWallet   = errors.New("signed by an address this node does not trust")
	ErrStale         = errors.New("sequence is not newer than the one in force")
	ErrFrozen        = errors.New("the network is frozen; only a resume is accepted")
)

// Canonical renders the exact bytes that are signed.
//
// Line-based rather than JSON on purpose. Two JSON encoders disagree about
// spacing, key order and escaping, and a signature is over bytes -- so "the
// same document" in two languages is two different messages. This format has
// one way to write it, and a person can read it in the wallet's signing prompt
// and see what they are agreeing to.
func Canonical(d *Directive) string {
	var b strings.Builder
	b.WriteString(Header)
	for _, field := range signedFields {
		b.WriteString("\n")
		b.WriteString(field)
		b.WriteString(": ")
		b.WriteString(fieldValue(d, field))
	}
	return b.String()
}

func fieldValue(d *Directive, field string) string {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	switch field {
	case "kind":
		return dash(d.Kind)
	case "sequence":
		return strconv.FormatUint(d.Sequence, 10)
	case "issued_at":
		return strconv.FormatInt(d.IssuedAt, 10)
	case "not_before":
		return strconv.FormatInt(d.NotBefore, 10)
	case "emergency":
		// "yes"/"no", never Go's "true" or Python's "True". A boolean rendered
		// by each language's own conventions is two different signed messages.
		if d.Emergency {
			return "yes"
		}
		return "no"
	case "origin_domain":
		return dash(d.OriginDomain)
	case "origin_address":
		return dash(d.OriginAddress)
	case "origin_key":
		return dash(d.OriginKey)
	case "note":
		return dash(d.Note)
	}
	return "-"
}

// ParseCanonical reads a canonical message back into a Directive.
//
// Splitting on the FIRST ": " is what keeps the free-text note safe: a note
// reading "origin_domain: evil.example" stays inside the note's value instead
// of becoming a field of its own.
func ParseCanonical(text string) (*Directive, error) {
	lines := strings.Split(text, "\n")
	if len(lines) == 0 || lines[0] != Header {
		return nil, ErrNotADirective
	}
	if len(lines) != 1+len(signedFields) {
		return nil, fmt.Errorf("%w: expected %d lines, got %d",
			ErrMalformed, 1+len(signedFields), len(lines))
	}

	d := &Directive{}
	for i, field := range signedFields {
		line := lines[i+1]
		prefix := field + ": "
		if !strings.HasPrefix(line, prefix) {
			return nil, fmt.Errorf("%w: expected %q", ErrMalformed, field)
		}
		value := line[len(prefix):]
		blank := value == "-"
		switch field {
		case "kind":
			if blank {
				return nil, fmt.Errorf("%w: kind is required", ErrMalformed)
			}
			d.Kind = value
		case "sequence":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: sequence %q", ErrMalformed, value)
			}
			d.Sequence = n
		case "issued_at", "not_before":
			n, err := strconv.ParseInt(value, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("%w: %s %q", ErrMalformed, field, value)
			}
			if field == "issued_at" {
				d.IssuedAt = n
			} else {
				d.NotBefore = n
			}
		case "emergency":
			d.Emergency = value == "yes"
		case "origin_domain":
			if !blank {
				d.OriginDomain = value
			}
		case "origin_address":
			if !blank {
				d.OriginAddress = value
			}
		case "origin_key":
			if !blank {
				d.OriginKey = value
			}
		case "note":
			if !blank {
				d.Note = value
			}
		}
	}
	return d, nil
}

// RecoverSigner returns the 0x address that produced an EIP-191 personal_sign
// signature over message, lower-cased.
//
// This is the whole reason a node can act during an outage: no network call,
// no dependency on the origin, nothing to be unavailable.
func RecoverSigner(message string, signature string) (string, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(signature), "0x"))
	if err != nil {
		return "", fmt.Errorf("%w: signature is not hex", ErrBadSignature)
	}
	if len(raw) != 65 {
		return "", fmt.Errorf("%w: signature is %d bytes, want 65", ErrBadSignature, len(raw))
	}

	// Ethereum lays a signature out as r||s||v with v of 27 or 28. Some wallets
	// and libraries emit 0 or 1 instead, and rejecting those would fail for
	// signatures that are perfectly valid.
	v := raw[64]
	switch {
	case v >= 27:
		v -= 27
	case v > 1:
		return "", fmt.Errorf("%w: recovery id %d", ErrBadSignature, raw[64])
	}
	if v > 1 {
		return "", fmt.Errorf("%w: recovery id %d", ErrBadSignature, raw[64])
	}

	// decred wants the recovery byte FIRST, and offset by 27. Getting this
	// wrong recovers a valid-looking but entirely different address, which
	// would read as "the operator signed with the wrong wallet".
	compact := make([]byte, 65)
	compact[0] = v + 27
	copy(compact[1:], raw[:64])

	pub, _, err := ecdsa.RecoverCompact(compact, personalHash(message))
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrBadSignature, err)
	}
	return addressOf(pub), nil
}

// personalHash is keccak256 of the EIP-191 prefixed message. The prefix is what
// stops a signature over a directive being reusable as a transaction.
func personalHash(message string) []byte {
	h := sha3.NewLegacyKeccak256()
	fmt.Fprintf(h, "\x19Ethereum Signed Message:\n%d", len(message))
	h.Write([]byte(message))
	return h.Sum(nil)
}

func addressOf(pub *secp256k1.PublicKey) string {
	// Uncompressed form, minus the 0x04 tag: the address is the last 20 bytes
	// of keccak256 over the 64-byte X||Y.
	uncompressed := pub.SerializeUncompressed()
	h := sha3.NewLegacyKeccak256()
	h.Write(uncompressed[1:])
	sum := h.Sum(nil)
	return "0x" + hex.EncodeToString(sum[12:])
}

// SameAddress compares two 0x addresses without regard to case.
//
// NOT a plain lower-case comparison of arbitrary strings: an empty pinned
// wallet must never match an empty recovered one, because that is the shape of
// a node with no configured authority accepting anything at all.
func SameAddress(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if a == "" || b == "" {
		return false
	}
	return a == b
}

// Verify checks a served document against the wallet this node was configured
// with, and against what it already holds.
//
// held may be nil, meaning nothing is pinned yet.
func Verify(doc *Document, pinnedWallet string, held *Directive) (*Directive, error) {
	if doc == nil || doc.Directive == nil {
		return nil, ErrNotADirective
	}

	// Rebuilt from the signed fields rather than trusting doc.Canonical. A
	// document that carries text different from its own fields would otherwise
	// let a valid signature vouch for values nobody signed.
	d := doc.Directive
	message := Canonical(d)
	if doc.Canonical != "" && doc.Canonical != message {
		return nil, fmt.Errorf("%w: the served text does not match the served fields",
			ErrMalformed)
	}

	signer, err := RecoverSigner(message, doc.Signature)
	if err != nil {
		return nil, err
	}
	if !SameAddress(signer, pinnedWallet) {
		return nil, fmt.Errorf("%w: %s", ErrWrongWallet, signer)
	}

	if err := CheckAcceptable(d, held); err != nil {
		return nil, err
	}
	return d, nil
}

// CheckAcceptable applies the rules a correctly signed directive still has to
// pass. Kept separate from signature checking because "that is not your
// signature" and "that is your signature on a stale directive" call for
// different responses.
func CheckAcceptable(d *Directive, held *Directive) error {
	if held == nil {
		return nil
	}
	if d.Sequence <= held.Sequence {
		// The reason the sequence exists. A signature stays valid forever, so
		// without this a directive captured off the wire today could be
		// replayed in a year to drag the network somewhere it has since left.
		return fmt.Errorf("%w: %d is not newer than %d",
			ErrStale, d.Sequence, held.Sequence)
	}
	if held.Kind == KindFreeze && d.Kind != KindResume {
		return fmt.Errorf("%w (frozen at %d)", ErrFrozen, held.Sequence)
	}
	return nil
}

// Effective reports whether a verified directive may be acted on yet.
//
// An ordinary move waits, and that delay is the window in which an operator
// notices a directive they did not issue. An emergency skips it -- immediate
// failover is the actual requirement -- and pays for that in visibility: the
// caller is told, and is expected to say so loudly.
func (d *Directive) Effective(now int64) bool {
	return now >= d.NotBefore
}

// ParseDocument reads the JSON served at /.well-known/syndichan/network.json.
func ParseDocument(body []byte) (*Document, error) {
	var doc Document
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	return &doc, nil
}
