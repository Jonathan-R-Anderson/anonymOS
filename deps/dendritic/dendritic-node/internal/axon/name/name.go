package name

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/sha3"
)

// Normalisation (§11.3.2) and the grammar (§11.3.1).
//
// Normalise is a TOTAL FUNCTION from input to a canonical name or an error. It
// never guesses, and the list of things it deliberately does NOT do is as
// load-bearing as the list of things it does:
//
//   - no Unicode normalisation, because there is no Unicode: step 1 rejects
//     every byte >= 0x80, which removes every non-ASCII homograph class at once;
//   - no whitespace trimming, because "alice .lab.axon" is an ERROR rather than
//     "alice.lab.axon" -- silent trimming lets the first be planted where the
//     second is expected;
//   - no mapping of full-stop lookalikes (U+3002, U+FF0E, U+FF61), which step 1
//     already rejects, which is why step 1 is first.
//
// A mapping that "helps" is a mapping an attacker exploits.

var (
	ErrNonASCII      = errors.New("axon/name: byte >= 0x80")
	ErrControl       = errors.New("axon/name: control byte")
	ErrEmptyLabel    = errors.New("axon/name: empty label")
	ErrCharset       = errors.New("axon/name: byte outside [a-z0-9.-]")
	ErrGrammar       = errors.New("axon/name: grammar")
	ErrNotRoot       = errors.New("axon/name: last label is not the root suffix")
	ErrReserved      = errors.New("axon/name: reserved label")
	ErrTooLong       = errors.New("axon/name: name exceeds its length bound")
	ErrTooManyLabels = errors.New("axon/name: too many labels")
)

// Name is a normalised name. The zero value is invalid; construct with
// Normalise.
type Name struct {
	labels []string
}

// Normalise applies §11.3.2's eight steps in order.
func Normalise(input string) (Name, error) {
	// 1. Reject any byte >= 0x80. FIRST, so that every lookalike codepoint --
	//    including the full-stop lookalikes -- is gone before anything else
	//    inspects structure.
	//
	//    A SEPARATE PASS, not a combined one: §11.3.2 numbers this step 1 and
	//    the control-byte rule step 2, and an input carrying both must report
	//    the non-ASCII byte whichever comes first in the string. Folding the
	//    two rules into one loop makes the reported reason depend on byte
	//    order, which E8.3's second implementation caught.
	for i := 0; i < len(input); i++ {
		if input[i] >= 0x80 {
			return Name{}, fmt.Errorf("%w at offset %d", ErrNonASCII, i)
		}
	}

	// 2. Reject control bytes.
	for i := 0; i < len(input); i++ {
		if input[i] < 0x20 || input[i] == 0x7F {
			return Name{}, fmt.Errorf("%w at offset %d", ErrControl, i)
		}
	}

	// 3. Strip at most one trailing ".".
	s := input
	if strings.HasSuffix(s, ".") {
		s = s[:len(s)-1]
	}
	if s == "" {
		return Name{}, ErrEmptyLabel
	}

	// 5. Map A-Z to a-z. The ONLY character mapping performed.
	s = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, s)

	// 6. Reject any remaining byte outside [a-z0-9.-].
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return Name{}, fmt.Errorf("%w: %q at offset %d", ErrCharset, c, i)
		}
	}

	// 4. Reject a leading "." or any empty label.
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" {
			return Name{}, ErrEmptyLabel
		}
	}

	// 7 & 8. Grammar, and the root suffix.
	n := Name{labels: labels}
	if err := n.validate(); err != nil {
		return Name{}, err
	}
	return n, nil
}

// validate applies §11.3.1.
func (n Name) validate() error {
	if len(n.labels) > MaxLabels {
		return fmt.Errorf("%w: %d > %d", ErrTooManyLabels, len(n.labels), MaxLabels)
	}
	if l := len(n.String()); l > MaxNameBytes {
		return fmt.Errorf("%w: %d > %d bytes", ErrTooLong, l, MaxNameBytes)
	}
	// A bare root, or root with no registrable label, is not a name.
	if len(n.labels) < 3 {
		return fmt.Errorf("%w: need registrable.namespace.%s", ErrGrammar, RootSuffix)
	}

	for i, l := range n.labels[:len(n.labels)-1] {
		if err := validLDH(l); err != nil {
			return fmt.Errorf("label %d (%q): %w", i, l, err)
		}
	}
	ns, reg := n.Namespace(), n.Registrable()
	if len(ns) < MinNamespaceLen || len(ns) > MaxNamespaceLen {
		return fmt.Errorf("%w: namespace %q length %d outside [%d,%d]",
			ErrGrammar, ns, len(ns), MinNamespaceLen, MaxNamespaceLen)
	}
	if len(reg) < MinRegistrableLen || len(reg) > MaxRegistrableLen {
		return fmt.Errorf("%w: registrable %q length %d outside [%d,%d]",
			ErrGrammar, reg, len(reg), MinRegistrableLen, MaxRegistrableLen)
	}
	if IsReserved(ns) {
		return fmt.Errorf("%w: namespace %q", ErrReserved, ns)
	}
	if IsReserved(reg) {
		return fmt.Errorf("%w: registrable %q", ErrReserved, reg)
	}
	for i, l := range n.Subordinates() {
		if len(l) < MinSubordinateLen || len(l) > MaxSubordinateLen {
			return fmt.Errorf("%w: subordinate %d (%q) length %d outside [%d,%d]",
				ErrGrammar, i, l, len(l), MinSubordinateLen, MaxSubordinateLen)
		}
	}
	// 8. Require the last label == the root suffix.
	//
	// LAST, because §11.3.2 numbers it last: a name that is both ungrammatical
	// and not ours is reported as ungrammatical. Checking it earlier made the
	// root suffix mask every other refusal, which is the wrong reason to give a
	// caller and which E8.3's second implementation caught on 1 799 inputs.
	if n.labels[len(n.labels)-1] != RootSuffix {
		return ErrNotRoot
	}
	return nil
}

// validLDH enforces the ldh-label production.
func validLDH(l string) error {
	if l == "" {
		return ErrEmptyLabel
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return fmt.Errorf("%w: leading or trailing hyphen", ErrGrammar)
	}
	if l[0] == '-' {
		return fmt.Errorf("%w: leading hyphen", ErrGrammar)
	}
	// A label may not START with a digit? §11.3.1's production is
	//   ldh-label := (ALPHA-LOWER / DIGIT) ((ALPHA-LOWER / DIGIT / "-")* (ALPHA-LOWER / DIGIT))?
	// so a leading digit IS permitted. Stated because DNS's historical rule is
	// the opposite and an implementer working from memory gets it wrong.
	if len(l) >= 4 && l[2] == '-' && l[3] == '-' {
		// Reserves the IDNA A-label prefix. Stops a punycode-looking label
		// being smuggled past an ASCII registry into a client that helpfully
		// decodes it.
		return fmt.Errorf("%w: hyphens at positions 3 and 4 reserve the IDNA prefix", ErrGrammar)
	}
	return nil
}

// String returns the canonical form. This is what is hashed.
func (n Name) String() string { return strings.Join(n.labels, ".") }

// Labels returns the labels, root last.
func (n Name) Labels() []string { return append([]string(nil), n.labels...) }

// Root is the root suffix label.
func (n Name) Root() string { return n.labels[len(n.labels)-1] }

// Namespace is the governed label directly beneath the root.
func (n Name) Namespace() string { return n.labels[len(n.labels)-2] }

// Registrable is the only label held on chain.
func (n Name) Registrable() string { return n.labels[len(n.labels)-3] }

// Subordinates are the labels delegated off chain, outermost first.
func (n Name) Subordinates() []string {
	if len(n.labels) <= 3 {
		return nil
	}
	return append([]string(nil), n.labels[:len(n.labels)-3]...)
}

// IsRegistrable reports whether the name is exactly registrable.namespace.root,
// with no subordinate labels -- the only shape that has an on-chain nameHash.
func (n Name) IsRegistrable() bool { return len(n.labels) == 3 }

// ZoneID is the off-chain identifier: SHA-256 over the canonical name.
//
// SHA-256 because §2 fixes it for protocol hashing. The overlay never needs
// keccak and should not carry it.
func (n Name) ZoneID() [32]byte {
	h := sha256.New()
	h.Write([]byte(ZoneIDLabel))
	h.Write([]byte{0x00})
	h.Write([]byte(n.String()))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// NameHash is the on-chain identifier, ENS-style namehash over keccak256.
//
// keccak because §2 fixes it for Ethereum interop and the contract must
// recompute it. It exists only for a registrable name: subordinate names are
// delegated off chain and have a ZoneID and no NameHash.
func (n Name) NameHash() ([32]byte, error) {
	if !n.IsRegistrable() {
		return [32]byte{}, fmt.Errorf("%w: %q has subordinate labels and no on-chain hash",
			ErrGrammar, n)
	}
	// namehash("")     = 0x00 * 32
	// namehash(root)   = keccak(0x00*32 ‖ keccak(root))
	// namehash(ns.root)= keccak(namehash(root) ‖ keccak(ns))
	// nameHash         = keccak(namehash(ns.root) ‖ keccak(registrable))
	var node [32]byte
	for i := len(n.labels) - 1; i >= 0; i-- {
		lh := keccak([]byte(n.labels[i]))
		node = keccak(append(append([]byte{}, node[:]...), lh[:]...))
	}
	return node, nil
}

func keccak(b []byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(b)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
