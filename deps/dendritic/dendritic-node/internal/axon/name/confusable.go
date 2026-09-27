package name

import "strings"

// ASCII confusables (§11.3.3).
//
// THE POLICY, STATED RATHER THAN DELEGATED. Normalise rejects every byte
// >= 0x80, which removes the entire non-ASCII homograph class -- Cyrillic а for
// Latin a, Greek ο for o, the full-stop lookalikes, all of it -- in one rule.
//
// THAT IS A REAL COST, AND IT IS THE COST WE CHOSE: it excludes every legitimate
// non-Latin name. A user whose language is not written in ASCII cannot have a
// name in it. §11.3.3 says so, and this file does not pretend the restriction is
// free or that adopting IDNA would have solved it -- IDNA moves the problem into
// a table that is revised faster than a registry can re-police what it already
// issued.
//
// What remains after that rule is the ASCII-on-ASCII set, which is small,
// enumerable, and listed here PER PAIR rather than delegated to a library
// default (T8.4). A library's notion of "confusable" is a moving target; this
// table is auditable and changes only when somebody edits it.

// confusableFold maps a character to its skeleton representative.
//
// The skeleton is NOT a normalisation: two names with the same skeleton are both
// valid and both registrable in principle. It is a REGISTRY policy input --
// §11.3.1 refuses "a label whose confusable skeleton is held by another owner",
// which is a check the registrar makes against existing registrations, not
// something Normalise may do to an input.
var confusableFold = map[byte]byte{
	// digit/letter pairs, both directions folded onto the digit
	'o': '0', 'O': '0', // o, O -> 0   (O is lowercased before this runs)
	'l': '1', 'i': '1', 'I': '1', // l, i -> 1
	's': '5', // s -> 5
	'b': '6', // b -> 6
	'g': '9', // g -> 9
	'z': '2', // z -> 2
	// hyphen: elided outright in Skeleton before this table runs, so it is a
	// class member rather than a fold target. Listed so the absence is
	// visibly deliberate.
}

// Skeleton reduces a label to its confusable representative.
//
// Multi-character confusables are handled first: "rn" reads as "m" at small
// sizes and in most sans-serif faces, and it is the single most-used ASCII
// homograph in real phishing. It has to be folded BEFORE the per-character pass,
// or the r and n fold independently and the pair is lost.
func Skeleton(label string) string {
	// Hyphen elision FIRST (§11.3.3: `s := replace(s, "-", "")`). Without it
	// `my-bank` and `mybank` are different classes, and §11.3.3's own stated
	// consequence 1 -- "mybank.axon blocks my-bank.axon" -- does not hold.
	// The earlier note here read "hyphen-like" as a character-fold and
	// concluded there was nothing to do; the rule is elision, not folding.
	s := strings.ReplaceAll(label, "-", "")
	s = strings.ReplaceAll(s, "rn", "m")
	// "vv" reads as "w" for the same reason.
	s = strings.ReplaceAll(s, "vv", "w")
	// "cl" reads as "d" in several common faces.
	s = strings.ReplaceAll(s, "cl", "d")

	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if f, ok := confusableFold[c]; ok {
			c = f
		}
		out = append(out, c)
	}
	return string(out)
}

// Confusable reports whether two labels share a skeleton.
//
// This is the predicate a registrar applies against names ALREADY HELD. It is
// deliberately not applied by Normalise: refusing an input because it resembles
// something would make the function non-total and would make registration order
// determine validity.
func Confusable(a, b string) bool { return Skeleton(a) == Skeleton(b) }
