// Package name is AXON's L7 naming: grammar, normalisation and canonical
// encoding for the governed namespace.
//
// It is an ENCODING AND A POLICY, not a protocol. Nothing here goes on the wire.
// The only form a lower layer ever sees is a 32-byte hash.
package name

import "time"

// RootSuffix is the root label. §1 of the Constitution requires it to be
// reachable through exactly one constant, and this is it.
//
// THIS FILE IS THE ONLY PLACE THE LITERAL MAY APPEAR. TestRootSuffixIsNotHardcoded
// greps the package -- tests included -- and fails the build on any other
// occurrence. That is not tidiness: a literal scattered through the code is a
// literal somebody has to find and change correctly under pressure, and E8.2
// requires this constant to be switchable with the whole suite still passing.
const RootSuffix = "axon"

// Label length bounds (§11.3.1).
//
// Namespace labels are held tighter than registrable ones: at most 24 because
// they are typed constantly and appear in every name beneath them, at least 3
// because one- and two-character labels are ineligible under §11.0.2 anyway.
const (
	MinNamespaceLen   = 3
	MaxNamespaceLen   = 24
	MinRegistrableLen = 3
	MaxRegistrableLen = 63
	MinSubordinateLen = 1
	MaxSubordinateLen = 63

	// MaxNameBytes and MaxLabels bound the whole name: at most 5 levels below
	// the registrable label once the namespace and root suffix are counted.
	MaxNameBytes = 253
	MaxLabels    = 8
)

// ZoneIDLabel is the domain-separation prefix for the off-chain zone id.
const ZoneIDLabel = "AXON-zone-v1"

// reserved labels, refused as namespace or registrable labels.
//
// Held here rather than in a database because §12.3 puts the same set in the
// registry contract's constructor with no setter -- the set is immutable and
// verifiable from storage, and this copy must agree with it.
//
// RootSuffix is included by construction rather than by being typed again.
//
// BUILT IN A FUNCTION, NOT A MAP LITERAL. A literal with both "test" and
// RootSuffix as keys is a COMPILE ERROR when RootSuffix is "test" -- Go rejects
// duplicate constant keys -- and E8.2 names exactly that value as the one to try.
// The first version was a literal and did not build under the criterion meant to
// check it, which is a small demonstration of why the criterion exists.
var reserved = buildReserved()

func buildReserved() map[string]struct{} {
	m := make(map[string]struct{}, 8)
	for _, l := range []string{
		"key", "srv", "local", "test", "invalid", "example",
		// The root itself is never a registrable or namespace label.
		RootSuffix,
	} {
		m[l] = struct{}{}
	}
	return m
}

// IsReserved reports whether a label may not be registered.
//
// Labels beginning with "_" are reserved as a class, for the same reason DNS
// reserves them: they are where protocols put things that are not names.
func IsReserved(label string) bool {
	if label == "" {
		return true
	}
	if label[0] == '_' {
		return true
	}
	_, ok := reserved[label]
	return ok
}

// RecordTTL is how long a resolved name may be cached. Stated here so the
// resolver (P10) cannot invent its own.
const RecordTTL = 6 * time.Hour
