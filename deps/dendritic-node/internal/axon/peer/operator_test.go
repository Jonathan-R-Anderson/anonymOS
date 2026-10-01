package peer

import (
	"errors"
	"net/netip"
	"testing"
)

func opID(b byte) OperatorID {
	var o OperatorID
	for i := range o {
		o[i] = b
	}
	return o
}

// fakeChain is a stand-in for the light-client-backed registry lookup.
type fakeChain struct {
	owners map[string]OperatorID
	err    error
}

func (f *fakeChain) Operator(nodeID string) (OperatorID, bool, error) {
	if f.err != nil {
		return OperatorUnknown, false, f.err
	}
	o, ok := f.owners[nodeID]
	return o, ok, nil
}

func annAt(t *testing.T, s string) Annotation {
	t.Helper()
	a, err := Annotate(netip.MustParseAddr(s))
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// TestT12b4UnknownOperatorsAreDistinct is T12b.4.
//
// The failure it prevents is the flattering one: treating "we do not know who
// owns either of these" as "these have the same owner" would make a network
// with no chain access look like a network owned by one person, and every path
// would be refused. Treating it as "distinct" is the conservative direction —
// paths are built and the report says the rung could not be applied.
func TestT12b4UnknownOperatorsAreDistinct(t *testing.T) {
	a := annAt(t, "10.1.0.1")
	b := annAt(t, "10.2.0.1")
	if a.Operator != OperatorUnknown || b.Operator != OperatorUnknown {
		t.Fatal("a fresh annotation has a non-zero operator")
	}
	if SameDomain(a, b, DomainOperator) {
		t.Fatal("T12b.4 violated: two unknown operators compared equal")
	}
	// One known, one unknown, is also not the same.
	a.Operator, a.OperatorSource = opID(1), OperatorSourceChain
	if SameDomain(a, b, DomainOperator) {
		t.Fatal("T12b.4 violated: a known operator matched an unknown one")
	}
	// Two known and equal IS the same.
	b.Operator, b.OperatorSource = opID(1), OperatorSourceChain
	if !SameDomain(a, b, DomainOperator) {
		t.Fatal("two relays with the same verified owner compared distinct")
	}
	// Equal owner but UNVERIFIED provenance is not the same, because an
	// unverified owner is not a fact about ownership at all.
	b.OperatorSource = OperatorSourceNone
	if SameDomain(a, b, DomainOperator) {
		t.Fatal("an unverified owner was accepted as a match")
	}
}

// TestT12b3DeclaredOwnerMustMatchTheChain is T12b.3.
func TestT12b3DeclaredOwnerMustMatchTheChain(t *testing.T) {
	chain := &fakeChain{owners: map[string]OperatorID{"n1": opID(7)}}

	// Agreeing declaration: accepted, sourced from the chain.
	d := opID(7)
	got, src, err := ResolveOperator("n1", &d, chain)
	if err != nil || src != OperatorSourceChain || got != opID(7) {
		t.Fatalf("agreeing declaration: %v %v %v", got, src, err)
	}

	// No declaration at all: the chain still answers.
	got, src, err = ResolveOperator("n1", nil, chain)
	if err != nil || src != OperatorSourceChain || got != opID(7) {
		t.Fatalf("undeclared: %v %v %v", got, src, err)
	}

	// Disagreeing declaration: REFUSED, and not silently corrected to the
	// chain's answer. A relay whose descriptor claims somebody else's identity
	// is not a relay to route through while quietly fixing the paperwork.
	wrong := opID(9)
	got, src, err = ResolveOperator("n1", &wrong, chain)
	if !errors.Is(err, ErrOperatorMismatch) {
		t.Fatalf("T12b.3 violated: mismatched declaration gave %v (owner %v, source %v)", err, got, src)
	}
	if got != OperatorUnknown || src != OperatorSourceNone {
		t.Fatalf("T12b.3 violated: refusal still produced owner %v source %v", got, src)
	}
}

// TestOperatorDegradesToUnknownNotToEqual covers the chain-outage failure mode
// P12b names: every operator becoming unknown at once.
func TestOperatorDegradesToUnknownNotToEqual(t *testing.T) {
	// No resolver at all — a node with no chain access.
	got, src, err := ResolveOperator("n1", nil, nil)
	if err != nil || got != OperatorUnknown || src != OperatorSourceNone {
		t.Fatalf("nil resolver: %v %v %v", got, src, err)
	}

	// Resolver present but failing.
	boom := errors.New("light client offline")
	got, src, err = ResolveOperator("n1", nil, &fakeChain{err: boom})
	if !errors.Is(err, boom) {
		t.Fatalf("outage swallowed: %v", err)
	}
	if got != OperatorUnknown || src != OperatorSourceNone {
		t.Fatalf("outage produced owner %v source %v", got, src)
	}

	// Registered nowhere: not an error, just unknown.
	got, src, err = ResolveOperator("nobody", nil, &fakeChain{owners: map[string]OperatorID{}})
	if err != nil || got != OperatorUnknown || src != OperatorSourceNone {
		t.Fatalf("unregistered node: %v %v %v", got, src, err)
	}
}

// TestDomainKeysOmitUnknowns checks the opaque-key rendering the placement
// planner consumes.
//
// An unknown domain must produce NO KEY rather than a placeholder like "a:0".
// A placeholder would collide with every other unknown, which is the exact
// equality rule T12b.4 and ASNUnknown forbid — reintroduced by a stringifier.
func TestDomainKeysOmitUnknowns(t *testing.T) {
	a := annAt(t, "10.1.0.1")
	keys := DomainKeys(a)
	if len(keys) != 1 || keys[0] != "p:10.1.0.0/24" {
		t.Fatalf("unknown ASN and operator produced %v", keys)
	}

	a.ASN, a.ASNSource = 64512, ASNSourceOperator
	a.Operator, a.OperatorSource = opID(3), OperatorSourceChain
	keys = DomainKeys(a)
	if len(keys) != 3 {
		t.Fatalf("fully known annotation produced %v", keys)
	}

	// Two annotations that are both unknown everywhere but the prefix share no
	// key beyond the prefix, so a key-based planner cannot conclude they are
	// co-located in an AS or an operator.
	x, y := annAt(t, "10.1.0.1"), annAt(t, "10.2.0.1")
	shared := 0
	for _, kx := range DomainKeys(x) {
		for _, ky := range DomainKeys(y) {
			if kx == ky {
				shared++
			}
		}
	}
	if shared != 0 {
		t.Fatalf("two all-unknown annotations shared %d domain keys", shared)
	}
}
