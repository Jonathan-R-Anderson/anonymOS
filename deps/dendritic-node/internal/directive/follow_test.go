package directive

import (
	"sort"
	"testing"
)

func TestRewriteOriginFollowsTheOldOrigin(t *testing.T) {
	known := []string{"rabbiit.io"}
	cases := map[string]string{
		"https://rabbiit.io/api/v1/gateways":                    "https://rabbiit.net/api/v1/gateways",
		"https://rabbiit.io":                                    "https://rabbiit.net",
		"https://rabbiit.io/.well-known/rabbiit/network.json": "https://rabbiit.net/.well-known/rabbiit/network.json",
		"http://rabbiit.io/x?a=1&b=2":                           "http://rabbiit.net/x?a=1&b=2",
	}
	for input, want := range cases {
		got, changed := RewriteOrigin(input, known, "rabbiit.net")
		if !changed || got != want {
			t.Fatalf("%s -> %s (changed=%v), want %s", input, got, changed, want)
		}
	}
}

func TestRewriteOriginLeavesUnrelatedHostsAlone(t *testing.T) {
	// A config can legitimately name hosts that are nothing to do with the
	// origin. Rewriting them because something else moved would redirect an
	// operator's deliberate choice to a host they never named.
	known := []string{"rabbiit.io"}
	for _, input := range []string{
		"https://my-own-registry.example/api",
		"http://127.0.0.1:9090/",
		"https://gw3.rabbiit.io/", // a gateway subdomain is not the origin
		"https://notrabbiit.io/x", // substring, not the host
		"https://rabbiit.io.evil.example/x",
	} {
		got, changed := RewriteOrigin(input, known, "rabbiit.net")
		if changed {
			t.Fatalf("%s was rewritten to %s", input, got)
		}
	}
}

func TestRewriteOriginDropsAStalePort(t *testing.T) {
	// Carrying :8443 from the old origin to a new one that does not listen
	// there produces a connection failure nobody would think to look for.
	got, changed := RewriteOrigin("https://rabbiit.io:8443/api",
		[]string{"rabbiit.io"}, "rabbiit.net")
	if !changed || got != "https://rabbiit.net/api" {
		t.Fatalf("got %q (changed=%v)", got, changed)
	}
}

func TestRewriteOriginIsIdempotent(t *testing.T) {
	// The node applies this on every start. A URL already pointing at the new
	// domain must not be reported as a change, or every restart logs a move
	// that is not happening.
	_, changed := RewriteOrigin("https://rabbiit.net/api",
		[]string{"rabbiit.io", "rabbiit.net"}, "rabbiit.net")
	if changed {
		t.Fatal("rewriting an already-current URL reported a change")
	}
}

func TestRewriteOriginHandlesJunk(t *testing.T) {
	for _, input := range []string{"", "not a url", "://", "/relative/path"} {
		if _, changed := RewriteOrigin(input, []string{"rabbiit.io"}, "rabbiit.net"); changed {
			t.Fatalf("%q was rewritten", input)
		}
	}
	if _, changed := RewriteOrigin("https://rabbiit.io/x", []string{"rabbiit.io"}, ""); changed {
		t.Fatal("an empty new domain rewrote something")
	}
}

func TestKnownOriginsKeepsTheInstallTimeHost(t *testing.T) {
	// A node that dropped its install-time origin after one move could never
	// follow a directive moving the network BACK -- the ordinary outcome of a
	// registrar dispute being resolved.
	got := KnownOrigins("https://rabbiit.io", []string{"rabbiit.net", "rabbiit.net"})
	sort.Strings(got)
	if len(got) != 2 || got[0] != "rabbiit.io" || got[1] != "rabbiit.net" {
		t.Fatalf("got %v", got)
	}
}

func TestKnownOriginsAcceptsBareDomainsAndURLs(t *testing.T) {
	got := KnownOrigins("rabbiit.io", []string{"https://rabbiit.net/api/v1/gateways"})
	sort.Strings(got)
	if len(got) != 2 || got[0] != "rabbiit.io" || got[1] != "rabbiit.net" {
		t.Fatalf("got %v", got)
	}
}

func TestPlanListsWhatWouldChange(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "rabbiit.net"}
	plan := Plan(held, []string{"rabbiit.io"}, map[string]string{
		"gateway registration": "https://rabbiit.io/api/v1/gateways",
		"validator origin":     "https://rabbiit.io",
		"management page":      "http://127.0.0.1:9090/",
	})
	if len(plan) != 2 {
		t.Fatalf("expected 2 changes, got %d: %+v", len(plan), plan)
	}
	for _, entry := range plan {
		if entry.From == entry.To {
			t.Fatalf("a no-op was reported as a change: %+v", entry)
		}
		if HostOf(entry.To) != "rabbiit.net" {
			t.Fatalf("wrong target: %+v", entry)
		}
	}
}

func TestPlanIsEmptyForNonMoves(t *testing.T) {
	// A freeze pins the network where it is. Reading it as a move to nowhere
	// would blank every origin URL on the node.
	urls := map[string]string{"validator origin": "https://rabbiit.io"}
	for _, held := range []*Directive{
		nil,
		{Kind: KindFreeze, Sequence: 3},
		{Kind: KindResume, Sequence: 4},
		{Kind: KindMove, Sequence: 5}, // a move with no domain
	} {
		if plan := Plan(held, []string{"rabbiit.io"}, urls); len(plan) != 0 {
			t.Fatalf("%+v produced a plan: %+v", held, plan)
		}
	}
}
