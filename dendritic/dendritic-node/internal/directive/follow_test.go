package directive

import (
	"sort"
	"testing"
)

func TestRewriteOriginFollowsTheOldOrigin(t *testing.T) {
	known := []string{"syndichan.org"}
	cases := map[string]string{
		"https://syndichan.org/api/v1/gateways":                    "https://syndichan.net/api/v1/gateways",
		"https://syndichan.org":                                    "https://syndichan.net",
		"https://syndichan.org/.well-known/syndichan/network.json": "https://syndichan.net/.well-known/syndichan/network.json",
		"http://syndichan.org/x?a=1&b=2":                           "http://syndichan.net/x?a=1&b=2",
	}
	for input, want := range cases {
		got, changed := RewriteOrigin(input, known, "syndichan.net")
		if !changed || got != want {
			t.Fatalf("%s -> %s (changed=%v), want %s", input, got, changed, want)
		}
	}
}

func TestRewriteOriginLeavesUnrelatedHostsAlone(t *testing.T) {
	// A config can legitimately name hosts that are nothing to do with the
	// origin. Rewriting them because something else moved would redirect an
	// operator's deliberate choice to a host they never named.
	known := []string{"syndichan.org"}
	for _, input := range []string{
		"https://my-own-registry.example/api",
		"http://127.0.0.1:9090/",
		"https://gw3.syndichan.org/", // a gateway subdomain is not the origin
		"https://notsyndichan.org/x", // substring, not the host
		"https://syndichan.org.evil.example/x",
	} {
		got, changed := RewriteOrigin(input, known, "syndichan.net")
		if changed {
			t.Fatalf("%s was rewritten to %s", input, got)
		}
	}
}

func TestRewriteOriginDropsAStalePort(t *testing.T) {
	// Carrying :8443 from the old origin to a new one that does not listen
	// there produces a connection failure nobody would think to look for.
	got, changed := RewriteOrigin("https://syndichan.org:8443/api",
		[]string{"syndichan.org"}, "syndichan.net")
	if !changed || got != "https://syndichan.net/api" {
		t.Fatalf("got %q (changed=%v)", got, changed)
	}
}

func TestRewriteOriginIsIdempotent(t *testing.T) {
	// The node applies this on every start. A URL already pointing at the new
	// domain must not be reported as a change, or every restart logs a move
	// that is not happening.
	_, changed := RewriteOrigin("https://syndichan.net/api",
		[]string{"syndichan.org", "syndichan.net"}, "syndichan.net")
	if changed {
		t.Fatal("rewriting an already-current URL reported a change")
	}
}

func TestRewriteOriginHandlesJunk(t *testing.T) {
	for _, input := range []string{"", "not a url", "://", "/relative/path"} {
		if _, changed := RewriteOrigin(input, []string{"syndichan.org"}, "syndichan.net"); changed {
			t.Fatalf("%q was rewritten", input)
		}
	}
	if _, changed := RewriteOrigin("https://syndichan.org/x", []string{"syndichan.org"}, ""); changed {
		t.Fatal("an empty new domain rewrote something")
	}
}

func TestKnownOriginsKeepsTheInstallTimeHost(t *testing.T) {
	// A node that dropped its install-time origin after one move could never
	// follow a directive moving the network BACK -- the ordinary outcome of a
	// registrar dispute being resolved.
	got := KnownOrigins("https://syndichan.org", []string{"syndichan.net", "syndichan.net"})
	sort.Strings(got)
	if len(got) != 2 || got[0] != "syndichan.net" || got[1] != "syndichan.org" {
		t.Fatalf("got %v", got)
	}
}

func TestKnownOriginsAcceptsBareDomainsAndURLs(t *testing.T) {
	got := KnownOrigins("syndichan.org", []string{"https://syndichan.net/api/v1/gateways"})
	sort.Strings(got)
	if len(got) != 2 || got[0] != "syndichan.net" || got[1] != "syndichan.org" {
		t.Fatalf("got %v", got)
	}
}

func TestPlanListsWhatWouldChange(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 3, OriginDomain: "syndichan.net"}
	plan := Plan(held, []string{"syndichan.org"}, map[string]string{
		"gateway registration": "https://syndichan.org/api/v1/gateways",
		"validator origin":     "https://syndichan.org",
		"management page":      "http://127.0.0.1:9090/",
	})
	if len(plan) != 2 {
		t.Fatalf("expected 2 changes, got %d: %+v", len(plan), plan)
	}
	for _, entry := range plan {
		if entry.From == entry.To {
			t.Fatalf("a no-op was reported as a change: %+v", entry)
		}
		if HostOf(entry.To) != "syndichan.net" {
			t.Fatalf("wrong target: %+v", entry)
		}
	}
}

func TestPlanIsEmptyForNonMoves(t *testing.T) {
	// A freeze pins the network where it is. Reading it as a move to nowhere
	// would blank every origin URL on the node.
	urls := map[string]string{"validator origin": "https://syndichan.org"}
	for _, held := range []*Directive{
		nil,
		{Kind: KindFreeze, Sequence: 3},
		{Kind: KindResume, Sequence: 4},
		{Kind: KindMove, Sequence: 5}, // a move with no domain
	} {
		if plan := Plan(held, []string{"syndichan.org"}, urls); len(plan) != 0 {
			t.Fatalf("%+v produced a plan: %+v", held, plan)
		}
	}
}
