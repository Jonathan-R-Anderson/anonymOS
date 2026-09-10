package directive

import "testing"

func self(hostname string, addresses ...string) Identity {
	return Identity{Hostname: hostname, Addresses: addresses}
}

func TestAddressBeatsDomain(t *testing.T) {
	// Several nodes can legitimately answer for one domain during a move --
	// the old origin, the new one, and whatever DNS still points at. A node
	// concluding it is the origin because it recognises the DOMAIN would have
	// two of them both believing it.
	held := &Directive{Kind: KindMove, Sequence: 5,
		OriginDomain: "syndichan.net", OriginAddress: "203.0.113.9:443"}

	if got := RoleFor(held, self("syndichan.net", "198.51.100.7:443")); got != RoleGateway {
		t.Fatalf("a node answering for the domain but at another address: %s", got)
	}
	if got := RoleFor(held, self("", "203.0.113.9:443")); got != RoleOrigin {
		t.Fatalf("the node AT the named address: %s", got)
	}
}

func TestHostOnlyAddressesStillMatch(t *testing.T) {
	// A node knows itself as "203.0.113.9" while the directive names
	// "203.0.113.9:443". Failing to match those leaves the real origin
	// demoting itself.
	held := &Directive{Kind: KindMove, Sequence: 5, OriginAddress: "203.0.113.9:443"}
	if got := RoleFor(held, self("", "203.0.113.9")); got != RoleOrigin {
		t.Fatalf("got %s", got)
	}
}

func TestIPv6IsNotMangled(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 5, OriginAddress: "[2001:db8::1]:443"}
	if got := RoleFor(held, self("", "2001:db8::1")); got != RoleOrigin {
		t.Fatalf("got %s", got)
	}
	if got := RoleFor(held, self("", "2001:db8::2")); got != RoleGateway {
		t.Fatalf("a different v6 address matched: %s", got)
	}
}

func TestDomainOnlyDirectives(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 5, OriginDomain: "syndichan.net"}
	if got := RoleFor(held, self("syndichan.net")); got != RoleOrigin {
		t.Fatalf("got %s", got)
	}
	if got := RoleFor(held, self("gw3.syndichan.net")); got != RoleGateway {
		t.Fatalf("a gateway subdomain claimed origin: %s", got)
	}
}

func TestUnknownIsNotGateway(t *testing.T) {
	// A node that has never seen a directive must not conclude it has been
	// demoted -- "nothing is pinned" and "somebody else is the origin" are
	// different answers.
	for _, held := range []*Directive{
		nil,
		{Kind: KindFreeze, Sequence: 3},
		{Kind: KindMove, Sequence: 3}, // a move naming neither
	} {
		if got := RoleFor(held, self("syndichan.net", "203.0.113.9")); got != RoleUnknown {
			t.Fatalf("%+v gave %s", held, got)
		}
	}
}

func TestDemotionIsReportedWithAReason(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 9, OriginAddress: "198.51.100.7:443"}
	demotion := CheckDemotion(RoleOrigin, held, self("", "203.0.113.9:443"))
	if demotion == nil {
		t.Fatal("an emergency origin was not told to step down")
	}
	if demotion.Sequence != 9 || demotion.Now != RoleGateway {
		t.Fatalf("%+v", demotion)
	}
	if len(demotion.Why) < 80 {
		t.Fatalf("the reason is not written for a person: %q", demotion.Why)
	}
}

func TestPromotionIsNeverAutomatic(t *testing.T) {
	// Standing a node up as an origin needs a human with a passphrase. A node
	// must never conclude from a directive alone that it has become one --
	// only the step DOWN is safe to do by itself.
	held := &Directive{Kind: KindMove, Sequence: 9, OriginAddress: "203.0.113.9:443"}
	if CheckDemotion(RoleGateway, held, self("", "203.0.113.9:443")) != nil {
		t.Fatal("a gateway was auto-promoted to origin")
	}
}

func TestNoDemotionWhenStillTheOrigin(t *testing.T) {
	held := &Directive{Kind: KindMove, Sequence: 9, OriginAddress: "203.0.113.9:443"}
	if CheckDemotion(RoleOrigin, held, self("", "203.0.113.9:443")) != nil {
		t.Fatal("the current origin was told to step down")
	}
}

func TestNoDemotionOnAFreeze(t *testing.T) {
	// A freeze pins the network where it is. Reading it as "somebody else is
	// the origin" would demote the origin during the one directive whose whole
	// purpose is to change nothing.
	held := &Directive{Kind: KindFreeze, Sequence: 9}
	if CheckDemotion(RoleOrigin, held, self("", "203.0.113.9:443")) != nil {
		t.Fatal("a freeze demoted the origin")
	}
}
