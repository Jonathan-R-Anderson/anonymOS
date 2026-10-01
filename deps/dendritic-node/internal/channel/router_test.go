package channel

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

var rNow = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func testRouter() *Router {
	return NewRouter(RouterPolicy{
		MinTimelockMargin: 10 * time.Minute, MaxInFlight: 3,
	}, DeriveKey(seedA))
}

// Build a packet whose hop 0 belongs to `shared`.
func routedPacket(t *testing.T, outgoing, packetExpiry time.Time) (*Packet, [32]byte) {
	t.Helper()
	shared := [32]byte{0xa1}
	hops := []HopInstruction{{
		NextHop: "next", OutgoingCommitment: Commitment{1},
		OutgoingExpiry: uint64(outgoing.Unix()),
	}}
	p, err := Build([32]byte{0xee}, hops, [][32]byte{shared})
	if err != nil {
		t.Fatal(err)
	}
	p.Expiry = uint64(packetExpiry.Unix())
	return p, shared
}

func TestForwardsAValidHop(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	onward, lock, err := r.Forward(p, shared, 1000, rNow)
	if err != nil {
		t.Fatal(err)
	}
	if onward == nil || len(onward.Slots) != MaxHops {
		t.Fatal("onward packet malformed")
	}
	if onward.Expiry != uint64(rNow.Add(30*time.Minute).Unix()) {
		t.Error("onward expiry was not set from the hop instruction")
	}
	if lock.Expiry.IsZero() {
		t.Error("no lock recorded")
	}
}

// THE retention property. A router must not be able to hold what the onion
// exists to hide — checked against the type's FIELDS, so adding a cache is a
// visible act with a failing test attached.
func TestRouterCannotRetainRouteData(t *testing.T) {
	forbidden := []string{"NextHop", "Instruction", "Route", "Predecessor",
		"Secret", "Shared", "Packet", "Onion"}
	for _, typ := range []reflect.Type{reflect.TypeOf(Router{}), reflect.TypeOf(InFlight{})} {
		for i := 0; i < typ.NumField(); i++ {
			name := typ.Field(i).Name
			for _, bad := range forbidden {
				if strings.Contains(name, bad) {
					t.Errorf("%s has field %q — a router may not retain route data",
						typ.Name(), name)
				}
			}
		}
	}
}

// The onward packet must be the same size as what arrived, or this router's
// position is inferable downstream.
func TestOnwardPacketIsTheSameSize(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	before := p.Size()
	onward, _, err := r.Forward(p, shared, 1000, rNow)
	if err != nil {
		t.Fatal(err)
	}
	if onward.Size() != before {
		t.Fatalf("size changed %d -> %d", before, onward.Size())
	}
}

// The margin is the room to claim upstream after paying downstream — the one
// routing failure that actually loses money.
func TestRefusesInsufficientTimelockMargin(t *testing.T) {
	r := testRouter()
	// Only 1 minute between outgoing and incoming; policy demands 10.
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(31*time.Minute))
	if _, _, err := r.Forward(p, shared, 1000, rNow); !errors.Is(err, ErrExpiryTooTight) {
		t.Fatalf("got %v, want ErrExpiryTooTight", err)
	}
}

func TestRefusesAnAlreadyExpiredHop(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(-time.Minute), rNow.Add(time.Hour))
	if _, _, err := r.Forward(p, shared, 1000, rNow); !errors.Is(err, ErrExpiredHop) {
		t.Fatalf("got %v, want ErrExpiredHop", err)
	}
}

func TestRefusesWithoutLiquidity(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	if _, _, err := r.Forward(p, shared, 0, rNow); !errors.Is(err, ErrNoLiquidity) {
		t.Fatalf("got %v, want ErrNoLiquidity", err)
	}
}

// A payment already forwarded must never be forwarded again — including after
// its lock resolves, or replay is possible one second later.
func TestReplayIsRefusedEvenAfterTheLockResolves(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	_, lock, err := r.Forward(p, shared, 1000, rNow)
	if err != nil {
		t.Fatal(err)
	}
	p2, _ := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	if _, _, err := r.Forward(p2, shared, 1000, rNow); !errors.Is(err, ErrReplayed) {
		t.Fatalf("got %v, want ErrReplayed", err)
	}
	r.Resolve(lock.ReplayGuard)
	if _, _, err := r.Forward(p2, shared, 1000, rNow); !errors.Is(err, ErrReplayed) {
		t.Fatal("a resolved payment became forwardable again")
	}
}

// The jamming defence: a peer opening locks it never settles must not be able
// to consume this router's capacity indefinitely.
func TestInFlightCapIsEnforcedAndReleasable(t *testing.T) {
	r := NewRouter(RouterPolicy{MinTimelockMargin: time.Minute, MaxInFlight: 2}, DeriveKey(seedA))
	var guards [][32]byte
	for i := 0; i < 2; i++ {
		shared := [32]byte{byte(i + 1)}
		hops := []HopInstruction{{OutgoingExpiry: uint64(rNow.Add(30 * time.Minute).Unix())}}
		p, _ := Build([32]byte{byte(i + 100)}, hops, [][32]byte{shared})
		p.Expiry = uint64(rNow.Add(time.Hour).Unix())
		_, lock, err := r.Forward(p, shared, 1000, rNow)
		if err != nil {
			t.Fatalf("hop %d: %v", i, err)
		}
		guards = append(guards, lock.ReplayGuard)
	}
	// Third must be refused.
	shared := [32]byte{0x33}
	hops := []HopInstruction{{OutgoingExpiry: uint64(rNow.Add(30 * time.Minute).Unix())}}
	p, _ := Build([32]byte{0x99}, hops, [][32]byte{shared})
	p.Expiry = uint64(rNow.Add(time.Hour).Unix())
	if _, _, err := r.Forward(p, shared, 1000, rNow); !errors.Is(err, ErrTooManyInFlight) {
		t.Fatalf("got %v, want ErrTooManyInFlight", err)
	}
	r.Resolve(guards[0])
	if _, _, err := r.Forward(p, shared, 1000, rNow); err != nil {
		t.Fatalf("capacity did not free after resolving: %v", err)
	}
}

// Stale locks must expire, or one silent downstream hop fills the cap forever.
func TestStaleLocksExpire(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	if _, _, err := r.Forward(p, shared, 1000, rNow); err != nil {
		t.Fatal(err)
	}
	if n := r.ExpireStale(rNow); n != 0 {
		t.Errorf("expired %d live locks", n)
	}
	if n := r.ExpireStale(rNow.Add(2 * time.Hour)); n != 1 {
		t.Errorf("expired %d, want 1", n)
	}
	if len(r.Outstanding()) != 0 {
		t.Error("a stale lock survived expiry")
	}
}

// A packet not addressed to this router must be refused, not forwarded blind.
func TestPacketForAnotherRouterIsRefused(t *testing.T) {
	r := testRouter()
	p, _ := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	if _, _, err := r.Forward(p, [32]byte{0xff}, 1000, rNow); !errors.Is(err, ErrNotForUs) {
		t.Fatalf("got %v, want ErrNotForUs", err)
	}
}

// Counters are aggregate only — they say what an operator needs and identify
// nobody.
func TestCountersAreAggregateOnly(t *testing.T) {
	r := testRouter()
	p, shared := routedPacket(t, rNow.Add(30*time.Minute), rNow.Add(time.Hour))
	_, _, _ = r.Forward(p, shared, 1000, rNow)
	_, _, _ = r.Forward(p, [32]byte{0xff}, 1000, rNow)
	if r.Forwarded != 1 || r.Refused != 1 {
		t.Errorf("forwarded=%d refused=%d", r.Forwarded, r.Refused)
	}
}
