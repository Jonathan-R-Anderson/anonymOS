package padding

import (
	"bytes"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

var t0 = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// fixed returns a deterministic uniform stream cycling through vs.
func fixed(vs ...float64) func() float64 {
	i := 0
	return func() float64 {
		v := vs[i%len(vs)]
		i++
		return v
	}
}

// TestM6aKeepaliveFiresOnIdleAndResetsOnReal is M6a.
func TestM6aKeepaliveFiresOnIdleAndResetsOnReal(t *testing.T) {
	// u = 0.5 puts every keepalive at the midpoint of [1.5 s, 9.5 s] = 5.5 s.
	m := New(RoleRelay, true, t0, fixed(0.5))
	mid := params.KeepaliveMin + (params.KeepaliveMax-params.KeepaliveMin)/2

	if n := m.Due(t0.Add(mid - time.Millisecond)); n != 0 {
		t.Fatalf("padding due %d cells before the interval elapsed", n)
	}
	if n := m.Due(t0.Add(mid)); n != 1 {
		t.Fatalf("keepalive emitted %d cells at the deadline, want 1", n)
	}

	// A real cell resets the schedule: the next keepalive is measured from it,
	// not from the previous deadline.
	realAt := t0.Add(mid + time.Second)
	m.Real(realAt)
	if n := m.Due(realAt.Add(mid - time.Millisecond)); n != 0 {
		t.Fatal("a real cell did not reset the keepalive")
	}
	if n := m.Due(realAt.Add(mid)); n != 1 {
		t.Fatalf("keepalive did not re-arm after a real cell (%d)", n)
	}
}

// TestM6aIntervalIsRandomNotAMetronome is the distinguisher this package's own
// doc names.
//
// A fixed keepalive interval is a metronome, and a metronome's phase identifies
// the link that beats it for as long as the link lives. Draws must differ.
func TestM6aIntervalIsRandomNotAMetronome(t *testing.T) {
	m := New(RoleRelay, true, t0, nil) // crypto/rand, the production source
	seen := map[time.Duration]int{}
	at := t0
	for i := 0; i < 500; i++ {
		d := m.Deadline(at)
		gap := d.Sub(at)
		if gap < params.KeepaliveMin || gap > params.KeepaliveMax {
			t.Fatalf("keepalive gap %v outside [%v, %v]", gap, params.KeepaliveMin, params.KeepaliveMax)
		}
		seen[gap]++
		at = d
		m.Due(at)
	}
	if len(seen) < 400 {
		t.Fatalf("500 keepalives produced only %d distinct intervals -- the schedule is a metronome",
			len(seen))
	}
}

// TestM6bFloorIsContinuousAndHoldsTheRate is M6b.
//
// This test used to be TestM6bFloorHoldsTheRateAndThenStops, and the name was
// the bug. §16.3's table reads as though the floor switches off 5-30 s after
// the last real cell; its prose and its 6.4 GB/month cost figure both describe a
// floor that never stops. Under the switch reading an idle daemon runs at M6a's
// 0.18 cells/s and a trickling one at 0.5, which are trivially separable -- and
// separating exactly those two is the property §16.3 claims the mechanism buys.
// See Machine.floorActive for the ruling.
func TestM6bFloorIsContinuousAndHoldsTheRate(t *testing.T) {
	m := New(RoleGuardLink, true, t0, nil)
	interval := time.Duration(float64(time.Second) / params.FloorRateCellsPerSec)
	if interval != 2*time.Second {
		t.Fatalf("floor interval is %v, want 2s at R_floor=%v", interval, params.FloorRateCellsPerSec)
	}

	// No real traffic at all, for five minutes. The floor must still be running
	// at the end of it.
	at := t0
	for end := t0.Add(5 * time.Minute); at.Before(end); at = at.Add(250 * time.Millisecond) {
		m.Due(at)
	}
	rate := float64(m.Stats().Padding) / (5 * time.Minute).Seconds()
	if math.Abs(rate-params.FloorRateCellsPerSec) > 0.1*params.FloorRateCellsPerSec {
		t.Fatalf("an idle guard link ran at %.4f cells/s, not the %.2f floor",
			rate, params.FloorRateCellsPerSec)
	}
	if !m.floorActive(at) {
		t.Fatal("the floor stopped on an idle link")
	}
}

// TestFloorEpochRollsSoTheEndOfActivityIsNotMarked is what the U(5 s, 30 s)
// draw is actually for.
//
// The deficit is measured within an epoch. A burst of real traffic leaves the
// machine in credit; if the epoch never rolled, the link would then stay quiet
// for exactly as long as the burst was large -- which marks the end of the burst
// precisely, in a mechanism whose stated purpose is to blur it.
func TestFloorEpochRollsSoTheEndOfActivityIsNotMarked(t *testing.T) {
	m := New(RoleGuardLink, true, t0, nil)

	// A burst: 200 real cells in 5 s, forty times the floor.
	at := t0
	for i := 0; i < 200; i++ {
		at = at.Add(25 * time.Millisecond)
		m.Real(at)
		m.Due(at)
	}
	burstEnd := at
	before := m.Stats().Padding

	// The two minutes after the burst must run at the floor, not in credit.
	// In credit, 200 cells of surplus would buy 400 s of silence.
	for end := burstEnd.Add(2 * time.Minute); at.Before(end); at = at.Add(250 * time.Millisecond) {
		m.Due(at)
	}
	after := float64(m.Stats().Padding-before) / (2 * time.Minute).Seconds()
	if after < 0.5*params.FloorRateCellsPerSec {
		t.Fatalf("after a burst the link ran at %.4f cells/s -- the epoch did not roll "+
			"and the credit is marking the end of activity", after)
	}
}

// TestRealCellsCountTowardTheFloor is §16.3's "real cells count toward the
// floor".
//
// A machine that emitted its floor ON TOP of real traffic would double the cost
// of an active link and, worse, make the total rate a function of the real rate
// — which is the leak the floor exists to hide.
func TestRealCellsCountTowardTheFloor(t *testing.T) {
	m := New(RoleGuardLink, true, t0, fixed(0.99)) // long tail
	at := t0
	// Real traffic at 4 cells/s, well above the 0.5 floor, for 10 s.
	for i := 0; i < 40; i++ {
		at = at.Add(250 * time.Millisecond)
		m.Real(at)
		m.Due(at)
	}
	if p := m.Stats().Padding; p != 0 {
		t.Fatalf("%d padding cells emitted while real traffic exceeded the floor", p)
	}
}

// TestFloorIsGuardLinkOnly checks that a relay-role machine never runs M6b.
//
// §16.3 scopes the floor to client↔guard. Running it on every relay↔relay link
// multiplies its cost by the number of links in the network while defending an
// observation point only the client has.
func TestFloorIsGuardLinkOnly(t *testing.T) {
	relay := New(RoleRelay, true, t0, fixed(0.99))
	guard := New(RoleGuardLink, true, t0, fixed(0.99))
	relay.Real(t0)
	guard.Real(t0)

	at := t0.Add(20 * time.Second)
	relay.Due(at)
	guard.Due(at)
	if relay.Stats().Padding >= guard.Stats().Padding {
		t.Fatalf("relay link emitted %d padding cells, guard link %d -- the floor is not guard-only",
			relay.Stats().Padding, guard.Stats().Padding)
	}
}

// TestT133DisablingIsOneVisibleBit is T13.3.
func TestT133DisablingIsOneVisibleBit(t *testing.T) {
	if !params.PaddingEnabledByDefault {
		t.Fatal("T13.3 violated: padding is not on by default")
	}
	off := New(RoleGuardLink, false, t0, fixed(0.5))
	off.Real(t0)
	if off.Enabled() {
		t.Fatal("a disabled machine reports enabled")
	}
	if !off.Deadline(t0).IsZero() {
		t.Fatal("a disabled machine still schedules padding")
	}
	if n := off.Due(t0.Add(time.Hour)); n != 0 {
		t.Fatalf("a disabled machine emitted %d padding cells", n)
	}
	// And there is no third state: the constructor takes a bool, so a partially
	// padded machine is not expressible.
	on := New(RoleGuardLink, true, t0, fixed(0.5))
	if !on.Enabled() {
		t.Fatal("an enabled machine reports disabled")
	}
}

// TestStalledWriterDoesNotEmitABurst covers maxCatchUp.
//
// A writer blocked for an hour owes an hour of floor. Emitting it is a burst,
// and a burst is exactly the kind of structure link padding exists to remove.
func TestStalledWriterDoesNotEmitABurst(t *testing.T) {
	m := New(RoleGuardLink, true, t0, fixed(0.99))
	m.Real(t0)
	n := m.Due(t0.Add(time.Hour))
	if n > maxCatchUp+1 {
		t.Fatalf("a one-hour stall produced a burst of %d cells", n)
	}
	// And the machine resynchronises rather than staying an hour in arrears.
	if d := m.Deadline(t0.Add(time.Hour)); !d.After(t0.Add(time.Hour)) {
		t.Fatalf("machine still in arrears after catch-up: deadline %v", d)
	}
}

// ---------------------------------------------------------------------------
// M2 — fixed datagrams
// ---------------------------------------------------------------------------

func TestM2DatagramIsAlwaysTheSameSize(t *testing.T) {
	for _, n := range []int{0, 1, 44, 1024, MaxDatagramPayload} {
		d, err := PackDatagram(make([]byte, n))
		if err != nil {
			t.Fatalf("payload %d: %v", n, err)
		}
		if len(d) != params.DatagramSize {
			t.Fatalf("payload %d produced a %d-byte datagram", n, len(d))
		}
		back, err := UnpackDatagram(d)
		if err != nil {
			t.Fatalf("round trip %d: %v", n, err)
		}
		if len(back) != n {
			t.Fatalf("round trip %d returned %d bytes", n, len(back))
		}
	}
	if _, err := PackDatagram(make([]byte, MaxDatagramPayload+1)); !errors.Is(err, ErrDatagramTooLarge) {
		t.Fatalf("oversize payload gave %v", err)
	}
}

// TestM2PaddingIsZeroAndCarriesNothing is the covert-channel check.
func TestM2PaddingIsZeroAndCarriesNothing(t *testing.T) {
	d, err := PackDatagram([]byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	tail := d[DatagramHeaderSize+5:]
	if !bytes.Equal(tail, make([]byte, len(tail))) {
		t.Fatal("padding region is not zero")
	}

	// A peer that hides data in the padding must be refused, not tolerated:
	// free capacity in a fixed frame is a covert channel of exactly that width.
	d[len(d)-1] = 1
	if _, err := UnpackDatagram(d); err == nil {
		t.Fatal("a datagram with data hidden in its padding was accepted")
	}

	// A short datagram is refused too. Accepting one would let a peer choose its
	// own packet lengths, which is the leak M2 removes.
	if _, err := UnpackDatagram(d[:params.DatagramSize-1]); err != nil {
		if err.Error() == "" {
			t.Fatal("unexpected")
		}
	} else {
		t.Fatal("a short datagram was accepted")
	}

	// A declared length beyond the frame is refused rather than panicking.
	bad, _ := PackDatagram(nil)
	bad[0], bad[1] = 0xff, 0xff
	if _, err := UnpackDatagram(bad); err == nil {
		t.Fatal("a datagram declaring 65535 bytes of payload was accepted")
	}
}

// TestM1FitsInsideM2 checks the two mechanisms compose.
//
// If a cell did not fit one datagram, M2 would split it and the cell boundary
// would be visible in packet lengths again — the exact leak §16.8's first row
// says the datagram padding exists to close.
func TestM1FitsInsideM2(t *testing.T) {
	if params.CellSize > MaxDatagramPayload {
		t.Fatalf("a %d-byte cell does not fit a %d-byte datagram payload",
			params.CellSize, MaxDatagramPayload)
	}
	// And the arithmetic §16.8 quotes: +30.1 % over payload including IPv4/UDP.
	// 28 bytes of IPv4+UDP header on top of 1200 gives 1228 on the wire against
	// 944 bytes of cell payload.
	overhead := float64(params.DatagramSize+28)/944.0 - 1
	if math.Abs(overhead-0.301) > 0.005 {
		t.Fatalf("derived link overhead %.3f does not match §16.8's 30.1%%", overhead)
	}
}

// TestPaddingSatisfiesTheNATKeepaliveFloor is a cross-section invariant that
// nothing checked until the outstanding-work pass surfaced it.
//
// §6 specifies a **15 s keepalive floor** on the client↔guard link and says the
// link padding cell "doubles as the §16 cover schedule, so it is not extra
// traffic". §16.3 specifies the schedule and never mentions 15 s. The two hold
// together only because M6a's LONGEST possible interval is 9.5 s, which is
// under the floor by construction.
//
// Nothing enforced that. RFC 4787 requires NAT UDP mappings to survive two
// minutes and §6 records that deployed NATs frequently ignore it, with 30 s or
// less being common — so if KeepaliveMax were ever raised past 15 s, NAT
// mappings would start expiring and it would present as random connection loss
// on client links, not as a padding bug. That is a long way from its cause.
func TestPaddingSatisfiesTheNATKeepaliveFloor(t *testing.T) {
	const natFloor = 15 * time.Second // §6's guard-link keepalive

	if params.KeepaliveMax >= natFloor {
		t.Fatalf("§6 violated: M6a's longest interval is %v, at or above the %v NAT "+
			"keepalive floor -- guard-link NAT mappings will expire",
			params.KeepaliveMax, natFloor)
	}
	// The floor is denser still, so a guard link is covered twice over.
	floorGap := time.Duration(float64(time.Second) / params.FloorRateCellsPerSec)
	if floorGap >= natFloor {
		t.Fatalf("§6 violated: M6b's floor interval is %v, at or above %v", floorGap, natFloor)
	}

	// And empirically, over a long idle run: no gap ever reaches the floor.
	m := New(RoleGuardLink, true, t0, nil)
	at, last := t0, t0
	worst := time.Duration(0)
	for end := t0.Add(30 * time.Minute); at.Before(end); at = at.Add(100 * time.Millisecond) {
		if n := m.Due(at); n > 0 {
			if gap := at.Sub(last); gap > worst {
				worst = gap
			}
			last = at
		}
	}
	if worst >= natFloor {
		t.Fatalf("an idle guard link went %v without a cell, at or above the %v floor", worst, natFloor)
	}
	t.Logf("§6 keepalive: worst observed idle gap %v over 30 min, floor %v", worst.Round(time.Millisecond), natFloor)
}
