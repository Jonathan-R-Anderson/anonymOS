package dcs

import (
	"context"
	"testing"
	"time"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// The operator's simultaneous cap holds: with 2 slots, a third distinct owner
// is queued rather than run.
func TestSlotCapQueuesBeyondCapacity(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 2, InstanceTTL: 24 * time.Hour})
	ac.now = fixedClock(now)

	// Two owners fill the two slots.
	d1, _ := ac.Admit("owner-a", "")
	d2, _ := ac.Admit("owner-b", "")
	if !d1.Admitted || !d2.Admitted {
		t.Fatal("first two owners should be admitted")
	}
	if err := ac.Started(d1.SlotToken, "ctr-a", now.Add(24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := ac.Started(d2.SlotToken, "ctr-b", now.Add(12*time.Hour)); err != nil {
		t.Fatal(err)
	}

	// A third owner is queued at position 1, with an ETA equal to the SOONEST
	// slot to free (owner-b's 12h instance).
	d3, err := ac.Admit("owner-c", "")
	if err != nil {
		t.Fatal(err)
	}
	if !d3.Queued || d3.Position != 1 {
		t.Fatalf("third owner: queued=%v pos=%d", d3.Queued, d3.Position)
	}
	if d3.ETASeconds != int64((12 * time.Hour).Seconds()) {
		t.Fatalf("ETA = %ds, want %ds (soonest expiry)", d3.ETASeconds, int64((12 * time.Hour).Seconds()))
	}
}

// One instance per owner: the same owner cannot occupy two slots or double-queue.
func TestOneInstancePerOwner(t *testing.T) {
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 4})
	now := time.Unix(1700000000, 0)
	ac.now = fixedClock(now)

	d, _ := ac.Admit("owner-a", "")
	_ = ac.Started(d.SlotToken, "ctr-a", now.Add(time.Hour))

	// Same owner, second request -> refused, even though 3 slots are free.
	if _, err := ac.Admit("owner-a", ""); err != ErrOwnerHasInstance {
		t.Fatalf("second instance for the same owner was not refused: %v", err)
	}
	// A DIFFERENT owner is admitted -- many owners, one worker, is fine.
	if d2, err := ac.Admit("owner-b", ""); err != nil || !d2.Admitted {
		t.Fatalf("a different owner was blocked: %v", err)
	}
}

// The queue advances FIFO: when a slot frees, the head is promoted on its next
// Launch retry and the person behind moves up.
func TestQueueAdvancesFIFO(t *testing.T) {
	now := time.Unix(1700000000, 0)
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 1, InstanceTTL: 10 * time.Hour})
	ac.now = fixedClock(now)

	d1, _ := ac.Admit("owner-a", "")
	_ = ac.Started(d1.SlotToken, "ctr-a", now.Add(10*time.Hour))

	q1, _ := ac.Admit("owner-b", "") // position 1
	q2, _ := ac.Admit("owner-c", "") // position 2
	if q1.Position != 1 || q2.Position != 2 {
		t.Fatalf("queue positions: %d, %d", q1.Position, q2.Position)
	}

	// While the slot is full, retrying does not promote.
	again, _ := ac.Admit("owner-b", q1.Ticket)
	if again.Admitted {
		t.Fatal("head of queue was admitted while the slot was still full")
	}

	// Free the slot; the head (owner-b) is promoted on its next retry.
	ac.Release("ctr-a")
	promoted, err := ac.Admit("owner-b", q1.Ticket)
	if err != nil || !promoted.Admitted {
		t.Fatalf("head of queue was not promoted after a slot freed: %v", err)
	}
	// owner-c moves up to position 1.
	moved, ok := ac.QueueStatus(q2.Ticket)
	if !ok || moved.Position != 1 {
		t.Fatalf("owner-c did not advance: ok=%v pos=%d", ok, moved.Position)
	}
}

// An admitted-but-never-started reservation is reclaimed after its TTL, so a
// crashed client cannot leak a slot forever.
func TestReservationReclaimed(t *testing.T) {
	base := time.Unix(1700000000, 0)
	current := base
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 1, ReservationTTL: time.Minute})
	ac.now = func() time.Time { return current }

	d, _ := ac.Admit("owner-a", "") // reserves the only slot, never starts
	if !d.Admitted {
		t.Fatal("expected admission")
	}
	// Another owner is queued while the reservation holds the slot.
	q, _ := ac.Admit("owner-b", "")
	if !q.Queued {
		t.Fatal("expected queue while reservation holds the slot")
	}
	// Advance past the reservation TTL; the slot is reclaimed and owner-b's
	// retry is promoted.
	current = base.Add(2 * time.Minute)
	promoted, err := ac.Admit("owner-b", q.Ticket)
	if err != nil || !promoted.Admitted {
		t.Fatalf("slot was not reclaimed from a dead reservation: %v", err)
	}
}

// The reaper destroys instances past their TTL, freeing the slot.
func TestReaperSpinsDownExpired(t *testing.T) {
	base := time.Unix(1700000000, 0)
	current := base
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 1, InstanceTTL: 24 * time.Hour})
	ac.now = func() time.Time { return current }

	d, _ := ac.Admit("owner-a", "")
	_ = ac.Started(d.SlotToken, "ctr-a", base.Add(24*time.Hour))

	destroyed := []string{}
	reaper := NewReaper(ac, func(_ context.Context, id string) error {
		destroyed = append(destroyed, id)
		ac.Release(id) // real Destroy releases; mirror that here
		return nil
	}, nil)

	// Before expiry: nothing reaped.
	reaper.sweep(context.Background())
	if len(destroyed) != 0 {
		t.Fatal("reaped an instance before its TTL")
	}
	// After 24h: reaped, and the slot is free again.
	current = base.Add(25 * time.Hour)
	reaper.sweep(context.Background())
	if len(destroyed) != 1 || destroyed[0] != "ctr-a" {
		t.Fatalf("expired instance not reaped: %v", destroyed)
	}
	if next, err := ac.Admit("owner-b", ""); err != nil || !next.Admitted {
		t.Fatalf("slot not freed after reaping: %v", err)
	}
}

// End-to-end through the agent: a full worker queues the second owner with a
// countdown; freeing the first admits the queued one.
func TestAgentQueuesWhenFull(t *testing.T) {
	now := time.Unix(1700000000, 0)
	workerA := newIdentity(t)
	ownerX := newIdentity(t)
	ownerY := newIdentity(t)

	rt := &fakeRuntime{}
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: workerA.ID()},
		rt, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 1, InstanceTTL: 24 * time.Hour})
	ac.now = fixedClock(now)
	agent.SetAdmission(ac, 24*time.Hour)

	launch := func(owner *testIdentity, req DeployRequest) DeployReply {
		env, _ := NewEnvelope(owner, workerA.ID(), MethodLaunch, req, now)
		reply, err := agent.HandleLaunch(context.Background(), env)
		if err != nil {
			t.Fatalf("launch: %v", err)
		}
		return reply
	}

	// Owner X takes the only slot.
	rx := launch(ownerX, DeployRequest{DeploymentID: "x1", Image: "sha256:a", Lab: true, RuntimeSecs: 3600})
	if rx.Queued || rx.ContainerID == "" {
		t.Fatalf("owner X should have been admitted: %+v", rx)
	}
	if rx.InstanceTTL != int64((24*time.Hour).Seconds()) &&
		rx.InstanceTTL != int64((time.Hour).Seconds()) {
		// Lab ceiling (1h requested) wins over the 24h general TTL here.
	}

	// Owner Y is queued with a countdown.
	ry := launch(ownerY, DeployRequest{DeploymentID: "y1", Image: "sha256:a", Lab: true, RuntimeSecs: 3600})
	if !ry.Queued || ry.Position != 1 || ry.Ticket == "" {
		t.Fatalf("owner Y should have been queued: %+v", ry)
	}
	if ry.ETASeconds <= 0 {
		t.Fatal("queued reply carried no countdown")
	}

	// Free owner X's instance; owner Y's retry is admitted.
	if err := agent.Destroy(context.Background(), rx.ContainerID); err != nil {
		t.Fatal(err)
	}
	ry2 := launch(ownerY, DeployRequest{DeploymentID: "y1", Image: "sha256:a", Lab: true, RuntimeSecs: 3600, Ticket: ry.Ticket})
	if ry2.Queued || ry2.ContainerID == "" {
		t.Fatalf("owner Y should have been promoted after a slot freed: %+v", ry2)
	}
}
