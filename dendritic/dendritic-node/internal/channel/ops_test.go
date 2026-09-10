package channel

import (
	"strings"
	"testing"
	"time"
)

var oNow = time.Date(2026, 8, 5, 12, 0, 0, 0, time.UTC)

func ops(n int) []Candidate {
	var out []Candidate
	for i := 0; i < n; i++ {
		id := string(rune('a' + i))
		out = append(out, cand(id, "op"+id, "dom"+id))
	}
	return out
}

// THE property. A dip below the floor must keep alarming after recovery —
// payments routed during it were not private, and reporting "healthy" because
// it recovered hides exactly the interval that harmed someone.
func TestADipKeepsAlarmingAfterRecovery(t *testing.T) {
	m := NewDiversityMonitor(3, time.Hour)
	m.Observe(ops(5), oNow)
	m.Observe(ops(2), oNow.Add(10*time.Minute)) // the dip
	m.Observe(ops(5), oNow.Add(20*time.Minute)) // recovered

	level, why := m.Level()
	if level != DiversityDegraded {
		t.Fatalf("level = %d (%s), want degraded", level, why)
	}
	if !strings.Contains(why, "dropped to 2") {
		t.Errorf("the reason does not name the dip: %q", why)
	}
}

func TestBelowFloorIsBroken(t *testing.T) {
	m := NewDiversityMonitor(3, time.Hour)
	m.Observe(ops(1), oNow)
	if level, why := m.Level(); level != DiversityBroken {
		t.Fatalf("one operator reported as %d (%s)", level, why)
	}
}

// Exactly at the floor is not healthy: one operator leaving breaks it.
func TestExactlyAtTheFloorIsDegraded(t *testing.T) {
	m := NewDiversityMonitor(3, time.Hour)
	m.Observe(ops(3), oNow)
	level, why := m.Level()
	if level != DiversityDegraded {
		t.Fatalf("level = %d, want degraded at exactly the floor", level)
	}
	if !strings.Contains(why, "one operator leaving") {
		t.Errorf("reason does not explain the fragility: %q", why)
	}
}

// No observations must not read as healthy.
func TestUnmeasuredIsNotHealthy(t *testing.T) {
	m := NewDiversityMonitor(3, time.Hour)
	if level, _ := m.Level(); level != DiversityBroken {
		t.Fatal("an unmeasured network reported as anything but broken")
	}
}

// Old readings must age out, or a launch-day dip alarms forever.
func TestReadingsAgeOutOfTheWindow(t *testing.T) {
	m := NewDiversityMonitor(3, time.Hour)
	m.Observe(ops(1), oNow)
	m.Observe(ops(6), oNow.Add(2*time.Hour))
	if level, why := m.Level(); level != DiversityHealthy {
		t.Fatalf("level = %d (%s) — an expired dip still alarms", level, why)
	}
}

// Cooperative closes come first: instant, no challenge period, smallest window
// for anything to go wrong.
func TestCooperativeClosesAreScheduledFirst(t *testing.T) {
	channels := map[ChannelID]bool{"a": true, "b": true, "c": true}
	coop := map[ChannelID]bool{"b": true}
	steps, err := PlanMassClose(channels, coop, CloseOrderly, oNow, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !steps[0].Cooperative || steps[0].Channel != "b" {
		t.Fatalf("first step = %+v, want the cooperative close", steps[0])
	}
	if UnilateralCount(steps) != 2 {
		t.Errorf("unilateral count = %d, want 2", UnilateralCount(steps))
	}
}

// Orderly closes must be staggered: settling N channels in one block tells an
// observer they belonged to one operator.
func TestOrderlyClosesAreStaggered(t *testing.T) {
	channels := map[ChannelID]bool{"a": true, "b": true, "c": true}
	steps, _ := PlanMassClose(channels, nil, CloseOrderly, oNow, 10*time.Minute)
	times := map[time.Time]bool{}
	for _, s := range steps {
		if times[s.NotBefore] {
			t.Fatal("two unilateral closes scheduled for the same moment — they are linkable")
		}
		times[s.NotBefore] = true
	}
}

// Emergency deliberately skips staggering, and says so.
func TestEmergencyClosesImmediatelyAndAdmitsTheCost(t *testing.T) {
	channels := map[ChannelID]bool{"a": true, "b": true, "c": true}
	steps, _ := PlanMassClose(channels, nil, CloseEmergency, oNow, time.Minute)
	for _, s := range steps {
		if !s.NotBefore.Equal(oNow) {
			t.Error("an emergency close was delayed")
		}
		if !strings.Contains(s.Why, "linkable") {
			t.Errorf("emergency step does not state the privacy cost: %q", s.Why)
		}
	}
}

// The plan must be reproducible: an operator re-running it mid-exit must not
// get a different order and close something twice.
func TestPlanIsReproducible(t *testing.T) {
	channels := map[ChannelID]bool{"z": true, "a": true, "m": true, "q": true}
	first, _ := PlanMassClose(channels, nil, CloseOrderly, oNow, time.Minute)
	for i := 0; i < 20; i++ {
		again, _ := PlanMassClose(channels, nil, CloseOrderly, oNow, time.Minute)
		for j := range first {
			if again[j].Channel != first[j].Channel {
				t.Fatalf("run %d differs at step %d", i, j)
			}
		}
	}
}

func TestNothingToCloseIsAnError(t *testing.T) {
	if _, err := PlanMassClose(nil, nil, CloseOrderly, oNow, time.Minute); err != ErrNothingToClose {
		t.Fatal("planned an exit from no channels")
	}
}
