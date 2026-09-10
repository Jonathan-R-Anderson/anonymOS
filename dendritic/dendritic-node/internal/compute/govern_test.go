package compute

import (
	"strings"
	"testing"
	"time"
)

// fakeSensors is a machine state arranged on demand — a hot laptop on battery
// running a fullscreen game is not something you can conjure in CI.
type fakeSensors struct {
	load    float64
	battery bool
	temp    int
	gpu     int
}

func (f fakeSensors) LoadAverage1() float64 { return f.load }
func (f fakeSensors) OnBattery() bool       { return f.battery }
func (f fakeSensors) HottestC() int         { return f.temp }
func (f fakeSensors) GPUBusyPercent() int   { return f.gpu }

func idleMachine() fakeSensors { return fakeSensors{load: 0.1, temp: 45, gpu: 0} }

func eightCores() Profile {
	return Profile{CPU: CPUInfo{PhysicalCores: 8, LogicalCores: 16}}
}

func enabled() Policy { return Policy{Enabled: true, IdleOnly: true} }

func TestDisabledByDefault(t *testing.T) {
	// The zero value must never run work. Enabling is always an explicit act
	// by the machine's owner.
	g := NewGovernor(Policy{}, eightCores(), idleMachine())
	if g.Decide(0).Allowed() {
		t.Fatal("the zero-value policy ran work")
	}
}

func TestCoresAreReservedForTheUser(t *testing.T) {
	g := NewGovernor(enabled(), eightCores(), idleMachine())
	grant := g.Decide(0)
	if grant.Cores != 6 {
		t.Fatalf("granted %d cores of 8 with 2 reserved, want 6", grant.Cores)
	}
}

func TestASmallMachineKeepsItsCores(t *testing.T) {
	// Two cores, two reserved: nothing left. Correct — the roadmap's rule is
	// never to take the last cores, and a dual-core machine is exactly where
	// taking them would be felt worst.
	g := NewGovernor(enabled(), Profile{CPU: CPUInfo{PhysicalCores: 2, LogicalCores: 4}}, idleMachine())
	if g.Decide(0).Allowed() {
		t.Fatal("took the last cores on a 2-core machine")
	}
}

func TestBatteryStopsWork(t *testing.T) {
	sensors := idleMachine()
	sensors.battery = true
	g := NewGovernor(enabled(), eightCores(), sensors)
	grant := g.Decide(0)
	if grant.Allowed() {
		t.Fatal("ran work on battery")
	}
	if !strings.Contains(grant.Reason, "battery") {
		t.Fatalf("unhelpful reason: %q", grant.Reason)
	}
}

func TestHeatStopsWork(t *testing.T) {
	sensors := idleMachine()
	sensors.temp = 95
	g := NewGovernor(enabled(), eightCores(), sensors)
	if g.Decide(0).Allowed() {
		t.Fatal("ran work at 95°C")
	}
}

func TestAnAbsurdTemperatureLimitIsClampedDown(t *testing.T) {
	// A config typo must not be able to disable thermal protection. The clamp
	// goes toward doing less work, never more.
	policy := enabled()
	policy.MaxTempC = 100000
	if got := policy.Normalise().MaxTempC; got != defaultMaxTempC {
		t.Fatalf("limit normalised to %d, want the default %d", got, defaultMaxTempC)
	}
}

func TestABusyMachineIsLeftAlone(t *testing.T) {
	sensors := idleMachine()
	sensors.load = 12 // somebody is compiling
	g := NewGovernor(enabled(), eightCores(), sensors)
	if g.Decide(0).Allowed() {
		t.Fatal("took cores from a machine under load")
	}
}

func TestOwnLoadIsNotMistakenForTheUsers(t *testing.T) {
	// THE oscillation bug this design exists to avoid. At the core limit our
	// own threads put load on the run queue; reading that as the user's makes
	// the governor stop, watch load fall, start, and repeat — which is worse
	// for the desktop than either steady state.
	sensors := idleMachine()
	sensors.load = 6.05 // six cores of our own work, plus a rounding of noise
	g := NewGovernor(enabled(), eightCores(), sensors)

	if grant := g.Decide(6); !grant.Allowed() {
		t.Fatalf("stopped because of its own work: %q", grant.Reason)
	}
	// The same load with nothing of ours running IS the user, and must stop.
	if g.Decide(0).Allowed() {
		t.Fatal("mistook a genuinely busy machine for its own work")
	}
}

func TestAFullscreenGameIsNoticed(t *testing.T) {
	// Input idleness misses this completely: four hours into a game, no key
	// has been touched for minutes and the machine is as in use as it gets.
	sensors := idleMachine()
	sensors.gpu = 96
	g := NewGovernor(enabled(), eightCores(), sensors)
	grant := g.Decide(0)
	if grant.Allowed() {
		t.Fatal("ran work while the GPU was at 96%")
	}
	if !strings.Contains(grant.Reason, "GPU") {
		t.Fatalf("unhelpful reason: %q", grant.Reason)
	}
}

func TestUnreadableLoadStopsWork(t *testing.T) {
	// Fail closed. Not knowing whether the machine is in use is not permission
	// to assume it is free.
	sensors := idleMachine()
	sensors.load = -1
	g := NewGovernor(enabled(), eightCores(), sensors)
	if g.Decide(0).Allowed() {
		t.Fatal("ran work without being able to read system load")
	}
}

func TestUnreadableThermalsDoNotStopWork(t *testing.T) {
	// The one place not-knowing is allowed: containers and VMs expose no
	// thermal zones and have no fan to save. Refusing here would rule out most
	// of the server population for no benefit.
	sensors := idleMachine()
	sensors.temp = -1
	g := NewGovernor(enabled(), eightCores(), sensors)
	if !g.Decide(0).Allowed() {
		t.Fatal("refused work merely because thermals were unreadable")
	}
}

func TestNoSensorsMeansNoWork(t *testing.T) {
	g := NewGovernor(enabled(), eightCores(), nil)
	if g.Decide(0).Allowed() {
		t.Fatal("ran work with no way to observe the machine")
	}
}

// --- scheduled hours ---

func at(hour, minute int) func() time.Time {
	return func() time.Time { return time.Date(2026, 8, 3, hour, minute, 0, 0, time.UTC) }
}

func TestOvernightWindowWrapsMidnight(t *testing.T) {
	// The normal case for this feature — people offer machines overnight.
	// Treating it as an edge case is how "22:00-07:00" silently becomes never.
	policy := enabled()
	policy.Hours = "22:00-07:00"
	g := NewGovernor(policy, eightCores(), idleMachine())

	for _, tc := range []struct {
		hour, minute int
		want         bool
	}{
		{23, 30, true}, {2, 0, true}, {6, 59, true},
		{7, 0, false}, {12, 0, false}, {21, 59, false}, {22, 0, true},
	} {
		g.Now = at(tc.hour, tc.minute)
		if got := g.Decide(0).Allowed(); got != tc.want {
			t.Errorf("at %02d:%02d allowed=%v, want %v", tc.hour, tc.minute, got, tc.want)
		}
	}
}

func TestDaytimeWindowDoesNotWrap(t *testing.T) {
	policy := enabled()
	policy.Hours = "09:00-17:00"
	g := NewGovernor(policy, eightCores(), idleMachine())
	g.Now = at(12, 0)
	if !g.Decide(0).Allowed() {
		t.Fatal("refused work inside a daytime window")
	}
	g.Now = at(20, 0)
	if g.Decide(0).Allowed() {
		t.Fatal("ran work outside a daytime window")
	}
}

func TestAnUnparseableWindowStopsWork(t *testing.T) {
	// An operator who wrote a window meant to restrict something. Ignoring it
	// grants MORE than they asked for, which is the wrong way to be wrong.
	for _, window := range []string{"garbage", "25:00-26:00", "22:00", "12:00-12:00", "9-5"} {
		policy := enabled()
		policy.Hours = window
		g := NewGovernor(policy, eightCores(), idleMachine())
		if g.Decide(0).Allowed() {
			t.Errorf("ran work with an unparseable window %q", window)
		}
	}
}

// --- job classes ---

func TestAllClassesAcceptedByDefault(t *testing.T) {
	if !enabled().Normalise().AcceptsClass("train") {
		t.Fatal("an empty class list should accept everything")
	}
}

func TestAClassListIsAnAllowlist(t *testing.T) {
	policy := enabled()
	policy.JobClasses = []string{"media", "index"}
	policy = policy.Normalise()
	if !policy.AcceptsClass("media") {
		t.Fatal("refused a listed class")
	}
	if policy.AcceptsClass("train") {
		t.Fatal("accepted a class the operator did not list")
	}
}

func TestReasonsAreFitToShowTheOwner(t *testing.T) {
	// "What has my machine been doing" deserves a sentence. Every refusal path
	// must produce one — an empty reason is a dead end for the person the
	// whole policy exists to protect.
	cases := []struct {
		name    string
		policy  Policy
		sensors fakeSensors
	}{
		{"disabled", Policy{}, idleMachine()},
		{"battery", enabled(), fakeSensors{load: 0.1, temp: 45, battery: true}},
		{"hot", enabled(), fakeSensors{load: 0.1, temp: 99}},
		{"busy", enabled(), fakeSensors{load: 20, temp: 45}},
		{"gpu", enabled(), fakeSensors{load: 0.1, temp: 45, gpu: 90}},
	}
	for _, tc := range cases {
		g := NewGovernor(tc.policy, eightCores(), tc.sensors)
		grant := g.Decide(0)
		if grant.Allowed() {
			t.Errorf("%s: expected work to be refused", tc.name)
			continue
		}
		if len(strings.TrimSpace(grant.Reason)) < 10 {
			t.Errorf("%s: unhelpful reason %q", tc.name, grant.Reason)
		}
	}
}

func TestAGrantSaysWhatItGave(t *testing.T) {
	g := NewGovernor(enabled(), eightCores(), idleMachine())
	grant := g.Decide(0)
	if !strings.Contains(grant.Reason, "reserved for you") {
		t.Fatalf("a granting decision should say what was kept back: %q", grant.Reason)
	}
}

// --- M10: per-workload consent ---

func TestAnEmptyWorkloadListAcceptsEveryCatalogueWorkload(t *testing.T) {
	// The default has to be "everything in the catalogue", because the
	// catalogue is already the thing the operator consented to when they
	// enabled compute. An empty list meaning "nothing" would silently switch
	// off every existing node the day this field shipped.
	policy := enabled().Normalise()
	for _, name := range []string{"embed", "anything-added-later"} {
		if !policy.AcceptsWorkload(name) {
			t.Errorf("an empty workload list refused %q", name)
		}
	}
}

func TestAWorkloadListIsAnAllowlist(t *testing.T) {
	policy := enabled()
	policy.Workloads = []string{"embed"}
	policy = policy.Normalise()
	if !policy.AcceptsWorkload("embed") {
		t.Fatal("refused a workload the operator listed")
	}
	if policy.AcceptsWorkload("render") {
		t.Fatal("accepted a workload the operator did not list")
	}
}

// THE REGRESSION THIS FILE EXISTS TO PREVENT.
//
// computeworker's Admit calls AcceptsClass with a DEVICE string. If workload
// names were routed through JobClasses instead of their own list, the first
// operator to opt into a workload would turn an empty class list into a
// non-empty allowlist containing no device — and every device check would fall
// through it and refuse ALL work, permanently, with retryable:false.
func TestAWorkloadListDoesNotStopDeviceWork(t *testing.T) {
	policy := Policy{Enabled: true, OfferCPU: true, Workloads: []string{"embed"}}.Normalise()
	if !policy.AcceptsClass("cpu") {
		t.Fatal("opting into a workload refused the device the operator lent")
	}
	// And the whole node, not just the class check: a governor with this policy
	// must still grant cores.
	governor := &Governor{Policy: policy, Profile: eightCores(), Sensors: idleMachine()}
	if grant := governor.Decide(0); !grant.Allowed() {
		t.Fatalf("a node that opted into a workload stopped working: %q", grant.Reason)
	}
}

// The same value in the WRONG list, kept as a demonstration of why there are
// two. This is not a bug being asserted — it is AcceptsClass behaving exactly
// as documented for a value that is not a device, which is precisely why a
// workload name must never be put here.
func TestAWorkloadNameInTheClassListWouldRefuseEveryDevice(t *testing.T) {
	miswired := Policy{Enabled: true, OfferCPU: true, JobClasses: []string{"embed"}}.Normalise()
	if miswired.AcceptsClass("cpu") {
		t.Fatal("AcceptsClass changed meaning; the reason Workloads is a separate field no longer holds")
	}
}
