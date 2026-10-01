package ui

// What lending your machine actually costs you, shown live.
//
// WHY THIS EXISTS
// ---------------
// An operator lending CPU and a GPU is being asked to trust that the governor
// will stay out of their way. Trust is a poor substitute for a graph. Somebody
// deciding whether to keep the node running wants to see, right now, how much
// of their machine is going to the network and how much is theirs — and to see
// it drop when they start doing something.
//
// WHAT IT SEPARATES, AND WHY THAT IS THE WHOLE POINT
// -------------------------------------------------
// Total machine load and load THIS NODE caused are different numbers, and only
// the second is the network's doing. A meter that showed a single line would
// let an operator blame the node for their own compile, or miss the node
// pinning every core while they were away.
//
// So `Total` and `Node` are reported separately, and the node's own figure is
// derived from what it is actually running rather than inferred from load —
// inference would be a guess presented as a measurement.

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// Sample is one moment.
type Sample struct {
	At time.Time `json:"at"`
	// LoadPerCore is the 1-minute run queue divided by cores, so 1.0 means
	// "as busy as it can usefully be" on any machine. A raw load average is
	// meaningless without knowing the core count, and the reader should not
	// have to do that division.
	LoadPerCore float64 `json:"load_per_core"`
	// NodeJobs is how many compute jobs THIS node is running. The honest
	// measure of what the network is costing, as opposed to what the machine
	// happens to be doing.
	NodeJobs int `json:"node_jobs"`
	// GPUBusy is 0-100, or -1 when no GPU reports it. -1 rather than 0 because
	// "no reading" and "idle" are different facts and a graph that drew them
	// the same would be lying about an absence.
	GPUBusy int `json:"gpu_busy"`
	TempC   int `json:"temp_c"`
	// Paused says the governor is holding work back right now, and Reason says
	// why in words fit to show the machine's owner.
	Paused bool   `json:"paused"`
	Reason string `json:"reason,omitempty"`
}

// LoadMeter keeps a short rolling history for the graph.
//
// Deliberately small and in memory. A meter that persisted would be a
// minute-by-minute record of when the machine's owner was at their desk, which
// is a surveillance log dressed as a feature.
type LoadMeter struct {
	governor *compute.Governor
	sensors  compute.Sensors
	cores    int

	mu      sync.Mutex
	samples []Sample
	running func() int
}

// HistoryLength is how many samples are kept: five minutes at one per second.
// Enough to see a spike and its recovery, short enough that it says nothing
// about yesterday.
const HistoryLength = 300

func NewLoadMeter(governor *compute.Governor, sensors compute.Sensors, cores int, running func() int) *LoadMeter {
	if cores <= 0 {
		cores = 1
	}
	if running == nil {
		running = func() int { return 0 }
	}
	return &LoadMeter{governor: governor, sensors: sensors, cores: cores, running: running}
}

// Sample takes a reading.
func (m *LoadMeter) Sample(now time.Time) Sample {
	s := Sample{At: now, GPUBusy: -1, TempC: -1, NodeJobs: m.running()}
	if m.sensors != nil {
		if load := m.sensors.LoadAverage1(); load >= 0 {
			s.LoadPerCore = load / float64(m.cores)
		}
		s.GPUBusy = m.sensors.GPUBusyPercent()
		s.TempC = m.sensors.HottestC()
	}
	if m.governor != nil {
		grant := m.governor.Decide(s.NodeJobs)
		if !grant.Allowed() {
			s.Paused, s.Reason = true, grant.Reason
		}
	}

	m.mu.Lock()
	m.samples = append(m.samples, s)
	if len(m.samples) > HistoryLength {
		m.samples = m.samples[len(m.samples)-HistoryLength:]
	}
	m.mu.Unlock()
	return s
}

// History returns the rolling window, oldest first.
func (m *LoadMeter) History() []Sample {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Sample, len(m.samples))
	copy(out, m.samples)
	return out
}

// ServeHTTP returns the current sample plus history.
//
// Samples on request rather than on a timer: a node whose UI nobody has open
// should not be reading sensors every second forever, and the graph is the only
// consumer.
func (m *LoadMeter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	current := m.Sample(time.Now())
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"current": current,
		"history": m.History(),
		"cores":   m.cores,
	})
}
