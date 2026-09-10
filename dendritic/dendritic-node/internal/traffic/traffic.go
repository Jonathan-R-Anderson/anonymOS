// Package traffic counts what this node actually moved for other people.
//
// The coordinator cannot measure this. It never sees a peer-to-peer shard
// transfer or a gateway relay -- those go node to node, which is the whole
// point of the network -- so any throughput figure taken from the website's own
// logs would describe the website and call it the network.
//
// # WHAT COUNTS
//
// Bytes served TO somebody else. Not bytes this node fetched for itself, not
// its own uploads, not heartbeats or probes. The number is published as network
// throughput, and a node's own housekeeping is not throughput the network
// provided to anybody.
//
// # WHY A DRAIN AND NOT A COUNTER
//
// Window() returns what accumulated since the last call and resets. A
// cumulative counter would have to be differenced by the receiver, and it
// resets to zero when the process restarts -- which reads as a large NEGATIVE
// delta, i.e. as an enormous burst of traffic at exactly the moment a node is
// flapping. Draining makes a restart worth nothing instead of worth a spike.
//
// The consequence is that Window() has exactly ONE legitimate caller: whoever
// reports it. A second caller silently steals a slice of the first one's
// window, and the traffic simply disappears -- no error, no log, just a number
// quietly too low.
package traffic

import (
	"sync"
	"sync/atomic"
	"time"
)

// Meter accumulates bytes and requests until drained.
//
// The zero value is usable and is what a node with nothing wired up has: it
// reports a zero window, which the coordinator reads as "not reporting" rather
// than as "reported nothing". Those are different facts and the status page
// draws them differently.
type Meter struct {
	bytes    atomic.Int64
	requests atomic.Int64

	mu    sync.Mutex
	since time.Time
}

// Window is one drained interval.
type Window struct {
	Bytes         int64
	Requests      int
	WindowSeconds int
}

// AddBytes records payload served to somebody else. Safe from any goroutine.
func (m *Meter) AddBytes(n int64) {
	if m == nil || n <= 0 {
		return
	}
	m.bytes.Add(n)
}

// AddRequest records one served request, whatever its size.
func (m *Meter) AddRequest() {
	if m == nil {
		return
	}
	m.requests.Add(1)
}

// Serve records a request and its payload together, which is the common case
// and removes the chance of counting one without the other.
func (m *Meter) Serve(bytes int64) {
	if m == nil {
		return
	}
	m.requests.Add(1)
	if bytes > 0 {
		m.bytes.Add(bytes)
	}
}

// Window drains the meter and reports what accumulated since the previous call.
//
// The FIRST call establishes the start of measurement rather than reporting
// from process start: at boot `since` is zero, and treating that as the
// beginning of the window would divide by decades and report a rate of
// approximately nothing. It returns a zero window, which is honest -- nothing
// has been measured over a known interval yet.
func (m *Meter) Window(now time.Time) Window {
	if m == nil {
		return Window{}
	}
	m.mu.Lock()
	started := m.since
	m.since = now
	m.mu.Unlock()

	bytes := m.bytes.Swap(0)
	requests := m.requests.Swap(0)

	if started.IsZero() {
		// Drained anyway: whatever was counted before the first window belongs
		// to no measured interval, and carrying it into the next one would
		// attribute it to a period it did not happen in.
		return Window{}
	}
	elapsed := int(now.Sub(started) / time.Second)
	if elapsed <= 0 {
		// Two drains inside the same second. Reporting it would divide by zero
		// or claim a one-second rate from a fraction of one; both are worse
		// than saying nothing. The counters are already reset, so this loses a
		// sliver rather than double-counting it later.
		return Window{}
	}
	return Window{Bytes: bytes, Requests: int(requests), WindowSeconds: elapsed}
}
