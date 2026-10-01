package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

type fakeSensors struct {
	load float64
	gpu  int
	temp int
}

func (f fakeSensors) LoadAverage1() float64 { return f.load }
func (f fakeSensors) OnBattery() bool       { return false }
func (f fakeSensors) HottestC() int         { return f.temp }
func (f fakeSensors) GPUBusyPercent() int   { return f.gpu }

// Load must be reported PER CORE. A raw load average is meaningless without the
// core count, and the reader should not have to do that division to know
// whether their machine is busy.
func TestLoadIsReportedPerCore(t *testing.T) {
	m := NewLoadMeter(nil, fakeSensors{load: 8, gpu: -1, temp: -1}, 8, nil)
	s := m.Sample(time.Now())
	if s.LoadPerCore != 1.0 {
		t.Fatalf("load per core = %v, want 1.0 for load 8 on 8 cores", s.LoadPerCore)
	}
}

// "No reading" and "idle" are different facts. A meter that reported an absent
// GPU as 0 would draw it as permanently idle.
func TestAbsentGPUIsNotReportedAsIdle(t *testing.T) {
	m := NewLoadMeter(nil, fakeSensors{load: 1, gpu: -1, temp: -1}, 4, nil)
	if got := m.Sample(time.Now()).GPUBusy; got != -1 {
		t.Fatalf("absent GPU reported as %d, want -1", got)
	}
}

// The owner needs to tell THEIR load from the network's. A single number would
// let them blame the node for their own compile.
func TestNodeJobsAreReportedSeparatelyFromLoad(t *testing.T) {
	m := NewLoadMeter(nil, fakeSensors{load: 6, gpu: -1, temp: -1}, 4, func() int { return 2 })
	s := m.Sample(time.Now())
	if s.NodeJobs != 2 {
		t.Errorf("node jobs = %d, want 2", s.NodeJobs)
	}
	if s.LoadPerCore <= 0 {
		t.Error("machine load was folded into the node figure")
	}
}

// History must be bounded, or a node left running for a week accumulates a
// minute-by-minute record of when its owner was at their desk.
func TestHistoryIsBounded(t *testing.T) {
	m := NewLoadMeter(nil, fakeSensors{load: 1, gpu: -1, temp: -1}, 4, nil)
	now := time.Now()
	for i := 0; i < HistoryLength+50; i++ {
		m.Sample(now.Add(time.Duration(i) * time.Second))
	}
	if got := len(m.History()); got != HistoryLength {
		t.Fatalf("history = %d samples, want %d", got, HistoryLength)
	}
}

// A paused governor must say WHY, in words fit to show the machine's owner.
func TestPauseCarriesItsReason(t *testing.T) {
	policy := compute.Policy{Enabled: true, OfferCPU: true, IdleOnly: true,
		IdleLoadPerCore: 0.2, ReserveCores: 1}
	profile := compute.Profile{CPU: compute.CPUInfo{LogicalCores: 4, PhysicalCores: 4}}
	gov := compute.NewGovernor(policy.Normalise(), profile, fakeSensors{load: 40, gpu: -1, temp: -1})

	m := NewLoadMeter(gov, fakeSensors{load: 40, gpu: -1, temp: -1}, 4, nil)
	s := m.Sample(time.Now())
	if !s.Paused {
		t.Fatal("a heavily loaded machine was not reported as paused")
	}
	if s.Reason == "" {
		t.Error("paused with no reason to show the owner")
	}
}

func TestEndpointServesCurrentAndHistory(t *testing.T) {
	m := NewLoadMeter(nil, fakeSensors{load: 2, gpu: 55, temp: 40}, 4, func() int { return 1 })
	m.Sample(time.Now())

	rec := httptest.NewRecorder()
	m.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/load", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	// Must not be cached: a cached load graph is a graph of the past presented
	// as the present.
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Error("load readings are cacheable")
	}
	var out struct {
		Current Sample   `json:"current"`
		History []Sample `json:"history"`
		Cores   int      `json:"cores"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Cores != 4 || out.Current.GPUBusy != 55 || len(out.History) < 1 {
		t.Fatalf("payload = %+v", out)
	}
}
