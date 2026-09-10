package traffic

import (
	"sync"
	"testing"
	"time"
)

func TestFirstWindowEstablishesTheStartRatherThanReportingFromBoot(t *testing.T) {
	// At boot there is no previous drain to measure from. Treating the zero
	// time as the start would divide by decades and report approximately zero
	// throughput forever after the first call.
	var m Meter
	m.Serve(1000)
	got := m.Window(time.Unix(1_700_000_000, 0))
	if got.WindowSeconds != 0 || got.Bytes != 0 {
		t.Fatalf("first window should be empty, got %+v", got)
	}
}

func TestASecondWindowReportsWhatHappenedInIt(t *testing.T) {
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Window(start)

	m.Serve(4096)
	m.Serve(4096)
	got := m.Window(start.Add(60 * time.Second))

	if got.Bytes != 8192 || got.Requests != 2 || got.WindowSeconds != 60 {
		t.Fatalf("got %+v", got)
	}
}

func TestDrainingResetsSoTrafficIsNeverCountedTwice(t *testing.T) {
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Window(start)
	m.Serve(1024)
	m.Window(start.Add(30 * time.Second))

	got := m.Window(start.Add(60 * time.Second))
	if got.Bytes != 0 || got.Requests != 0 {
		t.Fatalf("a drained window must not reappear: %+v", got)
	}
	if got.WindowSeconds != 30 {
		t.Fatalf("the interval should still advance, got %d", got.WindowSeconds)
	}
}

func TestBytesBeforeTheFirstWindowAreDiscardedNotCarried(t *testing.T) {
	// They belong to no measured interval. Carrying them forward would
	// attribute them to a period they did not happen in, which on a busy node
	// restarting looks exactly like a traffic spike that never occurred.
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Serve(999999)
	m.Window(start)

	got := m.Window(start.Add(60 * time.Second))
	if got.Bytes != 0 {
		t.Fatalf("pre-window bytes leaked into a measured interval: %+v", got)
	}
}

func TestTwoDrainsInsideOneSecondReportNothing(t *testing.T) {
	// Dividing by zero, or claiming a one-second rate from a fraction of one,
	// are both worse than declining to answer.
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Window(start)
	m.Serve(5000)
	got := m.Window(start.Add(300 * time.Millisecond))
	if got.WindowSeconds != 0 || got.Bytes != 0 {
		t.Fatalf("sub-second window should report nothing, got %+v", got)
	}
}

func TestNegativeAndZeroByteCountsAreIgnored(t *testing.T) {
	// A negative would subtract from the network total and let one node hide
	// another's traffic once these are summed.
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Window(start)
	m.AddBytes(-500)
	m.AddBytes(0)
	got := m.Window(start.Add(10 * time.Second))
	if got.Bytes != 0 {
		t.Fatalf("got %+v", got)
	}
}

func TestANilMeterIsSafe(t *testing.T) {
	// Roles that serve nothing hold no meter. They must not have to check.
	var m *Meter
	m.AddBytes(10)
	m.AddRequest()
	m.Serve(10)
	if got := m.Window(time.Now()); got.WindowSeconds != 0 {
		t.Fatalf("a nil meter should report nothing, got %+v", got)
	}
}

func TestConcurrentServesAreAllCounted(t *testing.T) {
	var m Meter
	start := time.Unix(1_700_000_000, 0)
	m.Window(start)

	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Serve(512)
		}()
	}
	wg.Wait()

	got := m.Window(start.Add(time.Minute))
	if got.Requests != 200 || got.Bytes != 200*512 {
		t.Fatalf("lost counts under concurrency: %+v", got)
	}
}
