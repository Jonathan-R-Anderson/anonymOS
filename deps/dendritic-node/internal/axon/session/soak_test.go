package session

import (
	"crypto/sha256"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/params"
)

// TestE71TenMinuteTransfer is E7.1 at full length: a 10-minute transfer
// survives three forced tunnel deaths with zero application-visible error and
// zero duplicated bytes. It runs with the SPECIFIED timers (DefaultConfig) --
// only the replacement time is the test's, set to a READY-spare attach -- and
// it takes ten minutes, so it runs only with AXON_SOAK=1.
//
// Deaths are one explicit and two silent, the silent ones being the slow case
// the bound is built around.
func TestE71TenMinuteTransfer(t *testing.T) {
	if os.Getenv("AXON_SOAK") == "" {
		t.Skip("E7.1 soak: set AXON_SOAK=1 (takes 10 minutes)")
	}
	cfg := DefaultConfig()
	const replace = 500 * time.Millisecond
	pr := newPair(t, cfg, replace)
	bound := cfg.MigrationBound(replace)
	if cfg.MigrationBound(params.TunnelBuildTimeout) != params.SessionMigrationBound {
		t.Fatal("Config.MigrationBound disagrees with params.SessionMigrationBound")
	}

	cs, err := pr.cli.OpenStream([]byte("e71"))
	if err != nil {
		t.Fatal(err)
	}
	ss := accept(t, pr.svc)
	const duration = 10 * time.Minute
	const rate = 256 << 10 // bytes per second, each way
	start := time.Now()
	hUpTx, hDownTx := sha256.New(), sha256.New()
	var sentUp, sentDown int64
	var wg sync.WaitGroup
	writer := func(st *Stream, h io.Writer, n *int64) {
		defer wg.Done()
		buf := make([]byte, rate/10)
		for time.Since(start) < duration {
			if _, err := io.ReadFull(randReader{}, buf); err != nil {
				t.Error(err)
				return
			}
			h.Write(buf)
			if _, err := st.Write(buf); err != nil {
				t.Errorf("write at %v: %v", time.Since(start), err)
				return
			}
			*n += int64(len(buf))
			time.Sleep(100 * time.Millisecond)
		}
		st.CloseWrite()
	}
	var gotUp, gotDown atomic.Int64
	hUpRx, hDownRx := sha256.New(), sha256.New()
	var errUp, errDown error
	reader := func(st *Stream, h io.Writer, n *atomic.Int64, e *error) {
		defer wg.Done()
		buf := make([]byte, 64<<10)
		for {
			k, err := st.Read(buf)
			h.Write(buf[:k])
			n.Add(int64(k))
			if err == io.EOF {
				return
			}
			if err != nil {
				*e = err
				return
			}
		}
	}
	wg.Add(4)
	go writer(cs, hUpTx, &sentUp)
	go writer(ss, hDownTx, &sentDown)
	go reader(ss, hUpRx, &gotUp, &errUp)
	go reader(cs, hDownRx, &gotDown, &errDown)

	for i, at := range []time.Duration{duration / 4, duration / 2, duration * 3 / 4} {
		time.Sleep(time.Until(start.Add(at)))
		p := pr.path()
		p.mu.Lock()
		up, down := arrived(ss), arrived(cs)
		p.mu.Unlock()
		explicit := i == 0
		p.kill(explicit)
		d1, ok1 := waitProgress(func() int64 { return arrived(ss) }, up, 2*bound)
		d2, ok2 := waitProgress(func() int64 { return arrived(cs) }, down, 2*bound)
		stall := d1
		if d2 > stall {
			stall = d2
		}
		if !ok1 || !ok2 || stall > bound {
			t.Fatalf("death %d (explicit=%v): stalled %v, bound %v", i+1, explicit, stall, bound)
		}
		t.Logf("death %d at %v (explicit=%v): resumed in %v (bound %v)", i+1, at, explicit, stall, bound)
	}
	wg.Wait()
	if errUp != nil || errDown != nil {
		t.Fatalf("application-visible error: %v / %v", errUp, errDown)
	}
	if gotUp.Load() != sentUp || gotDown.Load() != sentDown {
		t.Fatalf("byte counts: up %d/%d down %d/%d", gotUp.Load(), sentUp, gotDown.Load(), sentDown)
	}
	if string(hUpRx.Sum(nil)) != string(hUpTx.Sum(nil)) || string(hDownRx.Sum(nil)) != string(hDownTx.Sum(nil)) {
		t.Fatal("content differs: bytes lost, duplicated or reordered")
	}
	t.Logf("E7.1: %d + %d bytes over %v, 3 deaths, client %+v, service %+v",
		sentUp, sentDown, time.Since(start).Round(time.Second), pr.cli.Stats(), pr.svc.Stats())
}

type randReader struct{}

func (randReader) Read(b []byte) (int, error) { return cryptoRead(b) }
