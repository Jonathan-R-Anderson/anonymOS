package reputation

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"
)

// TestReduceRaceAgainstAccept exercises the concurrency the other tests do not:
// one goroutine reducing a subject while another accepts new attestations about
// it. Reduce captures the inner issuer map under RLock and then iterates it
// after releasing the lock, so a concurrent Accept writing to that same map is
// a concurrent read/write. Run with -race.
func TestReduceRaceAgainstAccept(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	r := NewReducer(IssuerID(pub))
	r.Now = func() time.Time { return time.Unix(1_700_000_000, 0) }

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		i := 0
		for {
			select {
			case <-stop:
				return
			default:
			}
			a := Attestation{
				Subject: "relay-a", Dimension: DimUptime, Value: 0.5,
				Basis: "obs", Window: time.Hour,
				At: time.Unix(1_700_000_000+int64(i%7), 0),
			}
			if err := a.Sign(priv); err == nil {
				_ = r.Accept(a)
			}
			i++
		}
	}()

	for i := 0; i < 5000; i++ {
		_ = r.Reduce("relay-a", DimUptime)
	}
	close(stop)
	wg.Wait()
}
