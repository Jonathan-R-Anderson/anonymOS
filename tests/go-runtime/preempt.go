package main

// Signals must not corrupt the interrupted code's floating-point state.  Go preempts a goroutine
// that runs too long by sending its thread SIGURG; the handler runs Go code that uses SSE, and if
// the kernel does not save and restore the interrupted XMM/MXCSR state around the handler, the
// goroutine resumes with someone else's registers -- including X15, which Go's ABI keeps zero.
// Each worker computes the same float series many times between preemptions and checks it.
import (
	"fmt"
	"math"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

func series(seed float64) float64 {
	x := seed
	for i := 0; i < 200000; i++ {
		x = math.Sqrt(x*x+1.0000001) * 0.9999999
		x += float64(i&7) * 1e-9
	}
	return x
}

func main() {
	fmt.Println("PREEMPT-START")
	runtime.GOMAXPROCS(4)
	want := make([]float64, 8)
	for i := range want {
		want[i] = series(float64(i) + 0.5)
	}
	var bad, rounds atomic.Int64
	var wg sync.WaitGroup
	deadline := time.Now().Add(8 * time.Second)
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for time.Now().Before(deadline) {
				if got := series(float64(w) + 0.5); got != want[w] {
					bad.Add(1)
				}
				rounds.Add(1)
			}
		}(w)
	}
	wg.Wait()
	if bad.Load() != 0 {
		fmt.Printf("PREEMPT-FAIL %d of %d rounds corrupted\n", bad.Load(), rounds.Load())
		os.Exit(1)
	}
	fmt.Printf("PREEMPT-OK %d rounds, none corrupted\n", rounds.Load())
}
