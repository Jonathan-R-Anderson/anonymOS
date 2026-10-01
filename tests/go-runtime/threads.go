package main

// Many OS threads at once: goroutines that lock their thread and block in syscalls force the Go
// runtime to clone a new M for each, the way a large program's startup does.
import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

func main() {
	fmt.Println("THREADS-START")
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			runtime.LockOSThread()
			buf := make([]byte, 64)
			for k := 0; k < 50; k++ {
				f, err := os.Open("/proc/self/status")
				if err == nil {
					f.Read(buf)
					f.Close()
				}
				time.Sleep(time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
	fmt.Println("THREADS-OK")
}
