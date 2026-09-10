package main

import (
	"fmt"
	"os"
	"time"
)

func main() {
	fmt.Println("HELLO-FROM-GO-ON-ANONYMOS")
	// exercise the timer/scheduler path that nanosleep backs — this is what breaks first
	t0 := time.Now()
	time.Sleep(50 * time.Millisecond)
	fmt.Printf("slept %v\n", time.Since(t0))
	// a goroutine + channel: tests clone-threads + futex
	ch := make(chan int, 1)
	go func() { ch <- 42 }()
	fmt.Println("goroutine returned", <-ch)
	fmt.Println("GO-RUNTIME-OK")
	os.Exit(0)
}
