//go:build linux

package dcs

import (
	"context"
	"fmt"
	"net"
	"runtime"
	"sync"

	"golang.org/x/sys/unix"
)

// namespaceDialer dials into a container's network namespace by entering
// /proc/<pid>/ns/net for the duration of a single connect, then restoring the
// calling thread's own namespace.
//
// # WHY THIS IS SAFE-ISH AND WHERE THE SHARP EDGES ARE
//
// setns() changes the network namespace of the CURRENT THREAD, not the whole
// process. So the sequence must run on a thread that is locked to this
// goroutine (runtime.LockOSThread) and NEVER unlocked while it is in the
// foreign namespace -- if the goroutine returned to the pool still in the
// container's netns, unrelated code would suddenly dial from inside a
// vulnerable container. The thread is deliberately left locked on any restore
// failure so the Go runtime destroys it rather than reusing it.
//
// This requires CAP_SYS_ADMIN. A DCS worker that runs container hosting already
// holds the docker socket, which is strictly more powerful, so this adds no new
// privilege to the worker's own posture.
type namespaceDialer struct {
	containerPID int

	mu       sync.Mutex
	selfNS   int // fd of our own net namespace, opened once
	targetNS int // fd of the container's net namespace
	closed   bool
}

// NewNamespaceDialer opens handles to the calling process's and the container's
// network namespaces. containerPID is the container's main process PID, from
// `docker inspect`.
func NewNamespaceDialer(containerPID int) (NamespaceDialer, error) {
	self, err := unix.Open("/proc/self/ns/net", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dcs: open self netns: %w", err)
	}
	target, err := unix.Open(fmt.Sprintf("/proc/%d/ns/net", containerPID), unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(self)
		return nil, fmt.Errorf("dcs: open container %d netns: %w", containerPID, err)
	}
	return &namespaceDialer{containerPID: containerPID, selfNS: self, targetNS: target}, nil
}

func (d *namespaceDialer) DialContainerPort(ctx context.Context, port int) (net.Conn, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil, ErrProxyClosed
	}

	// Lock this goroutine to its OS thread for the whole enter/dial/restore.
	runtime.LockOSThread()

	if err := unix.Setns(d.targetNS, unix.CLONE_NEWNET); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("dcs: enter container netns: %w", err)
	}

	// Inside the container's netns now: 127.0.0.1 is the container's loopback,
	// where its services bind. A dialer with no deadline honours ctx.
	var dialer net.Dialer
	conn, dialErr := dialer.DialContext(ctx, "tcp", fmt.Sprintf("127.0.0.1:%d", port))

	// Restore our own namespace BEFORE unlocking the thread. If restore fails
	// the thread is poisoned (still in the container's netns), so we leave it
	// locked -- the Go runtime then retires it instead of returning it to the
	// pool where it could dial from inside the container.
	if err := unix.Setns(d.selfNS, unix.CLONE_NEWNET); err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		// Deliberately NOT UnlockOSThread: poison the thread.
		return nil, fmt.Errorf("dcs: restore netns (thread retired): %w", err)
	}
	runtime.UnlockOSThread()

	if dialErr != nil {
		return nil, dialErr // a closed container port; scan sees it closed
	}
	return conn, nil
}

func (d *namespaceDialer) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	if d.selfNS >= 0 {
		unix.Close(d.selfNS)
	}
	if d.targetNS >= 0 {
		unix.Close(d.targetNS)
	}
	return nil
}
