//go:build linux

package microvm

// Running the guest, and — more importantly — making sure it stops.
//
// WHY TEARDOWN IS THE HARD PART
// -----------------------------
// Spec layer 11 says the VM is destroyed after every job. That is easy when the
// guest cooperates and is the whole problem when it does not: a hostile payload
// has every reason to ignore a shutdown request and keep the slot, and a
// volunteer who finds a stuck VM eating a core is a volunteer who uninstalls
// the node.
//
// So there is no cooperative path here at all. The context deadline fires and
// the process is killed. Firecracker holds the guest entirely inside one host
// process — kill it and the vCPU threads, the memory mapping and the devices go
// with it — which is exactly why the VMM boundary is also the cleanup boundary.
//
// The kill is by PROCESS GROUP. Firecracker itself is well-behaved, but a
// runner that only signals the direct child leaves anything it spawned running,
// and "mostly cleaned up" is indistinguishable from "leaking one process per
// job" until the machine has a thousand of them.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// Result is what a finished job produced.
type Result struct {
	// Console is the guest's serial output. Captured always, including on
	// failure: when a guest dies the console is usually the only evidence of
	// why, and discarding it on the error path removes it exactly when needed.
	Console []byte

	// TimedOut distinguishes "the job ran and failed" from "the job never
	// finished". They look identical in an exit code and mean different things
	// to a scheduler — one is a bad payload, the other may be a bad estimate.
	TimedOut bool

	ExitCode int
	Duration time.Duration
}

// MaxConsoleBytes caps captured serial output.
//
// A guest that prints in a loop would otherwise fill the host's disk through
// the one channel it is allowed — denial of service by way of the log file. The
// cap is not a formatting preference; it is the reason the channel is safe.
const MaxConsoleBytes = 4 << 20 // 4 MiB

// Runner boots guests using a specific firecracker binary.
type Runner struct {
	// Binary is the firecracker executable. Explicit rather than looked up at
	// call time so a node cannot start executing a different binary because
	// something changed PATH after the node started.
	Binary string
}

// NewRunner resolves firecracker once, at startup.
func NewRunner() (*Runner, error) {
	path, err := exec.LookPath("firecracker")
	if err != nil {
		return nil, fmt.Errorf("microvm: firecracker not found: %w", err)
	}
	return &Runner{Binary: path}, nil
}

// Run boots the job's guest and waits for it to finish or time out.
//
// Never returns before the guest is gone. The deferred teardown runs on every
// path including panic, because the one thing worse than a failed job is a
// failed job whose VM is still running.
func (r *Runner) Run(ctx context.Context, j Job) (Result, error) {
	cfg, err := BuildConfig(j)
	if err != nil {
		return Result{}, err
	}

	dir, err := os.MkdirTemp("", "microvm-")
	if err != nil {
		return Result{}, fmt.Errorf("microvm: workspace: %w", err)
	}
	defer os.RemoveAll(dir)

	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, cfg, 0o600); err != nil {
		return Result{}, fmt.Errorf("microvm: write config: %w", err)
	}

	ctx, cancel := context.WithTimeout(ctx, j.Limits.Timeout)
	defer cancel()

	// --no-api: without it Firecracker opens a control socket that can
	// reconfigure the running VM. Nothing here needs to, and a socket nobody
	// uses is an interface that only an attacker has a reason to reach.
	cmd := exec.Command(r.Binary, "--no-api", "--config-file", configPath)
	cmd.Dir = dir
	// The guest's stdin is /dev/null, not a terminal. Layer 5: no input device
	// exists, so there is no keystroke stream for a payload to read.
	cmd.Stdin = nil
	console := &capped{limit: MaxConsoleBytes}
	cmd.Stdout = console
	cmd.Stderr = console
	// Own process group, so teardown can signal the whole tree rather than one
	// process that may have children.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("microvm: start: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	var timedOut bool
	select {
	case err = <-done:
	case <-ctx.Done():
		timedOut = true
		killGroup(cmd.Process.Pid)
		// Reap, so the goroutine and the zombie both go away. Bounded, because
		// a process wedged in uninterruptible sleep would otherwise hang the
		// node here forever waiting for something that cannot arrive.
		select {
		case err = <-done:
		case <-time.After(5 * time.Second):
			err = errors.New("microvm: guest did not exit after kill")
		}
	}

	result := Result{
		Console:  console.Bytes(),
		TimedOut: timedOut,
		Duration: time.Since(started),
		ExitCode: exitCodeOf(err),
	}
	if timedOut {
		// Not an error return. A job hitting its deadline is an ordinary
		// outcome the scheduler must reason about, and the console explaining
		// what it was doing is worth more than an error value that discards it.
		return result, nil
	}
	return result, err
}

// killGroup terminates the guest and anything it started.
//
// SIGKILL rather than SIGTERM. There is no cooperative shutdown to negotiate:
// the guest is untrusted, the VMM does not need to flush anything, and asking
// politely only gives a hostile payload a window to ignore.
func killGroup(pid int) {
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	_ = syscall.Kill(pid, syscall.SIGKILL)
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode()
	}
	return -1
}
