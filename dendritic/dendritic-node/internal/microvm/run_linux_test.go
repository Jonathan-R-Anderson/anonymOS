//go:build linux

package microvm

// Integration tests that boot a real guest.
//
// Skipped unless MICROVM_KERNEL and MICROVM_ROOTFS name real images, because
// they need KVM, a firecracker binary and ~150MB of artifacts that do not
// belong in a repository. The unit tests next door prove the POLICY; these
// prove the policy survives contact with an actual hypervisor, which is a
// different claim and the one that catches a config Firecracker rejects.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func artifacts(t *testing.T) (kernel, rootfs string) {
	t.Helper()
	kernel, rootfs = os.Getenv("MICROVM_KERNEL"), os.Getenv("MICROVM_ROOTFS")
	if kernel == "" || rootfs == "" {
		t.Skip("set MICROVM_KERNEL and MICROVM_ROOTFS to run boot tests")
	}
	for _, p := range []string{kernel, rootfs} {
		if _, err := os.Stat(p); err != nil {
			t.Skipf("artifact %s unavailable: %v", p, err)
		}
	}
	return kernel, rootfs
}

// outputImage makes the one writable surface a guest gets.
func outputImage(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "output.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(16 << 20); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return path
}

// The claim that matters: a booted guest has no network device.
//
// Asserted against the guest's own kernel log rather than against our config,
// because the config is what we ASKED for and the boot log is what the guest
// actually got. Those differ whenever an assumption about Firecracker is wrong,
// which is precisely the case a config-only test cannot see.
func TestRealGuestHasNoNetworkDevice(t *testing.T) {
	kernel, rootfs := artifacts(t)
	runner, err := NewRunner()
	if err != nil {
		t.Skipf("firecracker unavailable: %v", err)
	}

	job := Job{
		KernelPath: kernel,
		RootFSPath: rootfs,
		OutputPath: outputImage(t),
		Limits:     Limits{VCPUs: 1, MemMiB: 512, Timeout: 20 * time.Second},
	}
	result, err := runner.Run(context.Background(), job)
	if err != nil {
		t.Fatalf("run: %v\nconsole:\n%s", err, result.Console)
	}
	console := string(result.Console)
	if len(console) == 0 {
		t.Fatal("no console output — the guest did not boot")
	}
	// It booted at all.
	if !strings.Contains(console, "Linux version") {
		t.Fatalf("no kernel banner in console:\n%s", truncate(console))
	}

	// No NIC. Matched on device names in the kernel's own log: a guest with an
	// interface announces it, and its absence here is the guarantee holding.
	nic := regexp.MustCompile(`(?m)\b(eth\d|ens\d|enp\ds\d|virtio_net)\b`)
	if found := nic.FindString(console); found != "" {
		t.Errorf("guest has a network device: %q", found)
	}
	// virtio-net driver must not even initialise.
	if strings.Contains(console, "virtio_net") {
		t.Error("virtio_net driver loaded in the guest")
	}
}

// A guest that ignores every request to stop must still stop.
//
// The Ubuntu rootfs boots to a login prompt and sits there forever, which is a
// perfectly good stand-in for a hostile payload that simply declines to exit:
// both hold the slot until something takes it away. If teardown only worked for
// cooperative guests it would work in every test and none of the real cases.
func TestGuestThatNeverExitsIsKilledAtTheDeadline(t *testing.T) {
	kernel, rootfs := artifacts(t)
	runner, err := NewRunner()
	if err != nil {
		t.Skipf("firecracker unavailable: %v", err)
	}

	before := firecrackerPIDs(t)
	job := Job{
		KernelPath: kernel,
		RootFSPath: rootfs,
		OutputPath: outputImage(t),
		Limits:     Limits{VCPUs: 1, MemMiB: 256, Timeout: 8 * time.Second},
	}

	started := time.Now()
	result, err := runner.Run(context.Background(), job)
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("run returned an error instead of a timeout result: %v", err)
	}
	if !result.TimedOut {
		t.Error("a guest that never exits was not reported as timed out")
	}
	// The deadline must actually bound the wait. A generous ceiling: the point
	// is that it returned near its deadline rather than whenever the guest felt
	// like it, not that the kill is instant.
	if elapsed > 20*time.Second {
		t.Errorf("run took %s for an 8s timeout", elapsed)
	}

	// And nothing is left behind. This is the assertion the whole teardown
	// design exists for — a leaked VM per job is invisible until the volunteer's
	// machine is full of them.
	time.Sleep(500 * time.Millisecond)
	after := firecrackerPIDs(t)
	for pid := range after {
		if !before[pid] {
			t.Errorf("leaked a firecracker process (pid %d) after teardown", pid)
		}
	}
}

// A cancelled context must tear the guest down too — a node shutting down, or a
// job the requester withdrew, is the same problem as a deadline.
func TestCancelledContextTearsDownTheGuest(t *testing.T) {
	kernel, rootfs := artifacts(t)
	runner, err := NewRunner()
	if err != nil {
		t.Skipf("firecracker unavailable: %v", err)
	}

	before := firecrackerPIDs(t)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(3 * time.Second)
		cancel()
	}()

	job := Job{
		KernelPath: kernel,
		RootFSPath: rootfs,
		OutputPath: outputImage(t),
		Limits:     Limits{VCPUs: 1, MemMiB: 256, Timeout: 5 * time.Minute},
	}
	started := time.Now()
	if _, err := runner.Run(ctx, job); err != nil {
		t.Logf("run returned %v", err)
	}
	if elapsed := time.Since(started); elapsed > 30*time.Second {
		t.Errorf("cancellation took %s to stop the guest", elapsed)
	}

	time.Sleep(500 * time.Millisecond)
	for pid := range firecrackerPIDs(t) {
		if !before[pid] {
			t.Errorf("leaked a firecracker process (pid %d) after cancellation", pid)
		}
	}
}

func firecrackerPIDs(t *testing.T) map[int]bool {
	t.Helper()
	out := map[int]bool{}
	raw, err := exec.Command("pgrep", "-x", "firecracker").Output()
	if err != nil {
		return out // none running
	}
	for _, line := range strings.Fields(string(raw)) {
		pid := 0
		for _, c := range line {
			if c < '0' || c > '9' {
				pid = 0
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid > 0 {
			out[pid] = true
		}
	}
	return out
}

func truncate(s string) string {
	if len(s) <= 2000 {
		return s
	}
	return s[:2000] + "\n… truncated"
}
