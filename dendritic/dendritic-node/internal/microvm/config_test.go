package microvm

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func goodJob() Job {
	return Job{
		KernelPath: "/srv/vmlinux",
		RootFSPath: "/srv/rootfs.squashfs",
		OutputPath: "/srv/out.ext4",
		Limits:     DefaultLimits(),
	}
}

// The headline guarantee. Spec layer 2 is "no network at all" — absent, not
// firewalled — and this is the assertion that says so about the actual bytes
// Firecracker is handed.
func TestConfigNeverGrantsANetworkInterface(t *testing.T) {
	cfg, err := BuildConfig(goodJob())
	if err != nil {
		t.Fatal(err)
	}
	if HasNetworkInterface(cfg) {
		t.Fatalf("config grants a network interface:\n%s", cfg)
	}
	// Asserted on the parsed document too, so a future rename of the JSON key
	// cannot slip past a substring check that is looking for the old name.
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	for key := range parsed {
		if strings.Contains(key, "network") || strings.Contains(key, "vsock") {
			t.Errorf("config carries a %q section", key)
		}
	}
}

// Layer 3: the guest may not write to the image it booted from. Without this a
// job can leave something behind for the next job to find, which is how one
// compromise becomes a permanent one.
func TestRootFilesystemIsAlwaysReadOnly(t *testing.T) {
	cfg, err := BuildConfig(goodJob())
	if err != nil {
		t.Fatal(err)
	}
	var parsed fcConfig
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	var sawRoot bool
	for _, d := range parsed.Drives {
		if d.IsRootDevice {
			sawRoot = true
			if !d.IsReadOnly {
				t.Error("root device is writable")
			}
		}
	}
	if !sawRoot {
		t.Fatal("no root device in config")
	}
}

// The only writable surface must not also be the root. If output were the root
// device the read-only guarantee above would be describing nothing.
func TestOutputIsWritableAndNotTheRoot(t *testing.T) {
	cfg, _ := BuildConfig(goodJob())
	var parsed fcConfig
	if err := json.Unmarshal(cfg, &parsed); err != nil {
		t.Fatal(err)
	}
	var writable int
	for _, d := range parsed.Drives {
		if !d.IsReadOnly {
			writable++
			if d.IsRootDevice {
				t.Error("the writable drive is the root device")
			}
		}
	}
	if writable != 1 {
		t.Errorf("expected exactly 1 writable drive, got %d", writable)
	}
}

// Boot arguments are constructed, never supplied. The kernel command line can
// choose an init and mount filesystems, so a caller who could set it would own
// the guest's entire configuration regardless of every other layer.
func TestBootArgsCannotBeSuppliedByACaller(t *testing.T) {
	// A compile-time fact stated as a test: adding a BootArgs field to Job is
	// the change this guards against, and it would fail here.
	if strings.Contains(structFields(), "BootArgs") {
		t.Fatal("Job exposes BootArgs — the kernel command line is caller-controlled")
	}
	cfg, _ := BuildConfig(goodJob())
	for _, required := range []string{"root=/dev/vda ro", "pci=off", "panic=1", "console=ttyS0"} {
		if !strings.Contains(string(cfg), required) {
			t.Errorf("boot args missing %q", required)
		}
	}
}

func TestSMTIsDisabled(t *testing.T) {
	// Sibling hyperthreads share execution resources, which is the channel a
	// good many cross-VM side channels ride on.
	cfg, _ := BuildConfig(goodJob())
	var parsed fcConfig
	_ = json.Unmarshal(cfg, &parsed)
	if parsed.MachineConfig.SMT {
		t.Error("SMT is enabled for an untrusted guest")
	}
}

func TestLimitsAreRejectedNotClamped(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Job)
	}{
		{"too many vcpus", func(j *Job) { j.Limits.VCPUs = MaxVCPUs + 1 }},
		{"no vcpus", func(j *Job) { j.Limits.VCPUs = 0 }},
		{"too little memory", func(j *Job) { j.Limits.MemMiB = MinMemMiB - 1 }},
		{"too much memory", func(j *Job) { j.Limits.MemMiB = MaxMemMiB + 1 }},
		{"no timeout", func(j *Job) { j.Limits.Timeout = 0 }},
		{"endless timeout", func(j *Job) { j.Limits.Timeout = MaxTimout + time.Second }},
		{"no kernel", func(j *Job) { j.KernelPath = "" }},
		{"no rootfs", func(j *Job) { j.RootFSPath = "" }},
		{"no output", func(j *Job) { j.OutputPath = "" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := goodJob()
			tc.mut(&j)
			if err := j.Validate(); err == nil {
				t.Fatal("accepted an invalid job")
			}
			if _, err := BuildConfig(j); err == nil {
				t.Fatal("built a config from an invalid job")
			}
		})
	}
}

// Every layer must survive a job that asks for the maximum of everything —
// resource limits and isolation are independent, and a big job is not a
// trusted one.
func TestIsolationHoldsAtMaximumLimits(t *testing.T) {
	j := goodJob()
	j.Limits = Limits{VCPUs: MaxVCPUs, MemMiB: MaxMemMiB, Timeout: MaxTimout}
	cfg, err := BuildConfig(j)
	if err != nil {
		t.Fatal(err)
	}
	if HasNetworkInterface(cfg) {
		t.Error("a maximal job got a network interface")
	}
	var parsed fcConfig
	_ = json.Unmarshal(cfg, &parsed)
	for _, d := range parsed.Drives {
		if d.IsRootDevice && !d.IsReadOnly {
			t.Error("a maximal job got a writable root")
		}
	}
}

func TestConsoleCapDiscardsOverflowRatherThanFailing(t *testing.T) {
	c := &capped{limit: 32}
	// A guest printing far more than the cap must not make the write fail:
	// a short write can kill the child, turning a log policy into a job failure.
	n, err := c.Write([]byte(strings.Repeat("x", 4096)))
	if err != nil || n != 4096 {
		t.Fatalf("write reported (%d, %v), want (4096, nil)", n, err)
	}
	out := c.Bytes()
	if len(out) > 32+64 {
		t.Errorf("captured %d bytes despite a 32-byte cap", len(out))
	}
	if !strings.Contains(string(out), "truncated") {
		t.Error("truncation is silent — the reader cannot tell output is missing")
	}
}

func TestConsoleUnderCapIsVerbatim(t *testing.T) {
	c := &capped{limit: 1024}
	_, _ = c.Write([]byte("hello"))
	_, _ = c.Write([]byte(" world"))
	if got := string(c.Bytes()); got != "hello world" {
		t.Errorf("got %q", got)
	}
}

// structFields reports Job's field names by REFLECTION.
//
// It was briefly a hand-written string listing the fields, which is worse than
// no test: it passes forever regardless of what Job actually grows, so the
// guard against a caller-controlled kernel command line would have kept
// reporting success the moment somebody added the field it exists to catch.
func structFields() string {
	var names []string
	t := reflect.TypeOf(Job{})
	for i := 0; i < t.NumField(); i++ {
		names = append(names, t.Field(i).Name)
	}
	return strings.Join(names, " ")
}

// The dangerous fields are absent from Job by construction. Enumerated here so
// that adding any of them fails loudly rather than quietly widening what a
// caller may ask for.
func TestJobExposesNoEscapeHatches(t *testing.T) {
	fields := structFields()
	for _, forbidden := range []string{
		"BootArgs", "Network", "NIC", "Vsock", "Device", "Mount", "Privileged",
	} {
		if strings.Contains(fields, forbidden) {
			t.Errorf("Job exposes %q — callers can weaken isolation", forbidden)
		}
	}
}
