// Package microvm boots a Firecracker guest to run one untrusted job.
//
// M2's layers 1-4 and 10-11, made executable. The organising rule is that the
// dangerous configurations are not merely defaulted off — they are
// UNREPRESENTABLE. There is no network field to set, no writable-root field to
// flip, no device list to append to. A caller cannot ask for them, so no future
// caller can be talked into asking for them, and no code review has to catch it.
//
// WHY CONFIG BUILDING IS A PURE FUNCTION
// --------------------------------------
// Everything that decides the guest's isolation is decided here, in a function
// that takes a Job and returns bytes. That means the guarantees can be tested
// without KVM, without root, and without booting anything — the test asserts on
// the JSON that Firecracker will be handed. A boot test proves the mechanism
// works; these prove the POLICY is what we think it is, and policy is what
// silently rots when someone adds a feature.
package microvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Limits are the resource ceilings from spec layer 10.
//
// Present as values rather than "unlimited by default" because a guest with no
// memory cap can drive the HOST into the OOM killer, which kills whatever the
// kernel picks — quite possibly the volunteer's browser rather than the job.
type Limits struct {
	VCPUs   int
	MemMiB  int
	Timeout time.Duration
}

// Sane bounds. A volunteer machine is somebody's desktop: the ceiling exists so
// a submitted job cannot request the whole machine, and the floor exists
// because a guest that cannot boot wastes the slot and reports a confusing
// failure rather than an honest refusal.
const (
	MinMemMiB = 128
	MaxMemMiB = 16384
	MaxVCPUs  = 32
	MaxTimout = 6 * time.Hour
)

// DefaultLimits are deliberately modest — the common job is small, and a
// default that reserves a lot of a volunteer's machine is a default that gets
// the node uninstalled.
func DefaultLimits() Limits {
	return Limits{VCPUs: 1, MemMiB: 512, Timeout: 5 * time.Minute}
}

// Job is everything a caller may specify. Note what is absent: no network, no
// devices, no boot arguments, no writable root. See the package comment.
type Job struct {
	// KernelPath and RootFSPath are host paths supplied by the NODE, not by the
	// submitter. A submitter who could name the rootfs could name one of the
	// host's own files and read it out.
	KernelPath string
	RootFSPath string

	// OutputPath is a pre-made writable image the guest mounts at /output. It
	// is the only writable thing in the VM and the only thing that survives it.
	OutputPath string

	Limits Limits
}

// fcConfig is Firecracker's config-file schema, restricted to the subset we
// will ever emit.
//
// Deliberately NOT a general binding to Firecracker's API. A complete binding
// would carry NetworkInterfaces and Vsock fields, and a field that exists is a
// field something can set. The type system is doing security work here.
type fcConfig struct {
	BootSource    bootSource    `json:"boot-source"`
	Drives        []drive       `json:"drives"`
	MachineConfig machineConfig `json:"machine-config"`
}

type bootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type machineConfig struct {
	VcpuCount  int `json:"vcpu_count"`
	MemSizeMib int `json:"mem_size_mib"`
	// SMT off. Sibling hyperthreads share execution resources, and that sharing
	// is the channel a good many cross-VM side-channel attacks ride on. A
	// volunteer's other VM — or the host — should not be co-resident on a core
	// with an untrusted guest.
	SMT bool `json:"smt"`
}

// bootArgs are constructed, never accepted from a caller.
//
// The kernel command line can mount filesystems, choose an init, and enable
// debugging interfaces. Accepting a caller's string here would hand the guest's
// entire configuration to whoever submits the job — the one place where "just
// pass it through" undoes every layer below it.
//
//	console=ttyS0   serial only; there is no framebuffer to attach to (layer 6)
//	reboot=k        a guest reboot becomes a clean exit rather than a hung VM
//	panic=1         panic exits immediately instead of sitting there holding a slot
//	pci=off         no PCI bus to enumerate — nothing to find (layer 4)
//	root=/dev/vda ro  read-only root (layer 3)
//	random.trust_cpu=on  RDRAND seeds the guest; there is no entropy daemon and
//	                     a guest blocking forever on /dev/random looks like a hang
const bootArgs = "console=ttyS0 reboot=k panic=1 pci=off " +
	"root=/dev/vda ro random.trust_cpu=on i8042.noaux i8042.nokbd"

var (
	ErrNoKernel  = errors.New("microvm: no kernel image")
	ErrNoRootFS  = errors.New("microvm: no root filesystem")
	ErrNoOutput  = errors.New("microvm: no output image")
	ErrBadLimits = errors.New("microvm: limits out of range")
)

// Validate checks a job before anything is spawned.
//
// Errors rather than clamping. A caller that asked for 64 vCPUs on an 8-core
// machine has misunderstood something, and silently giving it 8 produces a job
// that runs four times slower than the requester budgeted for with no
// indication why — a wrong answer about performance is still a wrong answer.
func (j Job) Validate() error {
	switch {
	case j.KernelPath == "":
		return ErrNoKernel
	case j.RootFSPath == "":
		return ErrNoRootFS
	case j.OutputPath == "":
		return ErrNoOutput
	}
	l := j.Limits
	if l.VCPUs < 1 || l.VCPUs > MaxVCPUs {
		return fmt.Errorf("%w: vcpus %d not in 1..%d", ErrBadLimits, l.VCPUs, MaxVCPUs)
	}
	if l.MemMiB < MinMemMiB || l.MemMiB > MaxMemMiB {
		return fmt.Errorf("%w: memory %d MiB not in %d..%d",
			ErrBadLimits, l.MemMiB, MinMemMiB, MaxMemMiB)
	}
	if l.Timeout <= 0 || l.Timeout > MaxTimout {
		return fmt.Errorf("%w: timeout %s not in 0..%s", ErrBadLimits, l.Timeout, MaxTimout)
	}
	return nil
}

// BuildConfig renders the Firecracker config for a job.
//
// Exported so the boot path and the tests read the SAME bytes. A test that
// built its own approximation of the config would assert on something the
// runner never runs.
func BuildConfig(j Job) ([]byte, error) {
	if err := j.Validate(); err != nil {
		return nil, err
	}
	cfg := fcConfig{
		BootSource: bootSource{KernelImagePath: j.KernelPath, BootArgs: bootArgs},
		Drives: []drive{
			// Root: read-only, always. The guest may not modify the image it
			// booted from, so one job cannot leave anything behind for the next
			// one to find — persistence across jobs is how a single compromise
			// becomes a permanent one.
			{DriveID: "rootfs", PathOnHost: j.RootFSPath, IsRootDevice: true, IsReadOnly: true},
			// Output: the single writable surface, and not the root device.
			{DriveID: "output", PathOnHost: j.OutputPath, IsRootDevice: false, IsReadOnly: false},
		},
		MachineConfig: machineConfig{
			VcpuCount:  j.Limits.VCPUs,
			MemSizeMib: j.Limits.MemMiB,
			SMT:        false,
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// HasNetworkInterface reports whether a rendered config would give the guest a
// NIC.
//
// A belt-and-braces assertion the runner itself can call. The type system
// already makes a network interface unrepresentable, so this can only fail if
// somebody adds the field back — which is exactly the change worth catching,
// and exactly the one whose author will not think to look here.
func HasNetworkInterface(cfg []byte) bool {
	text := string(cfg)
	return strings.Contains(text, "network-interfaces") ||
		strings.Contains(text, "host_dev_name") ||
		strings.Contains(text, "guest_mac")
}
