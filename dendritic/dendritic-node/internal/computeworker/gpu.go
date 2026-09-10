//go:build linux

package computeworker

// GPU work, and the constraint that shapes all of it.
//
// FIRECRACKER CANNOT PASS THROUGH A GPU
// -------------------------------------
// Not a limitation of this code — a property of the VMM. Firecracker has no PCI
// bus at all (which is why the guest boots with `pci=off`), and GPU passthrough
// requires VFIO, which requires PCI. There is no configuration that makes this
// work.
//
// So the two things a submitter might want cannot both be had here:
//
//	arbitrary code   →  microVM   →  no GPU
//	GPU              →  container →  catalogue images only
//
// WHY THAT MEANS GPU WORK IS CATALOGUE-ONLY
// -----------------------------------------
// The catalogue rule exists because a container is not a boundary to run
// somebody else's code behind. GPU work must run in a container, therefore GPU
// work must be catalogue work. Relaxing that would mean running arbitrary code
// in a container while pointing at a microVM the job never touches.
//
// It is worse than the general case, too. Passthrough hands the guest a device
// node and a closed-source driver shim, and GPU kernel drivers have a long
// history of privilege-escalation CVEs — so a GPU container is a WEAKER
// boundary than an ordinary one, not merely equal to it.
//
// The honest options, if arbitrary GPU code is ever required:
//   - swap the VMM for one with VFIO (Cloud Hypervisor, QEMU), losing
//     Firecracker's small attack surface and fast boot
//   - keep GPU work catalogue-only, which is what this does
//
// The second is chosen deliberately, and this file exists so that choice is
// visible rather than an accident of which VMM someone picked first.

import (
	"errors"
	"fmt"
	"os"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

var (
	// ErrGPUNeedsCatalogue is the refusal that follows from the constraint
	// above. Distinct from ErrGPUUnavailable: the node HAS a GPU and is
	// declining a specific combination, which is a different thing to tell a
	// submitter than "no GPU here".
	ErrGPUNeedsCatalogue = errors.New(
		"computeworker: GPU work must use a signed catalogue image — a GPU cannot " +
			"be passed into a microVM, so arbitrary GPU code would run in a " +
			"container, which is not a strong enough boundary")
	ErrGPUNotOffered = errors.New("computeworker: this node does not lend its GPU")
	ErrNoGPUDevices  = errors.New("computeworker: no usable GPU device nodes found")
)

// GPUDevices are the host device nodes a GPU container needs.
//
// Enumerated explicitly rather than passing --privileged or mounting all of
// /dev. Privileged is not passthrough, it is surrender: it hands the container
// every device on the machine to solve a problem about one of them.
type GPUDevices struct {
	Vendor string
	Paths  []string
}

// DetectGPUDevices finds what a GPU job would need.
//
// Existence only. Whether the driver works is proven by running something, not
// by a stat — and a node that advertised a card whose driver is broken would
// fail every GPU job routed to it, costing the requester a deadline for a
// capability the node never had.
func DetectGPUDevices() (GPUDevices, error) {
	nvidia := []string{"/dev/nvidiactl", "/dev/nvidia-uvm"}
	present := []string{}
	for _, p := range nvidia {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	// The numbered cards. Bounded rather than globbed: an unbounded scan of
	// /dev is a lot of syscalls to answer a question about the first few.
	for i := 0; i < 8; i++ {
		p := fmt.Sprintf("/dev/nvidia%d", i)
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	if len(present) > 2 {
		return GPUDevices{Vendor: "nvidia", Paths: present}, nil
	}

	// AMD exposes render nodes rather than per-card devices.
	amd := []string{"/dev/kfd", "/dev/dri/renderD128"}
	present = present[:0]
	for _, p := range amd {
		if _, err := os.Stat(p); err == nil {
			present = append(present, p)
		}
	}
	if len(present) == len(amd) {
		return GPUDevices{Vendor: "amd", Paths: present}, nil
	}
	return GPUDevices{}, ErrNoGPUDevices
}

// AdmitGPU decides whether a GPU payload may run here.
//
// Separate from Admit because the GPU rule is not a special case of the
// isolation rule — it INVERTS it. Everywhere else, stronger isolation permits
// more; here the strongest isolation permits nothing, because the device cannot
// cross that boundary.
func AdmitGPU(payload Payload, policy compute.Policy, devices GPUDevices) error {
	if !payload.NeedsGPU {
		return nil
	}
	if !policy.Enabled || !policy.OfferGPU {
		return ErrGPUNotOffered
	}
	if len(devices.Paths) == 0 {
		return ErrNoGPUDevices
	}
	// The constraint, enforced. A GPU job that is also arbitrary code has asked
	// for two things that cannot be true at once.
	if payload.Arbitrary {
		return ErrGPUNeedsCatalogue
	}
	if payload.CatalogueImage == "" {
		return fmt.Errorf("computeworker: GPU work needs a catalogue image")
	}
	return nil
}

// GPUIsolation reports what boundary GPU work actually runs behind.
//
// Always container, and never microVM, whatever the node's probe says. Exists so
// a result can record the truth: a GPU result and a CPU microVM result are not
// the same claim, and storing "microvm" for a GPU job because the node has KVM
// would be a lie the record could not later distinguish from the truth.
func GPUIsolation() Isolation { return IsolationContainer }
