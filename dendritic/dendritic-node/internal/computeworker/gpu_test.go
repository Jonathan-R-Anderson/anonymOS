//go:build linux

package computeworker

import (
	"errors"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

func gpuPolicy() compute.Policy {
	return compute.Policy{Enabled: true, OfferCPU: true, OfferGPU: true}
}

func devices() GPUDevices {
	return GPUDevices{Vendor: "nvidia", Paths: []string{"/dev/nvidiactl", "/dev/nvidia0"}}
}

// THE constraint. A GPU cannot be passed into a Firecracker microVM, so GPU
// work runs in a container — which means it must be catalogue work. Asking for
// both is asking for two things that cannot be true at once.
func TestArbitraryGPUCodeIsRefused(t *testing.T) {
	payload := Payload{Arbitrary: true, NeedsGPU: true}
	if err := AdmitGPU(payload, gpuPolicy(), devices()); !errors.Is(err, ErrGPUNeedsCatalogue) {
		t.Fatalf("got %v, want ErrGPUNeedsCatalogue", err)
	}
	// The refusal must explain the conflict, not merely deny it.
	if err := AdmitGPU(payload, gpuPolicy(), devices()); !contains(err.Error(), "microVM") {
		t.Errorf("refusal does not explain why: %q", err)
	}
}

func TestCatalogueGPUWorkIsAccepted(t *testing.T) {
	payload := Payload{NeedsGPU: true, CatalogueImage: "registry.local/compute-cuda:latest"}
	if err := AdmitGPU(payload, gpuPolicy(), devices()); err != nil {
		t.Fatalf("refused legitimate catalogue GPU work: %v", err)
	}
}

// An operator who did not offer their card must not have it used, whatever the
// job asks for.
func TestGPUNotOfferedIsRefused(t *testing.T) {
	payload := Payload{NeedsGPU: true, CatalogueImage: "img"}
	cpuOnly := compute.Policy{Enabled: true, OfferCPU: true}
	if err := AdmitGPU(payload, cpuOnly, devices()); !errors.Is(err, ErrGPUNotOffered) {
		t.Fatalf("got %v, want ErrGPUNotOffered", err)
	}
}

// A node that offers a GPU it has no device nodes for must refuse, or every job
// routed to it fails after acceptance.
func TestMissingDevicesAreRefused(t *testing.T) {
	payload := Payload{NeedsGPU: true, CatalogueImage: "img"}
	if err := AdmitGPU(payload, gpuPolicy(), GPUDevices{}); !errors.Is(err, ErrNoGPUDevices) {
		t.Fatalf("got %v, want ErrNoGPUDevices", err)
	}
}

// Non-GPU work is unaffected — this rule must not leak into ordinary jobs.
func TestNonGPUWorkPassesThrough(t *testing.T) {
	if err := AdmitGPU(Payload{Arbitrary: true}, gpuPolicy(), GPUDevices{}); err != nil {
		t.Fatalf("a non-GPU payload was caught by the GPU rule: %v", err)
	}
}

// GPU results must record the boundary they actually ran behind. Storing
// "microvm" because the node has KVM would be a lie the record could not later
// be distinguished from the truth.
func TestGPUWorkIsAlwaysRecordedAsContainer(t *testing.T) {
	if GPUIsolation() != IsolationContainer {
		t.Fatal("GPU work claimed microVM isolation it cannot have")
	}
	// Even on a node whose probe reports a usable microVM.
	usable := compute.Profile{MicroVM: compute.MicroVM{Usable: true}}
	if IsolationOf(usable) != IsolationMicroVM {
		t.Fatal("setup")
	}
	if GPUIsolation() == IsolationOf(usable) {
		t.Fatal("GPU isolation tracked the node's probe instead of the truth")
	}
}

// Detection must not panic on a machine with no GPU, which is most of them.
func TestDetectionIsSafeWithoutAGPU(t *testing.T) {
	d, err := DetectGPUDevices()
	if err != nil && !errors.Is(err, ErrNoGPUDevices) {
		t.Fatalf("unexpected error: %v", err)
	}
	if err == nil && len(d.Paths) == 0 {
		t.Error("reported a GPU with no device paths")
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}
