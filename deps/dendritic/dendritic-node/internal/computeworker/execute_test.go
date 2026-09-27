//go:build linux

package computeworker

import (
	"errors"
	"testing"

	"github.com/syndichan/maniwani/storage-client/internal/compute"
)

// THE rule. A container is not a boundary for code somebody else wrote, so a
// node without hardware isolation must REFUSE arbitrary payloads rather than
// run them and look like it is working.
func TestArbitraryCodeIsRefusedWithoutAMicroVM(t *testing.T) {
	arbitrary := Payload{Arbitrary: true, Files: map[string]string{"main.py": "print(1)"}}
	if err := Admit(arbitrary, IsolationContainer, false); !errors.Is(err, ErrArbitraryCodeRefused) {
		t.Fatalf("got %v — a container accepted arbitrary code", err)
	}
	if err := Admit(arbitrary, IsolationNone, false); !errors.Is(err, ErrArbitraryCodeRefused) {
		t.Fatal("a node with no isolation accepted arbitrary code")
	}
	if err := Admit(arbitrary, IsolationMicroVM, false); err != nil {
		t.Fatalf("a microVM refused arbitrary code: %v", err)
	}
}

// Catalogue work must still run on container-only nodes — that is the majority
// of the network and refusing it would empty the compute pool.
func TestCatalogueWorkRunsOnContainerNodes(t *testing.T) {
	catalogue := Payload{Arbitrary: false, CatalogueImage: "registry.local/compute-python:latest"}
	if err := Admit(catalogue, IsolationContainer, false); err != nil {
		t.Fatalf("a container node refused catalogue work: %v", err)
	}
}

// Non-arbitrary work with no image is a malformed request, not a silent default.
func TestCatalogueWorkNeedsAnImage(t *testing.T) {
	if err := Admit(Payload{Arbitrary: false}, IsolationMicroVM, false); err == nil {
		t.Fatal("accepted catalogue work with no image named")
	}
}

// GPU passthrough punches through the isolation everything else provides, so it
// is refused by default and requested explicitly.
func TestGPUIsRefusedWithoutPassthrough(t *testing.T) {
	gpu := Payload{Arbitrary: true, NeedsGPU: true}
	if err := Admit(gpu, IsolationMicroVM, false); !errors.Is(err, ErrGPUUnavailable) {
		t.Fatalf("got %v, want ErrGPUUnavailable", err)
	}
	if err := Admit(gpu, IsolationMicroVM, true); err != nil {
		t.Fatalf("GPU work refused where passthrough exists: %v", err)
	}
}

// What a node advertises and what it enforces must come from the same probe, or
// the scheduler routes work to a node that will refuse it.
func TestIsolationTracksTheProbe(t *testing.T) {
	usable := compute.Profile{MicroVM: compute.MicroVM{Usable: true}}
	if IsolationOf(usable) != IsolationMicroVM {
		t.Error("a usable microVM did not report microvm isolation")
	}
	// Every field set but Usable false: still container-only. The scheduler
	// matches on Usable, so a hand-built struct cannot leak through.
	notUsable := compute.Profile{MicroVM: compute.MicroVM{
		CPUVirt: true, KVMDevice: true, KVMWritable: true, Firecracker: "fc",
	}}
	if IsolationOf(notUsable) != IsolationContainer {
		t.Error("an unusable microVM reported hardware isolation")
	}
}

// An executor without a kernel or rootfs must refuse rather than boot nothing.
func TestMicroVMExecutorRefusesWithoutArtifacts(t *testing.T) {
	e := &MicroVMExecutor{}
	if _, _, err := e.Run(nil, Job{ID: "j1"}); !errors.Is(err, ErrArbitraryCodeRefused) {
		t.Fatalf("got %v — ran with no kernel or rootfs", err)
	}
}

func TestIsolationNames(t *testing.T) {
	for iso, want := range map[Isolation]string{
		IsolationMicroVM: "microvm", IsolationContainer: "container", IsolationNone: "none",
	} {
		if iso.String() != want {
			t.Errorf("got %q want %q", iso.String(), want)
		}
	}
}
