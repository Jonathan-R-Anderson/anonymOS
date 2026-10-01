//go:build linux

package compute

import "testing"

// A card that is PRESENT is not a card that is USABLE, and the difference is
// the whole reason vendor tools are consulted at all. Advertising an unusable
// GPU costs a requester their deadline and this node its reputation, for a
// capability it never had.
func TestABrokenDriverIsNotAWorkingOne(t *testing.T) {
	// Verbatim from a machine with a kernel-module version mismatch. Taken as
	// a model name once, which marked the card usable — the exact confusion
	// this code exists to prevent, arriving through the tool meant to prevent
	// it.
	broken := "Failed to initialize NVML: Driver/library version mismatch"

	for _, output := range []string{broken, "", "   ", "no comma here", "Some GPU, notanumber"} {
		gpus := []GPUInfo{{Vendor: "nvidia"}}
		applyNVIDIA(gpus, output)
		if gpus[0].DriverOK {
			t.Fatalf("claimed a working driver from %q", output)
		}
		if gpus[0].Model != "" {
			t.Fatalf("took %q as a model name", gpus[0].Model)
		}
	}
}

func TestAWorkingDriverIsRecorded(t *testing.T) {
	gpus := []GPUInfo{{Vendor: "nvidia"}}
	applyNVIDIA(gpus, "NVIDIA GeForce RTX 4090, 24564")
	if !gpus[0].DriverOK {
		t.Fatal("a well-formed row did not mark the driver usable")
	}
	if gpus[0].Model != "NVIDIA GeForce RTX 4090" {
		t.Fatalf("model %q", gpus[0].Model)
	}
	if want := int64(24564) * 1024 * 1024; gpus[0].VRAMBytes != want {
		t.Fatalf("vram %d, want %d", gpus[0].VRAMBytes, want)
	}
}

func TestPhysicalCoresCountTopologyNotHalfOfLogical(t *testing.T) {
	// Two threads on each of two cores. Dividing logical by two happens to work
	// here and breaks on SMT-disabled, asymmetric (P/E) and 4-way-SMT machines,
	// all of which exist in the volunteer population.
	var info CPUInfo
	parseCPUInfo(`processor	: 0
model name	: Test CPU
physical id	: 0
core id		: 0
flags		: avx2 sse4_2 nonsense

processor	: 1
physical id	: 0
core id		: 1

processor	: 2
physical id	: 0
core id		: 0

processor	: 3
physical id	: 0
core id		: 1
`, &info)
	if info.PhysicalCores != 2 {
		t.Fatalf("physical cores %d, want 2", info.PhysicalCores)
	}
	if info.Model != "Test CPU" {
		t.Fatalf("model %q", info.Model)
	}
	// Only flags a job could REQUIRE, not all hundred-odd.
	if len(info.Features) != 2 {
		t.Fatalf("features %v, want avx2 and sse4_2 only", info.Features)
	}
}
