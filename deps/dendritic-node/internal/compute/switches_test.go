package compute

import "testing"

// The two switches are a refusal, not a filter. An operator who did not offer
// their GPU has not offered it, and no job-class allowlist may talk the node
// into running GPU work anyway.
func TestDeclinedDeviceIsRefusedRegardlessOfAllowlist(t *testing.T) {
	cpuOnly := Policy{Enabled: true, OfferCPU: true, OfferGPU: false}
	for _, class := range []string{"gpu", "gpu:cuda", "gpu:rocm", "gpu:vulkan"} {
		if cpuOnly.AcceptsClass(class) {
			t.Errorf("accepted %q despite the GPU not being offered", class)
		}
	}
	if !cpuOnly.AcceptsClass("cpu") {
		t.Error("refused CPU work that was offered")
	}

	// And with an allowlist that explicitly names the GPU class — the switch
	// still wins. This is the case the ordering in AcceptsClass exists for.
	withAllowlist := Policy{
		Enabled: true, OfferCPU: true, OfferGPU: false,
		JobClasses: []string{"cpu", "gpu:cuda"},
	}
	if withAllowlist.AcceptsClass("gpu:cuda") {
		t.Error("an allowlist overrode the operator's GPU switch")
	}
}

func TestGPUOnlyOperatorDoesNotGetCPUWork(t *testing.T) {
	gpuOnly := Policy{Enabled: true, OfferCPU: false, OfferGPU: true}
	if gpuOnly.AcceptsClass("cpu") {
		t.Error("accepted CPU work that was not offered")
	}
	if !gpuOnly.AcceptsClass("gpu:cuda") {
		t.Error("refused GPU work that was offered")
	}
}

// Enabled alone lends nothing. "On" is not consent to a specific device, and a
// default that lent both would be consent nobody gave.
func TestEnabledWithoutADeviceLendsNothing(t *testing.T) {
	bare := Policy{Enabled: true}
	for _, class := range []string{"cpu", "gpu", "gpu:cuda"} {
		if bare.AcceptsClass(class) {
			t.Errorf("accepted %q with neither switch set", class)
		}
	}
}

func TestBothSwitchesAcceptBoth(t *testing.T) {
	both := Policy{Enabled: true, OfferCPU: true, OfferGPU: true}
	for _, class := range []string{"cpu", "gpu", "gpu:cuda", "gpu:rocm"} {
		if !both.AcceptsClass(class) {
			t.Errorf("refused %q with both switches set", class)
		}
	}
}

// An unrecognised class must fall through to the allowlist rather than be
// silently treated as CPU work — a class this build does not know about is not
// one it should assume is safe.
func TestUnknownClassFallsThroughToTheAllowlist(t *testing.T) {
	noList := Policy{Enabled: true, OfferCPU: true}
	if !noList.AcceptsClass("fpga") {
		t.Error("an empty allowlist should still mean 'any class I offer'")
	}
	restricted := Policy{Enabled: true, OfferCPU: true, JobClasses: []string{"cpu"}}
	if restricted.AcceptsClass("fpga") {
		t.Error("an unknown class bypassed a restrictive allowlist")
	}
}

// "gpu" must not be matched as a substring of an unrelated class name.
func TestGPUPrefixIsNotMatchedLoosely(t *testing.T) {
	cpuOnly := Policy{Enabled: true, OfferCPU: true}
	// Not a GPU class: it neither equals "gpu" nor starts with "gpu:".
	if isGPUClass("cpu-gpu-hybrid") {
		t.Error("matched a GPU class inside an unrelated name")
	}
	// And so it falls through to the allowlist rather than being refused.
	if !cpuOnly.AcceptsClass("cpu-gpu-hybrid") {
		t.Error("an unrelated class was refused as if it were GPU work")
	}
}

// Workload consent and device consent are two switches answering two questions,
// and neither may stand in for the other. An operator who lends CPU has not
// thereby agreed to every workload the catalogue grows, and one who opted into a
// workload has not offered a device they declined.
func TestWorkloadConsentIsSeparateFromDeviceConsent(t *testing.T) {
	cpuAndEmbed := Policy{
		Enabled: true, OfferCPU: true, OfferGPU: false,
		Workloads: []string{"embed"},
	}
	if !cpuAndEmbed.AcceptsClass("cpu") {
		t.Error("a workload allowlist suppressed the device the operator lent")
	}
	if cpuAndEmbed.AcceptsClass("gpu:cuda") {
		t.Error("a workload allowlist talked the node into GPU work")
	}
	if !cpuAndEmbed.AcceptsWorkload("embed") {
		t.Error("refused the workload the operator listed")
	}
	if cpuAndEmbed.AcceptsWorkload("render") {
		t.Error("accepted a workload the operator never listed")
	}

	// AcceptsWorkload consults ONLY the workload list — a node that lends
	// nothing still answers the workload question the same way, because that
	// question is about purpose and the device switches are about hardware.
	// (What stops such a node running anything is the device check, which the
	// caller asks separately.)
	lendsNothing := Policy{Enabled: true, Workloads: []string{"embed"}}
	if !lendsNothing.AcceptsWorkload("embed") {
		t.Error("AcceptsWorkload started consulting something other than the workload list")
	}
}
