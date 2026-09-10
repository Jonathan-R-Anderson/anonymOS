// Package compute detects what a node can compute with, and measures it.
//
// This is M1 of roadmap/gpgpu-roadmap.md — the foundation every later milestone
// prices against. A scheduler cannot place work without knowing what is here,
// and a marketplace cannot pay for it without knowing what it is worth.
//
// TWO RULES THIS PACKAGE IS BUILT AROUND
// --------------------------------------
// **Measure, do not read the model number.** A throttled laptop i7 and a
// datacentre i7 report the same name and differ by a factor of several in
// sustained throughput; a GPU's advertised TFLOPS is a spec-sheet peak nothing
// reaches. So every performance figure here comes from actually running
// something (see bench.go), and the identifying strings are labels for humans
// rather than inputs to scheduling.
//
// **A capability record is a CLAIM, not a fact.** Nothing here is trusted: a
// node can lie about any of it. That is deliberately not solved with
// attestation, which would mean trusted hardware and an enrolment problem.
// It is solved economically — a node that overstates itself takes work it
// cannot finish, misses deadlines, and loses reputation. The correction is in
// M8, not here.
//
// NO CGO, DELIBERATELY
// --------------------
// Detection reads sysfs and shells out to vendor tools that may or may not
// exist. It does NOT link NVML, ROCm or Level Zero. Linking them would give
// richer data and make the node unbuildable without vendor SDKs present, on a
// binary whose entire job is to run on other people's machines. A node with no
// GPU must build and run as easily as one with four.
package compute

import (
	"runtime"
	"time"
)

// Profile is everything a scheduler needs to decide whether a job fits here.
// Embedded in the DCS worker record, so it is signed and expiring like every
// other advertisement.
type Profile struct {
	// CPU is always present. GPU may be empty, which is the common case and
	// not a degraded one — most volunteers have no usable GPU and are still
	// providers. See the roadmap's CPU section.
	CPU CPUInfo   `json:"cpu"`
	GPU []GPUInfo `json:"gpu,omitempty"`

	// Bench is the measured figure, from the same kernel a verifier can
	// reproduce. Absent if probing was asked to skip it.
	Bench *Result `json:"bench,omitempty"`

	// MicroVM is whether this machine can host an isolated guest (M2). Always
	// present, including when unusable, because "this node cannot run isolated
	// work and here is why" is the answer an operator needs — omitting it when
	// false would make an unconfigured machine indistinguishable from an old
	// node that predates the field.
	MicroVM MicroVM `json:"microvm"`

	ProbedAt int64 `json:"probed_at"`
}

// CPUInfo describes the processor. Fields a scheduler matches on come first;
// the rest is for humans reading a node page.
type CPUInfo struct {
	// PhysicalCores and LogicalCores differ on SMT machines, and the
	// difference matters: two hyperthreads on one core do not deliver two
	// cores of throughput for compute-bound work, so scheduling by logical
	// count systematically overcommits.
	PhysicalCores int `json:"physical_cores"`
	LogicalCores  int `json:"logical_cores"`

	// Features are ISA extensions a runtime image may require — avx2,
	// avx512f, neon, sve. A job needing AVX-512 on a machine without it does
	// not run slowly, it dies on an illegal instruction, so this is a
	// scheduling input rather than a detail.
	Features []string `json:"features,omitempty"`

	Model    string `json:"model,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	Arch     string `json:"arch"`
	CacheKB  int    `json:"cache_kb,omitempty"`
	RAMBytes int64  `json:"ram_bytes,omitempty"`
}

// GPUInfo describes one device. A machine with two cards has two entries: they
// are separately schedulable and can differ in capability, so collapsing them
// to a single "has GPU" flag loses the thing a scheduler needs.
type GPUInfo struct {
	Vendor string `json:"vendor"` // nvidia, amd, intel, apple
	Model  string `json:"model,omitempty"`
	// APIs a job can target — cuda, rocm, vulkan, opencl, metal. Detected
	// independently of vendor because one card often has several, and the job
	// cares about the API it was built for rather than who made the silicon.
	APIs      []string `json:"apis,omitempty"`
	VRAMBytes int64    `json:"vram_bytes,omitempty"`
	// DriverOK distinguishes "a card is present" from "a card can be used".
	// A GPU with no working driver is a common state, and advertising it as
	// available means every job routed here fails.
	DriverOK bool `json:"driver_ok"`
}

// Options controls how much a probe does.
type Options struct {
	// SkipBenchmark returns identification only. The benchmark costs a second
	// or two of full-tilt CPU, which is fine at startup and rude on a periodic
	// re-advertisement of an idle desktop.
	SkipBenchmark bool
	// BenchTarget is how long the calibrated kernel should run for.
	BenchTarget time.Duration
	// BenchSeed must be shared with anyone expected to verify the digest.
	BenchSeed int64
}

// DefaultOptions: a run short enough not to be noticed, long enough to be
// meaningful on slow hardware. The seed is fixed so every node in the network
// produces a comparable — and mutually verifiable — digest.
func DefaultOptions() Options {
	return Options{BenchTarget: 750 * time.Millisecond, BenchSeed: 0x5359_4e44_4943_4841}
}

// Probe inspects the machine and, unless told not to, measures it.
//
// Never returns an error. Detection is best-effort by nature — sysfs paths
// differ between kernels, vendor tools may be absent, a container may hide
// half of it — and a node that refuses to advertise because it could not read
// a cache size is worse than one that advertises without it. Everything
// optional is omitempty for that reason.
func Probe(opts Options) Profile {
	if opts.BenchTarget <= 0 {
		opts.BenchTarget = DefaultOptions().BenchTarget
	}
	if opts.BenchSeed == 0 {
		opts.BenchSeed = DefaultOptions().BenchSeed
	}

	profile := Profile{
		CPU:      probeCPU(),
		GPU:      probeGPUs(),
		MicroVM:  probeMicroVM(),
		ProbedAt: time.Now().Unix(),
	}
	if !opts.SkipBenchmark {
		result := Calibrate(opts.BenchSeed, opts.BenchTarget)
		profile.Bench = &result
	}
	return profile
}

// Capabilities returns the DCS capability strings this machine can claim.
//
// Note what is NOT here: "gpu" is claimed only when a device reports a working
// driver. A card with no driver is a card no job can use, and advertising it
// means every GPU job routed here fails at startup — which costs the requester
// a deadline and this node its reputation, for a capability it never had.
func (p Profile) Capabilities() []string {
	caps := []string{"cpu"}
	for _, gpu := range p.GPU {
		if gpu.DriverOK {
			caps = append(caps, "gpu")
			break
		}
	}
	// "isolated" is claimed on the same principle as "gpu": only when the
	// mechanism is actually usable. Claiming it on a machine where KVM is
	// present but unopenable would route exactly the work that most needs the
	// boundary to a node that cannot build one.
	if p.MicroVM.Isolated() {
		caps = append(caps, "isolated")
	}
	return caps
}

// HasFeature reports whether the CPU advertises an ISA extension.
func (p Profile) HasFeature(name string) bool {
	for _, f := range p.CPU.Features {
		if f == name {
			return true
		}
	}
	return false
}

// Summary is one line for a log or a node page.
func (p Profile) Summary() string {
	out := p.CPU.Arch
	if p.CPU.Model != "" {
		out = p.CPU.Model
	}
	out += " (" + itoa(p.CPU.PhysicalCores) + " cores"
	if p.CPU.LogicalCores > p.CPU.PhysicalCores {
		out += ", " + itoa(p.CPU.LogicalCores) + " threads"
	}
	out += ")"
	for _, gpu := range p.GPU {
		out += " + " + gpu.Vendor
		if gpu.Model != "" {
			out += " " + gpu.Model
		}
		if !gpu.DriverOK {
			out += " [no driver]"
		}
	}
	if p.Bench != nil {
		out += " — " + itoa(int(p.Bench.OpsPerSecond/1e6)) + "M ops/s/core"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [24]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// hostArch is the fallback when nothing more specific is readable.
func hostArch() string { return runtime.GOARCH }

// numCPU is the logical processor count, wrapped so both detection files use
// one source.
func numCPU() int { return runtime.NumCPU() }
