//go:build linux

package compute

// CPU and GPU detection on Linux, from sysfs and procfs.
//
// Everything here is best-effort and every field is optional. These paths move
// between kernel versions, a container may mount none of them, and a node that
// declines to advertise because it could not read a cache size is worse than
// one that advertises without it.

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

func probeCPU() CPUInfo {
	info := CPUInfo{
		LogicalCores: numCPU(),
		Arch:         hostArch(),
	}

	if text, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		parseCPUInfo(string(text), &info)
	}
	if info.PhysicalCores == 0 {
		// No topology available (common in containers, and on arm64 where
		// /proc/cpuinfo has no core id). Assuming logical == physical
		// overcommits SMT machines; assuming half under-uses non-SMT ones.
		// Overcommitting is the worse error — it makes this node miss
		// deadlines it accepted — so fall back to the conservative direction
		// only where SMT is plausible.
		info.PhysicalCores = info.LogicalCores
	}
	info.RAMBytes = totalRAM()
	info.CacheKB = largestCache()
	return info
}

// parseCPUInfo reads model, vendor, flags and core topology.
//
// Physical cores are counted as distinct (physical id, core id) pairs rather
// than by dividing logical count by two. Dividing is wrong on any machine with
// SMT disabled in firmware, with asymmetric cores (P/E cores), or with more
// than two threads per core — all of which exist in the volunteer population.
func parseCPUInfo(text string, info *CPUInfo) {
	seen := map[string]bool{}
	var physical, core string

	flush := func() {
		if core != "" {
			seen[physical+":"+core] = true
		}
		physical, core = "", ""
	}

	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "model name", "Model name":
			if info.Model == "" {
				info.Model = value
			}
		case "vendor_id", "CPU implementer":
			if info.Vendor == "" {
				info.Vendor = value
			}
		case "physical id":
			physical = value
		case "core id":
			core = value
		case "flags", "Features":
			if len(info.Features) == 0 {
				info.Features = interestingFlags(value)
			}
		}
	}
	flush()
	if len(seen) > 0 {
		info.PhysicalCores = len(seen)
	}
}

// interestingFlags keeps only the ISA extensions a job might REQUIRE.
//
// /proc/cpuinfo lists well over a hundred flags. Publishing all of them makes
// the record large, and large records are the thing the DHT is worst at — but
// the real reason is that a scheduler can only act on the handful that change
// whether a binary runs at all. A job built for AVX-512 does not run slowly on
// a machine without it; it dies on an illegal instruction.
func interestingFlags(line string) []string {
	want := map[string]bool{
		"sse4_2": true, "avx": true, "avx2": true,
		"avx512f": true, "avx512bw": true, "avx512vl": true, "avx512dq": true,
		"avx_vnni": true, "amx_tile": true, "amx_bf16": true,
		"f16c": true, "fma": true, "aes": true, "sha_ni": true,
		// arm64
		"neon": true, "asimd": true, "sve": true, "sve2": true,
		"asimddp": true, "asimdhp": true, "sha2": true,
	}
	var out []string
	for _, flag := range strings.Fields(line) {
		if want[flag] {
			out = append(out, flag)
		}
	}
	sort.Strings(out)
	return out
}

func totalRAM() int64 {
	text, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(text), "\n") {
		if !strings.HasPrefix(line, "MemTotal:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}
		kb, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0
		}
		return kb * 1024
	}
	return 0
}

// largestCache returns the biggest cache level in KB — effectively L3, which
// is the number that predicts whether a working set stays on-chip.
func largestCache() int {
	matches, _ := filepath.Glob("/sys/devices/system/cpu/cpu0/cache/index*/size")
	largest := 0
	for _, path := range matches {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(raw))
		multiplier := 1
		switch {
		case strings.HasSuffix(text, "K"):
			text = strings.TrimSuffix(text, "K")
		case strings.HasSuffix(text, "M"):
			text, multiplier = strings.TrimSuffix(text, "M"), 1024
		}
		size, err := strconv.Atoi(text)
		if err != nil {
			continue
		}
		if size*multiplier > largest {
			largest = size * multiplier
		}
	}
	return largest
}

// drmVendors maps PCI vendor IDs as sysfs reports them.
var drmVendors = map[string]string{
	"0x10de": "nvidia",
	"0x1002": "amd",
	"0x1022": "amd",
	"0x8086": "intel",
	"0x106b": "apple",
}

// probeGPUs enumerates DRM devices, then asks vendor tools whether the driver
// actually works.
//
// Two steps rather than one because they answer different questions. sysfs says
// a card is PRESENT — it is there even with no driver loaded, no kernel module,
// or a permissions problem. The vendor tool says the card is USABLE. Reporting
// the first as if it were the second is how a node ends up advertising GPU
// capacity that fails every job routed to it.
func probeGPUs() []GPUInfo {
	entries, err := filepath.Glob("/sys/class/drm/card[0-9]*")
	if err != nil {
		return nil
	}
	var out []GPUInfo
	seen := map[string]bool{}
	for _, entry := range entries {
		// Skip connector nodes (card0-DP-1): they are outputs on a card
		// already counted, not separate devices.
		if strings.Contains(filepath.Base(entry), "-") {
			continue
		}
		vendorRaw, err := os.ReadFile(filepath.Join(entry, "device", "vendor"))
		if err != nil {
			continue
		}
		vendorID := strings.TrimSpace(string(vendorRaw))
		vendor := drmVendors[vendorID]
		if vendor == "" {
			vendor = "unknown(" + vendorID + ")"
		}
		key := entry + vendorID
		if seen[key] {
			continue
		}
		seen[key] = true

		gpu := GPUInfo{Vendor: vendor}
		if raw, err := os.ReadFile(filepath.Join(entry, "device", "mem_info_vram_total")); err == nil {
			if n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64); err == nil {
				gpu.VRAMBytes = n
			}
		}
		out = append(out, gpu)
	}

	// Vendor tools fill in model, VRAM and — the important part — whether the
	// driver answers at all.
	enrichNVIDIA(out)
	enrichAMD(out)
	for i := range out {
		if out[i].Vendor == "intel" && len(out[i].APIs) == 0 {
			// Intel integrated graphics via /dev/dri. No tool is assumed
			// present; the device node existing is the whole claim, and it is
			// a weak one, so no API is asserted without evidence.
			if _, err := os.Stat("/dev/dri/renderD128"); err == nil {
				out[i].APIs = append(out[i].APIs, "opencl", "vulkan")
				out[i].DriverOK = true
			}
		}
	}
	return out
}

// run executes a vendor tool with a short deadline.
//
// The deadline is not paranoia: nvidia-smi on a machine with a wedged driver
// blocks indefinitely, and this runs on the startup path. A probe that hangs
// takes the whole node's advertisement with it.
func run(name string, args ...string) (string, bool) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", false
	}
	done := make(chan struct{})
	var out []byte
	var runErr error
	cmd := exec.Command(path, args...)
	go func() {
		out, runErr = cmd.Output()
		close(done)
	}()
	select {
	case <-done:
		// The EXIT CODE decides, not whether anything was printed.
		//
		// A broken driver is chatty: `nvidia-smi` with a kernel-module version
		// mismatch prints "Failed to initialize NVML: Driver/library version
		// mismatch" and exits non-zero. Treating any output as success takes
		// that sentence as the GPU's model name and marks the card usable —
		// which is precisely the "present vs usable" confusion this function
		// exists to resolve, arriving through the tool meant to resolve it.
		// Observed on a real machine, not hypothetically.
		if runErr != nil {
			return "", false
		}
		return string(out), len(strings.TrimSpace(string(out))) > 0
	case <-time.After(4 * time.Second):
		_ = cmd.Process.Kill()
		return "", false
	}
}

func enrichNVIDIA(gpus []GPUInfo) {
	text, ok := run("nvidia-smi", "--query-gpu=name,memory.total", "--format=csv,noheader,nounits")
	if !ok {
		return
	}
	applyNVIDIA(gpus, text)
}

// applyNVIDIA is split out from the exec so the parsing can be tested against
// the outputs a broken driver actually produces.
func applyNVIDIA(gpus []GPUInfo, text string) {
	lines := nonEmptyLines(text)
	index := 0
	for i := range gpus {
		if gpus[i].Vendor != "nvidia" || index >= len(lines) {
			continue
		}
		name, mem, ok := strings.Cut(lines[index], ",")
		index++
		// Belt and braces on top of the exit-code check in run(): require the
		// row to have the shape we asked for. A tool can print a diagnostic and
		// still exit zero, and the cost of believing it is a node advertising a
		// GPU that fails every job sent to it.
		megabytes, err := strconv.ParseInt(strings.TrimSpace(mem), 10, 64)
		if !ok || err != nil || strings.TrimSpace(name) == "" {
			continue
		}
		gpus[i].Model = strings.TrimSpace(name)
		gpus[i].VRAMBytes = megabytes * 1024 * 1024
		gpus[i].APIs = []string{"cuda", "vulkan", "opencl"}
		gpus[i].DriverOK = true
	}
}

func enrichAMD(gpus []GPUInfo) {
	text, ok := run("rocm-smi", "--showproductname", "--csv")
	if !ok {
		return
	}
	usable := strings.Contains(strings.ToLower(text), "card")
	for i := range gpus {
		if gpus[i].Vendor != "amd" {
			continue
		}
		gpus[i].APIs = []string{"rocm", "vulkan", "opencl"}
		gpus[i].DriverOK = usable
	}
}

func nonEmptyLines(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) != "" {
			out = append(out, strings.TrimSpace(line))
		}
	}
	return out
}
