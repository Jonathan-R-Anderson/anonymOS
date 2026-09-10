//go:build linux

package compute

// Linux microVM detection. The type and the reasoning live in microvm.go.

import (
	"os"
	"os/exec"
	"strings"
)

func probeMicroVM() MicroVM {
	out := MicroVM{}

	// CPU support first, because it is the one blocker that cannot be fixed by
	// installing something.
	if data, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		out.CPUVirt = hasVirtFlag(string(data))
	}

	if _, err := os.Stat("/dev/kvm"); err == nil {
		out.KVMDevice = true
		// Opened rather than stat'ed for permission: mode bits and group
		// membership are two independent ways to be wrong about the same
		// question, and opening it answers the question that actually matters.
		// Closed immediately — this is a probe, not a reservation.
		//
		// Not hypothetical. The first machine this ran on has /dev/kvm as
		// crw-rw----+ root:kvm with the operator NOT in the kvm group — access
		// comes from a POSIX ACL (`user:bruns:rw-`) that the mode bits and the
		// group list both fail to mention. Checking either would have reported
		// a perfectly capable host as blocked, and sent its operator to fix a
		// group membership that was never the problem.
		if file, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err == nil {
			out.KVMWritable = true
			_ = file.Close()
		}
	}

	if path, err := exec.LookPath("firecracker"); err == nil {
		out.Firecracker = path
	}

	out.Reason = blockerFor(out)
	out.Usable = out.Reason == ""
	return out
}

// hasVirtFlag looks for VT-x/AMD-V in a /proc/cpuinfo dump.
//
// Matched against the flags LINE rather than the whole file: "svm" and "vmx"
// are short enough to appear inside a CPU model name, and a substring search
// over the entire file would report virtualisation support on the strength of a
// marketing string.
func hasVirtFlag(cpuinfo string) bool {
	for _, line := range strings.Split(cpuinfo, "\n") {
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		key := strings.TrimSpace(line[:colon])
		if key != "flags" && key != "Features" {
			continue
		}
		for _, flag := range strings.Fields(line[colon+1:]) {
			if flag == "vmx" || flag == "svm" {
				return true
			}
		}
	}
	return false
}

// blockerFor names the next thing to fix, or "" when nothing blocks.
//
// Ordered by which blocker bites first, not by which is easiest to fix: telling
// someone to install firecracker on a machine whose CPU cannot virtualise wastes
// their time and makes the real answer harder to find.
func blockerFor(m MicroVM) string {
	switch {
	case !m.CPUVirt:
		return "this CPU reports no virtualisation support (no vmx/svm), or it " +
			"is disabled in firmware"
	case !m.KVMDevice:
		return "/dev/kvm is missing — the kvm module is not loaded, or this is " +
			"a VM without nested virtualisation enabled"
	case !m.KVMWritable:
		return "/dev/kvm exists but this user cannot open it — usually means " +
			"adding the node's user to the 'kvm' group"
	case m.Firecracker == "":
		return "firecracker is not installed or not on PATH"
	}
	return ""
}
