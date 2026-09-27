//go:build linux

package compute

import "testing"

// The flag scan must read the flags LINE, not the file.
//
// This is the trap worth a test: "svm" and "vmx" are three characters, and CPU
// model names are marketing strings nobody controls. A substring search over
// /proc/cpuinfo would report virtualisation support because a chip happened to
// be called something containing "svm" — and the failure surfaces much later,
// as a guest that will not boot on a node that advertised it could.
func TestVirtFlagIsNotMatchedInsideAModelName(t *testing.T) {
	cpuinfo := "processor\t: 0\n" +
		"model name\t: Vendor Transvmxion svm-Edition 9000\n" +
		"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep\n"
	if hasVirtFlag(cpuinfo) {
		t.Fatal("matched a virtualisation flag inside the model name")
	}
}

func TestVirtFlagFoundOnIntelAndAMD(t *testing.T) {
	intel := "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep vmx smx est\n"
	amd := "flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep svm nx mmxext\n"
	if !hasVirtFlag(intel) {
		t.Error("missed vmx")
	}
	if !hasVirtFlag(amd) {
		t.Error("missed svm")
	}
}

// aarch64 has no vmx/svm at all, and its flags key is "Features". Detecting
// nothing there is correct; claiming support would be worse.
func TestArmFlagsLineDoesNotFalselyClaimSupport(t *testing.T) {
	arm := "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics\n"
	if hasVirtFlag(arm) {
		t.Fatal("claimed x86 virtualisation flags on an ARM flags line")
	}
}

func TestEmptyCPUInfoIsNotSupport(t *testing.T) {
	if hasVirtFlag("") {
		t.Fatal("empty cpuinfo reported virtualisation support")
	}
}

// Each blocker must name the ONE next thing to fix, in the order they bite.
// A machine with no KVM module also has no firecracker binary; telling the
// operator about the binary sends them to install something that will still
// not work.
func TestBlockerNamesTheFirstThingToFix(t *testing.T) {
	cases := []struct {
		name  string
		in    MicroVM
		want  string
		empty bool
	}{
		{name: "no cpu support", in: MicroVM{}, want: "virtualisation support"},
		{
			name: "cpu but no device",
			in:   MicroVM{CPUVirt: true},
			want: "/dev/kvm is missing",
		},
		{
			name: "device but no permission",
			in:   MicroVM{CPUVirt: true, KVMDevice: true},
			want: "'kvm' group",
		},
		{
			name: "all but the binary",
			in:   MicroVM{CPUVirt: true, KVMDevice: true, KVMWritable: true},
			want: "firecracker is not installed",
		},
		{
			name: "nothing missing",
			in: MicroVM{
				CPUVirt: true, KVMDevice: true, KVMWritable: true,
				Firecracker: "/usr/bin/firecracker",
			},
			empty: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := blockerFor(tc.in)
			if tc.empty {
				if got != "" {
					t.Fatalf("expected no blocker, got %q", got)
				}
				return
			}
			if got == "" {
				t.Fatal("expected a blocker, got none")
			}
			if !contains(got, tc.want) {
				t.Fatalf("blocker %q does not mention %q", got, tc.want)
			}
		})
	}
}

// A machine missing any one piece must not advertise the capability. This is
// the whole point of the probe: "isolated" routes the work that most needs a
// boundary, so a partial answer has to read as no.
func TestIsolatedRequiresEveryPiece(t *testing.T) {
	full := MicroVM{
		CPUVirt: true, KVMDevice: true, KVMWritable: true,
		Firecracker: "/usr/bin/firecracker",
	}
	if blockerFor(full) != "" {
		t.Fatal("a fully-equipped machine reported a blocker")
	}

	missing := []MicroVM{
		{KVMDevice: true, KVMWritable: true, Firecracker: "fc"},
		{CPUVirt: true, KVMWritable: true, Firecracker: "fc"},
		{CPUVirt: true, KVMDevice: true, Firecracker: "fc"},
		{CPUVirt: true, KVMDevice: true, KVMWritable: true},
	}
	for i, m := range missing {
		if blockerFor(m) == "" {
			t.Errorf("case %d: incomplete machine reported no blocker", i)
		}
		profile := Profile{MicroVM: m}
		for _, c := range profile.Capabilities() {
			if c == "isolated" {
				t.Errorf("case %d: advertised 'isolated' while incomplete", i)
			}
		}
	}
}

func TestCapabilityAppearsOnlyWhenUsable(t *testing.T) {
	yes := Profile{MicroVM: MicroVM{Usable: true}}
	if !hasCap(yes.Capabilities(), "isolated") {
		t.Error("a usable machine did not advertise 'isolated'")
	}
	// Usable false with everything else true should still not advertise: the
	// scheduler matches Usable, so a stale or hand-built struct cannot leak.
	no := Profile{MicroVM: MicroVM{
		CPUVirt: true, KVMDevice: true, KVMWritable: true, Firecracker: "fc",
	}}
	if hasCap(no.Capabilities(), "isolated") {
		t.Error("advertised 'isolated' without Usable set")
	}
}

// The probe must never panic or block on a real machine, whatever it finds —
// it runs at startup on every node, and a probe that dies takes the node with
// it for a capability the node did not need.
func TestProbeIsSafeOnThisMachine(t *testing.T) {
	got := probeMicroVM()
	if got.Usable && got.Reason != "" {
		t.Errorf("usable machine still carries a blocker: %q", got.Reason)
	}
	if !got.Usable && got.Reason == "" {
		t.Error("unusable machine gave no reason")
	}
}

func hasCap(caps []string, want string) bool {
	for _, c := range caps {
		if c == want {
			return true
		}
	}
	return false
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
