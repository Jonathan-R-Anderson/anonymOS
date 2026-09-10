package compute

// Can this machine host a Firecracker microVM?
//
// M2's architecture rests entirely on hardware virtualisation, so before any of
// it is built the honest question is how much of the volunteer population can
// host it at all. A node that cannot is not broken — it stays a CPU provider,
// which is most of the value today — but the scheduler has to know, because
// placing an isolated job on a machine without KVM fails at guest boot rather
// than at scheduling, and by then the requester has already waited.
//
// WHY THIS IS DETECTION AND NOT A PROMISE
// ---------------------------------------
// Every check here answers "is the mechanism present", never "does it work".
// The only proof a microVM boots on a given machine is booting one, and that
// belongs in the runner rather than in a probe that runs at startup on every
// node. Admission can still refuse a machine this reports as usable.
//
// WHY THE BLOCKERS ARE REPORTED SEPARATELY
// ----------------------------------------
// "No microVMs" has three completely different remedies, and from any distance
// they look identical:
//
//  1. No /dev/kvm. A VPS without nested virtualisation is the common case, and
//     it is invisible from CPU flags alone — the flags say the SILICON can, the
//     device node says whether the KERNEL will let you.
//  2. /dev/kvm present but not openable by this user. Normally group `kvm`.
//     A permissions problem is one command to fix and looks exactly like absent
//     hardware if the two are collapsed into one boolean.
//  3. No firecracker binary. The easiest to fix, and therefore the least
//     interesting, which is why it is checked last.

// MicroVM describes a node's ability to host isolated guests.
type MicroVM struct {
	// Usable is the only field a scheduler should match on. Everything else
	// exists so an operator can tell WHY not.
	Usable bool `json:"usable"`

	KVMDevice   bool   `json:"kvm_device"`   // /dev/kvm exists
	KVMWritable bool   `json:"kvm_writable"` // and this process may open it
	CPUVirt     bool   `json:"cpu_virt"`     // vmx/svm present in CPU flags
	Firecracker string `json:"firecracker,omitempty"`

	// Reason is empty when Usable. Otherwise it names the ONE thing to fix
	// next, in the order the blockers actually bite — an operator acts on the
	// first one, and a list of everything absent obscures which that is.
	Reason string `json:"reason,omitempty"`
}

// Isolated reports whether this node can offer the M2 isolation guarantee.
//
// Named for the guarantee rather than the technology because the capability
// string a job matches on is "isolated", not "firecracker": what a submitter
// needs is the boundary, and the VMM that provides it is this layer's business.
func (m MicroVM) Isolated() bool { return m.Usable }
