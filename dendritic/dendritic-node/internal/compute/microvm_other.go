//go:build !linux

package compute

// microVM detection on everything that is not Linux.
//
// Firecracker requires KVM, which is a Linux kernel interface. There is no
// partial answer to give on macOS or Windows — a different hypervisor is not a
// substitute, because M2's guarantees are stated in terms of what KVM and this
// specific VMM enforce.
//
// So this reports not-usable with a reason that says the platform rather than
// implying something is missing that could be installed.

func probeMicroVM() MicroVM {
	return MicroVM{
		Reason: "microVM isolation requires Linux with KVM; this platform cannot host it",
	}
}
