//go:build !linux

package compute

// Detection on everything that is not Linux.
//
// The node is built and run on Linux; these exist so the package compiles and
// behaves sanely on a developer's macOS or Windows machine rather than failing
// the build there. They report what the runtime can tell us and claim nothing
// else.
//
// Reporting no GPU on a machine that has one is the correct failure here.
// The alternative — guessing from runtime.GOOS that a Mac has Metal — would
// advertise a capability nothing has been written to use, and every job routed
// to it would fail. An absent capability costs this node some work; a false one
// costs a requester their deadline.

func probeCPU() CPUInfo {
	logical := numCPU()
	return CPUInfo{
		// No topology source here, so physical is reported as logical. It is
		// the honest reading of what is knowable, and this path is for
		// development rather than for scheduling real work.
		PhysicalCores: logical,
		LogicalCores:  logical,
		Arch:          hostArch(),
	}
}

func probeGPUs() []GPUInfo { return nil }
