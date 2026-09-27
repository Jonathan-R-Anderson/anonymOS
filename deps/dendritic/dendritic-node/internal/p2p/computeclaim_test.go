package p2p

import "testing"

// TestComputeIsNotAdvertisedUntilTheCatalogueIsHeld.
//
// The heartbeat is the ONE place the network learns what a node offers, so it is
// the one place the claim has to be true. Measured on the live fleet before this
// existed: peers advertised cpu_compute they could not perform, every dispatched
// unit failed, and placement kept choosing them because a missing image arrives
// looking like a failed execution.
func TestComputeIsNotAdvertisedUntilTheCatalogueIsHeld(t *testing.T) {
	node := &Node{}
	node.SetComputeRoles(true, true, true)

	// The default. A node that has not yet established it can run the catalogue
	// has not earned the advertisement, and a node with no container runtime
	// never will.
	if cpu, gpu := node.computeClaim(); cpu || gpu {
		t.Fatalf("compute was advertised before any image was confirmed (cpu=%v gpu=%v)",
			cpu, gpu)
	}

	node.SetComputeCatalogueReady(true)
	if cpu, gpu := node.computeClaim(); !cpu || !gpu {
		t.Fatalf("a node holding its images did not advertise (cpu=%v gpu=%v)", cpu, gpu)
	}

	// And it comes back down. Withdrawing a capability is the correct response
	// to losing it — the alternative is a node that keeps being chosen for work
	// it will fail.
	node.SetComputeCatalogueReady(false)
	if cpu, gpu := node.computeClaim(); cpu || gpu {
		t.Fatal("a node that lost its images kept advertising compute")
	}
}

// TestTheOperatorsSwitchesStillDecide: a ready catalogue must not turn compute
// ON for somebody who never offered it.
func TestTheOperatorsSwitchesStillDecide(t *testing.T) {
	node := &Node{}
	node.SetComputeCatalogueReady(true)

	if cpu, gpu := node.computeClaim(); cpu || gpu {
		t.Fatal("holding an image made a node lend compute its owner never offered")
	}
	node.SetComputeRoles(false, true, true)
	if cpu, gpu := node.computeClaim(); cpu || gpu {
		t.Fatal("compute disabled still advertised devices")
	}
	node.SetComputeRoles(true, true, false)
	cpu, gpu := node.computeClaim()
	if !cpu || gpu {
		t.Fatalf("per-device choices were not preserved (cpu=%v gpu=%v)", cpu, gpu)
	}
}
