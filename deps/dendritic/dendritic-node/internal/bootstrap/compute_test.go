package bootstrap

import "testing"

func doc() Document {
	return Document{
		Compute: []ComputePeer{
			{NodeID: "cpu1", Destination: "d1", CPU: true},
			{NodeID: "vm1", Destination: "d2", CPU: true, MicroVM: true},
			{NodeID: "gpu1", Destination: "d3", GPU: true},
			{NodeID: "gpuvm", Destination: "d4", GPU: true, MicroVM: true},
			{NodeID: "nameless", Destination: "", CPU: true},
		},
	}
}

// A listing without a destination is a name, not a provider. Filtering here
// means a caller never builds a plan around a peer it cannot reach.
func TestUnreachablePeersAreExcluded(t *testing.T) {
	for _, p := range doc().ComputePeers("cpu", false) {
		if p.NodeID == "nameless" {
			t.Fatal("a peer with no destination was offered as a provider")
		}
	}
	if (ComputePeer{NodeID: "x"}).Reachable() {
		t.Error("a peer with no destination reported reachable")
	}
	if (ComputePeer{Destination: "d"}).Reachable() {
		t.Error("a peer with no id reported reachable")
	}
}

// THE rule, duplicated on the node side deliberately: a node choosing its own
// peers must not depend on the directory having filtered correctly, or a
// compromised listing could place arbitrary code on a container node.
func TestArbitraryWorkOnlyMatchesMicroVMPeers(t *testing.T) {
	got := doc().ComputePeers("cpu", true)
	if len(got) != 1 || got[0].NodeID != "vm1" {
		t.Fatalf("arbitrary CPU work matched %v, want only vm1", ids(got))
	}
	gpu := doc().ComputePeers("gpu:cuda", true)
	if len(gpu) != 1 || gpu[0].NodeID != "gpuvm" {
		t.Fatalf("arbitrary GPU work matched %v, want only gpuvm", ids(gpu))
	}
}

// Catalogue work must still reach container nodes, or the compute pool empties:
// most volunteers have no KVM.
func TestCatalogueWorkMatchesContainerPeers(t *testing.T) {
	got := doc().ComputePeers("cpu", false)
	if len(got) != 2 {
		t.Fatalf("catalogue CPU work matched %v, want cpu1 and vm1", ids(got))
	}
}

// A CPU-only node must never be offered GPU work.
func TestDeviceIsMatchedNotAssumed(t *testing.T) {
	for _, p := range doc().ComputePeers("gpu:rocm", false) {
		if !p.GPU {
			t.Fatalf("%s was offered GPU work without a GPU", p.NodeID)
		}
	}
	for _, p := range doc().ComputePeers("cpu", false) {
		if !p.CPU {
			t.Fatalf("%s was offered CPU work without CPU", p.NodeID)
		}
	}
}

// An empty document must yield nothing rather than panicking — a node bootstraps
// against whatever it is given, including a network with no compute yet.
func TestEmptyDocumentYieldsNoPeers(t *testing.T) {
	if got := (Document{}).ComputePeers("cpu", false); len(got) != 0 {
		t.Fatalf("empty document produced %d peers", len(got))
	}
}

func ids(peers []ComputePeer) []string {
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		out = append(out, p.NodeID)
	}
	return out
}
