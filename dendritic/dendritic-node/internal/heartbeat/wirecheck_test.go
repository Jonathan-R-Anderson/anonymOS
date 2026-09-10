package heartbeat

import (
	"context"
	"os"
	"testing"
)

// Not a test of behaviour: a way to get the EXACT bytes a real node puts on the
// wire out of the Go side and into the Python coordinator's validator, so the
// two languages' field names are checked against each other rather than against
// two readings of the same document. Runs only when asked.
func TestDumpWireBody(t *testing.T) {
	path := os.Getenv("HEARTBEAT_WIRE_DUMP")
	if path == "" {
		t.Skip("set HEARTBEAT_WIRE_DUMP to write a sample body")
	}
	server, seen := capture(t)
	outstanding, deferred, unreadable := 2, 1, 0
	client := &Client{
		Signer: newTestSigner(t), Endpoint: server.URL, HTTP: server.Client(),
		Snapshot: func() State {
			return State{
				CapacityBytes: 20 << 30, UsedBytes: 3 << 30,
				Traffic: Traffic{Bytes: 1 << 20, Requests: 12, WindowSeconds: 300},
				Placement: &Placement{
					Objects: 11640, UnderReplicated: 402, LocalOnly: 7,
					FullyDispersed: 11238, Placed: 6, Failed: 3, Unassignable: 0,
					Attempted: 40, Peers: 9, AgeSeconds: 118,
					RecallsOutstanding: &outstanding,
					RecallsDeferred:    &deferred,
					RecallsUnreadable:  &unreadable,
					Refusals: []Refusal{
						{Peer: "12D3KooWFullDis", Count: 3, Reason: "storage capacity exceeded"},
						{Peer: "12D3KooWCacheOn", Count: 3, Reason: "node is cache-only"},
					},
				},
			}
		},
	}
	client.Send(context.Background())
	if err := os.WriteFile(path, (<-seen).body, 0o644); err != nil {
		t.Fatal(err)
	}
}
