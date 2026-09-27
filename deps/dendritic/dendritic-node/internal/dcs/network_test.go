package dcs

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeAttacher records attach/detach so a test can assert the container was
// wired to its destination on launch and torn down on destroy.
type fakeAttacher struct {
	mu       sync.Mutex
	attached []string
	handles  map[string]*fakeHandle
}

type fakeHandle struct {
	detached bool
}

func (h *fakeHandle) Detach() { h.detached = true }

func newFakeAttacher() *fakeAttacher {
	return &fakeAttacher{handles: map[string]*fakeHandle{}}
}

func (a *fakeAttacher) Attach(_ context.Context, containerID string, primaryPort int) (NetworkHandle, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.attached = append(a.attached, containerID)
	h := &fakeHandle{}
	a.handles[containerID] = h
	return h, nil
}

// The full lifecycle: launch attaches the container's network; destroy detaches
// it and purges the address.
func TestLaunchAttachesAndDestroyDetaches(t *testing.T) {
	researcher := newIdentity(t)
	worker := newIdentity(t)
	rt := &fakeRuntime{}
	alloc := NewAddressAllocator(&fakeOpener{}, t.TempDir())
	attacher := newFakeAttacher()
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()}, rt, alloc, &memAudit{})
	agent.SetNetworkAttacher(attacher)
	agent.now = func() time.Time { return time.Unix(1700000000, 0) }

	env, _ := NewEnvelope(researcher, worker.ID(), MethodLaunch,
		DeployRequest{DeploymentID: "scan-1", Image: "sha256:v", Lab: true, RuntimeSecs: 60, PrimaryPort: 8080},
		time.Unix(1700000000, 0))

	reply, err := agent.HandleLaunch(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	// The container's network was attached, so the returned address is reachable.
	if len(attacher.attached) != 1 || attacher.attached[0] != reply.ContainerID {
		t.Fatalf("container network not attached on launch: %v", attacher.attached)
	}
	if got := reply.Note; containsNotBridged(got) {
		t.Fatalf("reply claims unbridged despite an attacher: %q", got)
	}

	// Destroy detaches the network and purges the address.
	if err := agent.Destroy(context.Background(), reply.ContainerID); err != nil {
		t.Fatal(err)
	}
	if !attacher.handles[reply.ContainerID].detached {
		t.Fatal("destroy did not detach the container network")
	}
	if _, ok := alloc.Lookup(reply.ContainerID); ok {
		t.Fatal("destroy did not purge the container address")
	}
	if len(rt.removed) != 1 {
		t.Fatal("destroy did not remove the container")
	}
}

// Without an attacher the address is still returned, but the note is honest
// that it is not yet reachable -- no silent pretence.
func TestLaunchWithoutAttacherIsHonest(t *testing.T) {
	researcher := newIdentity(t)
	worker := newIdentity(t)
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		&fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = func() time.Time { return time.Unix(1700000000, 0) }

	env, _ := NewEnvelope(researcher, worker.ID(), MethodLaunch,
		DeployRequest{DeploymentID: "x", Image: "sha256:v", Lab: true, RuntimeSecs: 60},
		time.Unix(1700000000, 0))
	reply, err := agent.HandleLaunch(context.Background(), env)
	if err != nil {
		t.Fatal(err)
	}
	if !containsNotBridged(reply.Note) {
		t.Fatalf("unbridged launch did not say so: %q", reply.Note)
	}
	if reply.Destination == "" {
		t.Fatal("address should still be allocated even without a bridge")
	}
}

func containsNotBridged(note string) bool {
	return len(note) > 0 && (indexOf(note, "not yet bridged") >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
