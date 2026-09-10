package dcs

import (
	"context"
	"testing"
	"time"
)

// A trusted broker (a website's bridge node) deploys for many distinct site
// users through ONE node identity. The worker's one-container-per-owner rule
// must key on each named sub-owner, not on the shared broker identity -- else
// the whole site is capped to a single container per worker. Two different
// sub-owners get two containers; the same sub-owner twice is still blocked.
func TestTrustedBrokerSubAccountsByOnBehalfOf(t *testing.T) {
	now := time.Unix(1700000000, 0)
	worker := newIdentity(t)
	broker := newIdentity(t)

	agent := NewAgent(AgentConfig{
		AcceptsLab:     true,
		NodeID:         worker.ID(),
		TrustedBrokers: []string{broker.ID()},
	}, &fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 4, InstanceTTL: 24 * time.Hour})
	ac.now = fixedClock(now)
	agent.SetAdmission(ac, 24*time.Hour)

	launch := func(req DeployRequest) (DeployReply, error) {
		env, _ := NewEnvelope(broker, worker.ID(), MethodLaunch, req, now)
		return agent.HandleLaunch(context.Background(), env)
	}

	// Same broker, two different site users -> two running containers.
	r1, err := launch(DeployRequest{DeploymentID: "u1", Image: "sha256:a", Lab: true, RuntimeSecs: 3600, OnBehalfOf: "user-1"})
	if err != nil || r1.Queued || r1.ContainerID == "" {
		t.Fatalf("user-1 should be admitted: reply=%+v err=%v", r1, err)
	}
	r2, err := launch(DeployRequest{DeploymentID: "u2", Image: "sha256:a", Lab: true, RuntimeSecs: 3600, OnBehalfOf: "user-2"})
	if err != nil || r2.Queued || r2.ContainerID == "" {
		t.Fatalf("user-2 should be admitted through the same broker: reply=%+v err=%v", r2, err)
	}
	if r1.ContainerID == r2.ContainerID {
		t.Fatal("two sub-owners collapsed to one container")
	}

	// The SAME sub-owner a second time is still one-per-user rejected.
	if _, err := launch(DeployRequest{DeploymentID: "u1b", Image: "sha256:a", Lab: true, RuntimeSecs: 3600, OnBehalfOf: "user-1"}); err == nil {
		t.Fatal("same sub-owner was allowed a second concurrent container")
	}
}

// OnBehalfOf from an UNTRUSTED node is ignored: it accounts by the node id, so a
// stranger cannot dodge the one-per-owner rule by inventing sub-owner tags.
func TestUntrustedNodeCannotSubAccount(t *testing.T) {
	now := time.Unix(1700000000, 0)
	worker := newIdentity(t)
	stranger := newIdentity(t) // NOT in TrustedBrokers

	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		&fakeRuntime{}, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)
	ac := NewAdmissionController(AdmissionConfig{MaxSlots: 4, InstanceTTL: 24 * time.Hour})
	ac.now = fixedClock(now)
	agent.SetAdmission(ac, 24*time.Hour)

	launch := func(behalf string) (DeployReply, error) {
		env, _ := NewEnvelope(stranger, worker.ID(), MethodLaunch,
			DeployRequest{DeploymentID: "d-" + behalf, Image: "sha256:a", Lab: true, RuntimeSecs: 3600, OnBehalfOf: behalf}, now)
		return agent.HandleLaunch(context.Background(), env)
	}

	if r, err := launch("alice"); err != nil || r.ContainerID == "" {
		t.Fatalf("first deploy should be admitted: %+v %v", r, err)
	}
	// A second "different" sub-owner must NOT get a slot: the stranger is one owner.
	if _, err := launch("bob"); err == nil {
		t.Fatal("untrusted node sub-accounted its way to a second container")
	}
}

// Only the node that deployed a container may destroy it. A different node's
// signed Destroy for someone else's container is refused.
func TestHandleDestroyOwnerChecked(t *testing.T) {
	now := time.Unix(1700000000, 0)
	worker := newIdentity(t)
	owner := newIdentity(t)
	other := newIdentity(t)

	rt := &fakeRuntime{}
	agent := NewAgent(AgentConfig{AcceptsLab: true, NodeID: worker.ID()},
		rt, NewAddressAllocator(&fakeOpener{}, t.TempDir()), &memAudit{})
	agent.now = fixedClock(now)

	// Deploy one container as `owner`.
	env, _ := NewEnvelope(owner, worker.ID(), MethodLaunch,
		DeployRequest{DeploymentID: "d1", Image: "sha256:a", Lab: true, RuntimeSecs: 3600}, now)
	reply, err := agent.HandleLaunch(context.Background(), env)
	if err != nil || reply.ContainerID == "" {
		t.Fatalf("deploy failed: %+v %v", reply, err)
	}

	// A stranger cannot destroy it.
	badEnv, _ := NewEnvelope(other, worker.ID(), MethodDestroy,
		map[string]string{"container_id": reply.ContainerID}, now)
	if err := agent.HandleDestroy(context.Background(), badEnv); err == nil {
		t.Fatal("a non-owner was allowed to destroy the container")
	}
	if len(rt.removed) != 0 {
		t.Fatalf("container was removed by a non-owner: %v", rt.removed)
	}

	// The owner can.
	goodEnv, _ := NewEnvelope(owner, worker.ID(), MethodDestroy,
		map[string]string{"container_id": reply.ContainerID}, now)
	if err := agent.HandleDestroy(context.Background(), goodEnv); err != nil {
		t.Fatalf("owner could not destroy its own container: %v", err)
	}
	if len(rt.removed) != 1 || rt.removed[0] != reply.ContainerID {
		t.Fatalf("expected the owner's container removed, got %v", rt.removed)
	}
}
