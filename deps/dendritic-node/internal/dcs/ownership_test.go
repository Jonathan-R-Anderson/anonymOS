package dcs

import (
	"os"
	"path/filepath"
	"testing"
)

// The failure this guards against was found in production: six deliberately
// vulnerable containers still running after forty hours, for instances the site
// had long since expired. HandleDestroy refuses any container it cannot
// attribute — correctly — and a restart wiped the only record of who deployed
// what, so it could attribute none of them. The containers could not be torn
// down by anything except a human with shell access, and the worker went on
// counting them against their owners, who could then launch nothing.

func TestOwnershipSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dcs", "ownership.json")

	before := newOwnershipStore(path)
	before.set("container-a", "node-1", "")
	before.set("container-b", "node-2", "lab-7")
	if err := before.flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// A fresh store is what a restarted worker gets.
	after := newOwnershipStore(path)

	owner, known := after.owner("container-a")
	if !known || owner != "node-1" {
		t.Fatalf("container-a owner = %q known=%v, want node-1", owner, known)
	}
	owner, known = after.owner("container-b")
	if !known || owner != "node-2" {
		t.Fatalf("container-b owner = %q known=%v, want node-2", owner, known)
	}
	project, isCompose := after.compose("container-b")
	if !isCompose || project != "lab-7" {
		t.Fatalf("container-b compose = %q %v, want lab-7 — without the project "+
			"name, `compose down` cannot reach the backing services", project, isCompose)
	}
	if _, isCompose := after.compose("container-a"); isCompose {
		t.Fatal("a single-container deploy was recorded as a compose project")
	}
}

func TestForgettingIsPersistedToo(t *testing.T) {
	// A destroy that is not persisted comes back on the next start, and the
	// agent then refuses to re-destroy a container that no longer exists while
	// still counting it against its owner.
	path := filepath.Join(t.TempDir(), "ownership.json")
	store := newOwnershipStore(path)
	store.set("gone", "node-1", "")
	_ = store.flush()
	store.forget("gone")
	_ = store.flush()

	if _, known := newOwnershipStore(path).owner("gone"); known {
		t.Fatal("a destroyed container was still attributed after a restart")
	}
}

func TestCorruptStateIsDroppedNotGuessed(t *testing.T) {
	// Repairing a damaged file by guessing would let the wrong node tear down
	// someone else's container, which is the one thing the ownership check
	// exists to prevent. Losing the records is the safe failure.
	path := filepath.Join(t.TempDir(), "ownership.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newOwnershipStore(path)
	if len(store.records) != 0 {
		t.Fatalf("corrupt state produced %d records", len(store.records))
	}
}

func TestAgentRecoversOwnershipOnStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ownership.json")
	seed := newOwnershipStore(path)
	seed.set("c1", "node-1", "proj-1")
	if err := seed.flush(); err != nil {
		t.Fatal(err)
	}

	agent := NewAgent(AgentConfig{NodeID: "worker"}, nil, nil, &discardAudit{})
	agent.SetStatePath(path)

	agent.mu.Lock()
	owner := agent.owners["c1"]
	project := agent.composeOf["c1"]
	agent.mu.Unlock()
	if owner != "node-1" {
		t.Fatalf("agent recovered owner %q, want node-1", owner)
	}
	if project != "proj-1" {
		t.Fatalf("agent recovered project %q, want proj-1", project)
	}
}

type discardAudit struct{}

func (discardAudit) Record(AuditEntry) {}
