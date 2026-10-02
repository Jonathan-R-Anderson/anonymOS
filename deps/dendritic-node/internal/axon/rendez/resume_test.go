package rendez

import (
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/session"
)

// splicedRP returns an RP with one spliced pair (client 1, service 2) whose
// client has registered commitment n for preimage pre.
func splicedRP(t *testing.T, now *time.Time) (*RendezvousPoint, [32]byte) {
	t.Helper()
	rp := NewRendezvousPoint()
	rp.Grace = 60 * time.Second
	rp.Now = func() time.Time { return *now }
	c, _ := NewCookie(rand.Reader)
	if err := rp.Establish(c, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := rp.Splice(c, 2); err != nil {
		t.Fatal(err)
	}
	var pre [32]byte
	rand.Read(pre[:])
	if err := rp.RegisterResume(1, 1, session.ResumeCommit(pre, 1)); err != nil {
		t.Fatal(err)
	}
	return rp, pre
}

func TestCaseAResumeBurnsTheCommitment(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rp, pre := splicedRP(t, &now)
	if svc, keep := rp.ClientLost(1); !keep || svc != 2 {
		t.Fatalf("ClientLost = %d, %v; want the service circuit held", svc, keep)
	}
	if p, ok := rp.Peer(2); ok {
		t.Fatalf("a held service circuit still forwards to %d", p)
	}
	now = now.Add(30 * time.Second)
	svc, err := rp.Resume(3, 1, pre)
	if err != nil || svc != 2 {
		t.Fatalf("resume inside the grace window: %d %v", svc, err)
	}
	if p, ok := rp.Peer(3); !ok || p != 2 {
		t.Fatalf("resumed pair does not forward: %d %v", p, ok)
	}
	if p, ok := rp.Peer(2); !ok || p != 3 {
		t.Fatalf("service side does not forward to the new client circuit: %d %v", p, ok)
	}
	// Replay, in order or not, after the burn.
	rp.ClientLost(3)
	if _, err := rp.Resume(4, 1, pre); !errors.Is(err, ErrResumeRefused) {
		t.Fatalf("replayed RESUME_RENDEZVOUS: %v", err)
	}
	if rp.Held() != 0 {
		t.Fatalf("an uncommitted pair was held: %d", rp.Held())
	}
}

func TestCaseARefusals(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	var wrong [32]byte
	rand.Read(wrong[:])
	for name, try := range map[string]func(rp *RendezvousPoint, pre [32]byte) error{
		"wrong preimage": func(rp *RendezvousPoint, pre [32]byte) error {
			_, err := rp.Resume(9, 1, wrong)
			return err
		},
		"wrong counter": func(rp *RendezvousPoint, pre [32]byte) error {
			_, err := rp.Resume(9, 2, pre)
			return err
		},
		"after the grace window": func(rp *RendezvousPoint, pre [32]byte) error {
			now = now.Add(61 * time.Second)
			_, err := rp.Resume(9, 1, pre)
			return err
		},
		"onto a circuit already joined": func(rp *RendezvousPoint, pre [32]byte) error {
			c, _ := NewCookie(rand.Reader)
			rp.Establish(c, 9)
			rp.Splice(c, 10)
			_, err := rp.Resume(9, 1, pre)
			if errors.Is(err, ErrResumeNotFresh) {
				return ErrResumeRefused
			}
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			now = time.Unix(1_800_000_000, 0)
			rp, pre := splicedRP(t, &now)
			rp.ClientLost(1)
			if err := try(rp, pre); !errors.Is(err, ErrResumeRefused) {
				t.Fatalf("got %v, want a refusal", err)
			}
		})
	}
}

func TestCaseARegistrationCannotRollBack(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rp, pre := splicedRP(t, &now)
	if err := rp.RegisterResume(1, 1, session.ResumeCommit(pre, 1)); !errors.Is(err, ErrResumeCounter) {
		t.Fatalf("re-registering counter 1: %v", err)
	}
	if err := rp.RegisterResume(1, 2, session.ResumeCommit(pre, 2)); err != nil {
		t.Fatal(err)
	}
	rp.ClientLost(1)
	if _, err := rp.Resume(5, 1, pre); !errors.Is(err, ErrResumeRefused) {
		t.Fatalf("a superseded commitment resumed: %v", err)
	}
	if _, err := rp.Resume(5, 2, pre); err != nil {
		t.Fatalf("the newest commitment did not resume: %v", err)
	}
	if err := rp.RegisterResume(77, 1, [32]byte{}); !errors.Is(err, ErrNotJoined) {
		t.Fatalf("registration on an unspliced circuit: %v", err)
	}
}

func TestCaseAExpireFreesTheServiceCircuit(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rp, _ := splicedRP(t, &now)
	rp.ClientLost(1)
	if got := rp.Expire(); len(got) != 0 {
		t.Fatalf("expired inside the window: %v", got)
	}
	now = now.Add(61 * time.Second)
	if got := rp.Expire(); len(got) != 1 || got[0] != 2 {
		t.Fatalf("Expire = %v, want the service circuit", got)
	}
	if rp.Held() != 0 {
		t.Fatal("still held after expiry")
	}
}

func TestServiceLostTearsDownOrDrops(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	rp, pre := splicedRP(t, &now)
	if c, ok := rp.ServiceLost(2); !ok || c != 1 {
		t.Fatalf("ServiceLost on a live pair = %d %v; want the client circuit back for teardown", c, ok)
	}
	rp2, pre2 := splicedRP(t, &now)
	rp2.ClientLost(1)
	if _, ok := rp2.ServiceLost(2); ok {
		t.Fatal("a held pair returned a client circuit")
	}
	if _, err := rp2.Resume(3, 1, pre2); !errors.Is(err, ErrResumeRefused) {
		t.Fatalf("resumed onto a dead service circuit: %v", err)
	}
	_ = pre
}

func TestResumeBodiesRoundTrip(t *testing.T) {
	var c [32]byte
	rand.Read(c[:])
	reg := &ResumeRegister{Commit: c, Counter: 7}
	got, err := DecodeResumeRegister(reg.Encode())
	if err != nil || *got != *reg {
		t.Fatalf("RESUME_REGISTER: %+v %v", got, err)
	}
	rr := &ResumeRendezvous{Preimage: c, Counter: 9}
	got2, err := DecodeResumeRendezvous(rr.Encode())
	if err != nil || *got2 != *rr {
		t.Fatalf("RESUME_RENDEZVOUS: %+v %v", got2, err)
	}
	for _, b := range [][]byte{nil, make([]byte, 35)} {
		if _, err := DecodeResumeRegister(b); err == nil {
			t.Fatal("short RESUME_REGISTER accepted")
		}
		if _, err := DecodeResumeRendezvous(b); err == nil {
			t.Fatal("short RESUME_RENDEZVOUS accepted")
		}
	}
	if _, err := DecodeResumeStatus([]byte{2}); err == nil {
		t.Fatal("unknown resume status accepted")
	}
}
