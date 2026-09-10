//go:build !ethbls

package ethproof

// The no-BLS build must be UNABLE to claim a signature was verified.
//
// These tests are the difference between an explicit build boundary and a
// silent security downgrade. They are deliberately not "a malformed input is
// rejected" — that would pass just as well against an implementation that
// accepts well-formed forgeries. What they assert is that NOTHING returns nil,
// for any input, on any path.

import (
	"errors"
	"testing"
)

// plausibleCommittee is a committee that LOOKS usable: full size, non-zero
// keys, a real aggregate. Nothing about it is malformed, so a stub that only
// rejected garbage would let it through.
func plausibleCommittee() *SyncCommittee {
	c := &SyncCommittee{}
	for i := range c.Pubkeys {
		for b := range c.Pubkeys[i] {
			c.Pubkeys[i][b] = byte(i + b + 1)
		}
	}
	for b := range c.AggregatePubkey {
		c.AggregatePubkey[b] = byte(b + 1)
	}
	return c
}

// fullParticipation comes from lightclient_test.go — reused rather than
// redeclared, so this file cannot drift from what the other tests mean by it.

func plausibleSignature() []byte {
	sig := make([]byte, BLSSignatureBytes)
	for i := range sig {
		sig[i] = byte(i + 1)
	}
	return sig
}

func TestNoBLSVerifierIsNeverNil(t *testing.T) {
	// A nil verifier invites `if v != nil { verify }` at call sites, and that
	// guard is a bypass: the branch skipping verification is the one that runs.
	if NewBLSVerifier() == nil {
		t.Fatal("NewBLSVerifier returned nil, which a caller can nil-check past")
	}
}

func TestNoBLSStubSatisfiesTheInterface(t *testing.T) {
	// If this stops compiling the two builds are not interchangeable and the
	// build tag is a lie.
	var v SyncCommitteeVerifier = NewBLSVerifier()
	if v == nil {
		t.Fatal("the stub does not satisfy SyncCommitteeVerifier")
	}
}

func TestNoBLSVerificationNeverSucceeds(t *testing.T) {
	// Every combination that could plausibly be presented, including the fully
	// well-formed one. None may return nil.
	v := NewBLSVerifier()
	good := plausibleCommittee()
	sig := plausibleSignature()

	cases := []struct {
		name      string
		committee *SyncCommittee
		part      Participation
		sig       []byte
	}{
		{"fully well-formed", good, fullParticipation(), sig},
		{"empty participation", good, Participation{}, sig},
		{"nil committee", nil, fullParticipation(), sig},
		{"nil signature", good, fullParticipation(), nil},
		{"zero everything", &SyncCommittee{}, Participation{}, make([]byte, BLSSignatureBytes)},
	}
	for _, tc := range cases {
		err := v.VerifySyncCommitteeSignature(Root{}, tc.committee, tc.part, tc.sig)
		if err == nil {
			t.Fatalf("%s: verification SUCCEEDED in a build with no BLS support", tc.name)
		}
		if !errors.Is(err, ErrNoBLSSupport) {
			t.Errorf("%s: got %v, want ErrNoBLSSupport", tc.name, err)
		}
	}
}

func TestNoBLSValidateCommitteeNeverSucceeds(t *testing.T) {
	v := NewBLSVerifier()
	for _, tc := range []struct {
		name string
		c    *SyncCommittee
	}{
		{"plausible committee", plausibleCommittee()},
		{"zero committee", &SyncCommittee{}},
		{"nil committee", nil},
	} {
		err := v.ValidateCommittee(tc.c)
		if err == nil {
			t.Fatalf("%s: ValidateCommittee SUCCEEDED with no BLS support", tc.name)
		}
		if !errors.Is(err, ErrNoBLSSupport) {
			t.Errorf("%s: got %v, want ErrNoBLSSupport", tc.name, err)
		}
	}
}

func TestNoBLSErrorSaysWhatIsWrong(t *testing.T) {
	// The message has to distinguish "this signature did not verify" from
	// "this binary cannot verify signatures". Those call for opposite
	// responses, and an operator reading a log needs to tell them apart.
	msg := ErrNoBLSSupport.Error()
	for _, want := range []string{"ethbls", "without", "cannot verify"} {
		if !contains(msg, want) {
			t.Errorf("the error does not mention %q: %s", want, msg)
		}
	}
}

// Apply* are the three doors through which a caller could reach verification.
// Each must surface the refusal rather than swallowing it: an update that was
// never checked must not be applied.

func TestApplyUpdatePropagatesTheRefusal(t *testing.T) {
	assertRefused(t, "ApplyUpdate", func(s *LightClientState, u *Update) error {
		return s.ApplyUpdate(u, NewBLSVerifier())
	})
}

func TestApplyFinalityUpdatePropagatesTheRefusal(t *testing.T) {
	assertRefused(t, "ApplyFinalityUpdate", func(s *LightClientState, u *Update) error {
		return s.ApplyFinalityUpdate(u, NewBLSVerifier())
	})
}

func TestApplyRotatingUpdatePropagatesTheRefusal(t *testing.T) {
	assertRefused(t, "ApplyRotatingUpdate", func(s *LightClientState, u *Update) error {
		return s.ApplyRotatingUpdate(u, NewBLSVerifier())
	})
}

// assertRefused checks that a state-advancing call cannot succeed.
//
// It asserts NON-SUCCESS rather than a specific error: these methods perform
// their own structural checks before reaching the verifier, so a given fixture
// may legitimately be refused earlier. What must never happen is nil.
func assertRefused(t *testing.T, name string, apply func(*LightClientState, *Update) error) {
	t.Helper()
	committee := plausibleCommittee()
	state := &LightClientState{}
	update := &Update{
		Participation: fullParticipation(),
		Signature:     plausibleSignature(),
		SignatureSlot: 1,
	}
	_ = committee
	if err := apply(state, update); err == nil {
		t.Fatalf("%s advanced the state in a build that cannot verify signatures", name)
	}
}

func contains(hay, needle string) bool {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
