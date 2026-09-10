package channel

// The wire encoding must preserve everything the digest covers.
//
// storedState is the single encoding used for BOTH the disk and the wire, so a
// field it drops is a field that vanishes on restart and in transit alike. That
// is not a cosmetic loss: the digest is what both parties signed, so a state
// that comes back missing a field is a DIFFERENT state carrying a signature
// that no longer covers it. Everything downstream then does the right thing
// with the wrong data — the store fails closed on reload, the peer rejects a
// perfectly honest proposal, and the cause looks like a signature bug.

import (
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

// A checkpoint is the only transition that sets withdrawals, and it is exactly
// the state most in need of surviving a restart: value is leaving the contract
// under it.
func TestWireKeepsWithdrawals(t *testing.T) {
	in := State{
		Nonce:     7,
		BalanceA:  big.NewInt(100),
		BalanceB:  big.NewInt(50),
		WithdrawA: big.NewInt(30),
		WithdrawB: big.NewInt(20),
	}

	// Through real JSON, not just the struct conversion: the marshalling is
	// where a missing tag would actually lose the value.
	raw, err := json.Marshal(encodeStateWire(in))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var wire storedState
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	out, err := decodeStateWire(wire)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}

	if orZero(out.WithdrawA).Cmp(big.NewInt(30)) != 0 {
		t.Errorf("withdrawA: got %s want 30", orZero(out.WithdrawA))
	}
	if orZero(out.WithdrawB).Cmp(big.NewInt(20)) != 0 {
		t.Errorf("withdrawB: got %s want 20", orZero(out.WithdrawB))
	}

	// The point of the test. Two states are the same state only if they hash
	// the same, because the hash is what was signed.
	chainID, contract := big.NewInt(1), Address{0xAB}
	if want, got := in.Digest(chainID, contract), out.Digest(chainID, contract); want != got {
		t.Errorf("digest changed across the wire\n before %x\n after  %x", want, got)
	}
}

// Records written before checkpoints existed must encode exactly as they did,
// or every stored channel's JSON changes shape on the next write for no reason.
func TestWireOmitsZeroWithdrawals(t *testing.T) {
	raw, err := json.Marshal(encodeStateWire(State{
		Nonce: 1, BalanceA: big.NewInt(1), BalanceB: big.NewInt(2),
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(raw), "withdraw") {
		t.Errorf("an ordinary payment should carry no withdrawal fields: %s", raw)
	}
}

// The contract's field is uint256. A negative withdrawal describes a state that
// could never settle, so it is refused at the door rather than stored as though
// it could.
func TestWireRejectsNegativeWithdrawal(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"party A", "-1", ""},
		{"party B", "", "-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeStateWire(storedState{
				Channel: strings.Repeat("00", 32), Nonce: 1,
				BalanceA: "1", BalanceB: "2",
				WithdrawA: tc.a, WithdrawB: tc.b,
			})
			if err == nil {
				t.Fatal("a negative withdrawal was accepted")
			}
			if !strings.Contains(err.Error(), "negative") {
				t.Errorf("unhelpful error: %v", err)
			}
		})
	}
}
