package facilitation

import (
	"crypto/ed25519"
	"strings"
	"testing"
)

func TestPayoutDeclarationVerifies(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	d := DeclarePayout(pub, priv, "0xB2b36AaD18d7be5d4016267BC4cCec2f12a64b6e", 5)
	if !VerifyPayoutDeclaration(d) {
		t.Fatal("a node's own declaration did not verify")
	}
	if d.Payout != strings.ToLower(d.Payout) {
		t.Fatal("payout was not normalised — the server lowercases before verifying")
	}
}

// The attack this signature exists to stop: someone else naming your node and
// pointing its earnings at their address.
func TestPayoutCannotBeRedirectedByAnotherKey(t *testing.T) {
	victimPub, victimPriv, _ := ed25519.GenerateKey(nil)
	honest := DeclarePayout(victimPub, victimPriv, "0xaaaa000000000000000000000000000000000000", 1)

	// Attacker keeps the victim's node id but swaps the payout address.
	forged := honest
	forged.Payout = "0xbbbb000000000000000000000000000000000000"
	if VerifyPayoutDeclaration(forged) {
		t.Fatal("a rewritten payout address still verified — earnings could be stolen")
	}

	// Attacker signs with their own key while claiming the victim's identity.
	_, attackerPriv, _ := ed25519.GenerateKey(nil)
	impersonated := DeclarePayout(victimPub, attackerPriv, "0xbbbb000000000000000000000000000000000000", 2)
	if VerifyPayoutDeclaration(impersonated) {
		t.Fatal("a declaration signed by the wrong key verified")
	}
}

// A later declaration must be distinguishable from an earlier one, so replaying
// a superseded address cannot undo a change.
func TestSequenceIsCoveredBySignature(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	first := DeclarePayout(pub, priv, "0xaaaa000000000000000000000000000000000000", 1)
	replayed := first
	replayed.Sequence = 99
	if VerifyPayoutDeclaration(replayed) {
		t.Fatal("sequence could be rewritten after signing")
	}
}
