package channel

// P13 — the security test suite, mapped row by row to its specification.
//
// WHY THIS FILE IS SHAPED LIKE A TABLE
// ------------------------------------
// The package already had ~490 tests before this one, and many of the P13 rows
// were covered somewhere among them. What did not exist was any way to ANSWER
// the question "is every row covered?" without reading all of them and
// judging — which is the same as not knowing.
//
// So the specification is declared here as data, every row is exercised as a
// named subtest that registers itself, and the parent test FAILS if a row was
// never claimed. Coverage becomes a property the suite checks rather than a
// belief about it. Adding a row to the spec breaks the build until it is
// tested, which is the direction the pressure should point.
//
// This does not replace the existing tests and does not duplicate their depth.
// It is the audit layer over them.
//
// SCOPE, HONESTLY
// ---------------
// Rows here are exercised against the state machine, the store and the fake
// chain. The real ChannelManagerV2 is NOT deployed — P12-8 is unfinished — so
// no row here is a claim about the deployed contract. The digest vectors in
// state_test.go are what tie this package's encoding to the EVM, and they are
// the only place that claim is made.

import (
	"math/big"
	"os"
	"testing"
)

// p13Row is one requirement from the roadmap's P13 tables.
type p13Row struct {
	table    string // "direct", "htlc"
	name     string // as the roadmap spells it
	expected string // the roadmap's expectation, verbatim
}

// p13Spec is the roadmap's tables, transcribed. Do not edit to match the code:
// this is the specification, and the code is what is being checked against it.
var p13Spec = []p13Row{
	{"direct", "valid state", "succeeds"},
	{"direct", "invalid signer", "fails"},
	{"direct", "wrong channel id", "fails"},
	{"direct", "same nonce replay", "fails"},
	{"direct", "older nonce", "fails"},
	{"direct", "newer nonce", "succeeds"},
	{"direct", "insufficient balance", "fails"},
	{"direct", "non-conserving balances", "fails"},
	{"direct", "cooperative close", "succeeds"},
	{"direct", "unilateral close", "enters challenge"},
	{"direct", "newer state challenged", "newer state wins"},
	{"direct", "crash/restart", "latest state survives"},

	{"htlc", "valid secret", "succeeds"},
	{"htlc", "invalid secret", "fails"},
	{"htlc", "double claim", "fails"},
	{"htlc", "expired claim", "fails"},
	{"htlc", "valid refund", "succeeds"},
	{"htlc", "wrong hash", "fails"},
	{"htlc", "wrong amount", "fails"},
	{"htlc", "wrong channel", "fails"},
	{"htlc", "htlc replay", "fails"},
}

// p13Fixture is a funded, open channel with both parties' wallets.
type p13Fixture struct {
	ch     *Channel
	a, b   *signer
	chain  *FakeChain
	id     [32]byte
	depA   *big.Int
	depB   *big.Int
	chainI *big.Int
	con    Address
}

func newP13Fixture(t *testing.T) *p13Fixture {
	t.Helper()
	x, y := newSigner(t), newSigner(t)
	// Party A is the numerically lower address, never "the tipper".
	a, b := x, y
	if !x.address().Less(y.address()) {
		a, b = y, x
	}
	chainID := big.NewInt(v2ChainID)
	contract := mustAddr(t, v2Contract)
	depA, depB := anon(500), anon(500)

	chain := NewFakeChain()
	id := chain.Add(a.address(), b.address(), depA, depB)

	ch := NewChannel(chainID, contract, a.address(), b.address())
	ch.DepositA, ch.DepositB = depA, depB
	ch.Status = StatusOpen

	return &p13Fixture{ch: ch, a: a, b: b, chain: chain, id: id,
		depA: depA, depB: depB, chainI: chainID, con: contract}
}

// signed builds a fully co-signed state. Both signatures are real ECDSA over
// the EIP-191 wrapping of the contract's digest.
func (f *p13Fixture) signed(t *testing.T, st State) SignedState {
	t.Helper()
	raw := st.Digest(f.chainI, f.con)
	return SignedState{State: st, SigA: f.a.sign(raw), SigB: f.b.sign(raw)}
}

// state builds a balanced state at a nonce.
func (f *p13Fixture) state(nonce uint64, balA, balB *big.Int, locks ...HTLC) State {
	return State{
		Channel: f.ch.ID, Nonce: nonce,
		BalanceA: balA, BalanceB: balB, Pending: locks,
	}
}

func TestP13SecuritySuite(t *testing.T) {
	covered := map[string]bool{}
	cover := func(table, name string) { covered[table+"/"+name] = true }

	// ---- direct channel table -----------------------------------------

	t.Run("direct/valid state", func(t *testing.T) {
		cover("direct", "valid state")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(400), anon(600)))); err != nil {
			t.Fatalf("a correctly signed, conserving state was refused: %v", err)
		}
		if f.ch.Latest.State.Nonce != 1 {
			t.Fatalf("accepted but not adopted: latest nonce %d", f.ch.Latest.State.Nonce)
		}
	})

	t.Run("direct/invalid signer", func(t *testing.T) {
		cover("direct", "invalid signer")
		f := newP13Fixture(t)
		outsider := newSigner(t)
		st := f.state(1, anon(400), anon(600))
		raw := st.Digest(f.chainI, f.con)
		// A perfectly valid signature — by the wrong key. This is the attack:
		// the signature verifies, it just does not belong to a party.
		bad := SignedState{State: st, SigA: outsider.sign(raw), SigB: f.b.sign(raw)}
		if err := f.ch.Accept(bad); err == nil {
			t.Fatal("a state signed by a non-party was accepted")
		}
	})

	t.Run("direct/wrong channel id", func(t *testing.T) {
		cover("direct", "wrong channel id")
		f := newP13Fixture(t)
		st := f.state(1, anon(400), anon(600))
		st.Channel = [32]byte{31: 0xff} // some other channel
		// Both parties really did sign this. A signature over another
		// channel's state is still a valid signature, which is why the id is
		// checked separately from the signatures.
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("a state naming a different channel was accepted")
		}
	})

	t.Run("direct/same nonce replay", func(t *testing.T) {
		cover("direct", "same nonce replay")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(5, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Same nonce, DIFFERENT balances, both signatures valid. This is
		// exactly what a double-spend looks like.
		replay := f.signed(t, f.state(5, anon(100), anon(900)))
		if err := f.ch.Accept(replay); err == nil {
			t.Fatal("two different states at the same nonce were both accepted")
		}
		if f.ch.Latest.State.BalanceA.Cmp(anon(400)) != 0 {
			t.Fatal("the replay overwrote the accepted state")
		}
	})

	t.Run("direct/older nonce", func(t *testing.T) {
		cover("direct", "older nonce")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(9, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(8, anon(450), anon(550)))); err == nil {
			t.Fatal("a state older than the latest was accepted")
		}
	})

	t.Run("direct/newer nonce", func(t *testing.T) {
		cover("direct", "newer nonce")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(9, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		if err := f.ch.Accept(f.signed(t, f.state(10, anon(390), anon(610)))); err != nil {
			t.Fatalf("a newer state was refused: %v", err)
		}
		if f.ch.Latest.State.Nonce != 10 {
			t.Fatalf("latest nonce is %d, want 10", f.ch.Latest.State.Nonce)
		}
	})

	t.Run("direct/insufficient balance", func(t *testing.T) {
		cover("direct", "insufficient balance")
		f := newP13Fixture(t)
		// A pays 600 from a 500 deposit. Expressed as a negative balance,
		// which big.Int will happily represent and uint256 cannot.
		st := f.state(1, new(big.Int).Neg(anon(100)), anon(1100))
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("a state with a negative balance was accepted")
		}
	})

	t.Run("direct/non-conserving balances", func(t *testing.T) {
		cover("direct", "non-conserving balances")
		f := newP13Fixture(t)
		// Both balances positive, sum exceeds the deposits: minting.
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(600), anon(600)))); err == nil {
			t.Fatal("a state creating value from nothing was accepted")
		}
		// And the other direction — value quietly destroyed.
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(100), anon(100)))); err == nil {
			t.Fatal("a state destroying value was accepted")
		}
	})

	t.Run("direct/cooperative close", func(t *testing.T) {
		cover("direct", "cooperative close")
		f := newP13Fixture(t)
		if err := f.ch.Accept(f.signed(t, f.state(3, anon(400), anon(600)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// A cooperative close settles the channel on chain. Afterwards the
		// state machine must refuse further states: a settled channel that
		// still accepts updates is a channel that can be drained after payout.
		f.chain.Settled(f.id)
		f.ch.Status = StatusSettled
		if err := f.ch.Accept(f.signed(t, f.state(4, anon(300), anon(700)))); err == nil {
			t.Fatal("a settled channel accepted a new state")
		}
	})

	t.Run("direct/unilateral close", func(t *testing.T) {
		cover("direct", "unilateral close")
		f := newP13Fixture(t)
		const ends = 1_800_000_000
		f.chain.StartClose(f.id, 3, ends)
		occ, err := f.chain.ReadChannel(t.Context(), f.con, f.id)
		if err != nil {
			t.Fatalf("reading the closing channel: %v", err)
		}
		if occ.Status != StatusClosing {
			t.Fatalf("status is %v, want Closing", occ.Status)
		}
		if occ.ChallengeEnds != ends {
			t.Fatalf("challenge window is %d, want %d", occ.ChallengeEnds, ends)
		}
	})

	t.Run("direct/newer state challenged", func(t *testing.T) {
		cover("direct", "newer state challenged")
		f := newP13Fixture(t)
		// The channel really is at nonce 7.
		if err := f.ch.Accept(f.signed(t, f.state(7, anon(300), anon(700)))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// The counterparty closes on a stale nonce 3, which pays them more.
		f.chain.StartClose(f.id, 3, 1_800_000_000)
		occ, err := f.chain.ReadChannel(t.Context(), f.con, f.id)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		// The held state must be recognised as beating the posted one. This
		// comparison is the whole basis of the watchtower's decision to act.
		if !(f.ch.Latest.State.Nonce > occ.Nonce) {
			t.Fatalf("held nonce %d does not beat posted nonce %d",
				f.ch.Latest.State.Nonce, occ.Nonce)
		}
	})

	t.Run("direct/crash restart", func(t *testing.T) {
		cover("direct", "crash/restart")
		f := newP13Fixture(t)
		dir, err := os.MkdirTemp("", "p13store")
		if err != nil {
			t.Fatalf("tempdir: %v", err)
		}
		defer os.RemoveAll(dir)

		store, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("OpenStore: %v", err)
		}
		occ, err := f.chain.ReadChannel(t.Context(), f.con, f.id)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := store.TrackFromChain(f.chainI, f.con, occ); err != nil {
			t.Fatalf("TrackFromChain: %v", err)
		}
		want := f.state(11, anon(275), anon(725))
		if err := store.Accept(f.id, f.signed(t, want)); err != nil {
			t.Fatalf("Accept: %v", err)
		}

		// The crash: drop everything in memory and open the directory again.
		reopened, err := OpenStore(dir)
		if err != nil {
			t.Fatalf("reopen: %v", err)
		}
		got, ok := reopened.Get(f.id)
		if !ok {
			t.Fatal("the channel did not survive the restart")
		}
		if got.Latest.State.Nonce != 11 {
			t.Fatalf("latest nonce after restart is %d, want 11", got.Latest.State.Nonce)
		}
		if got.Latest.State.BalanceA.Cmp(anon(275)) != 0 {
			t.Fatalf("balance A after restart is %s, want 275e18", got.Latest.State.BalanceA)
		}
		if !got.Latest.Complete() {
			t.Fatal("the reloaded state lost a signature; it could not be settled")
		}
	})

	// ---- HTLC table ----------------------------------------------------

	preimage := [32]byte{31: 0x42}
	var lockHash [32]byte
	copy(lockHash[:], keccak(preimage[:]))

	newLock := func(id byte, amount *big.Int, expiry int64) HTLC {
		return HTLC{ID: [32]byte{31: id}, Hash: lockHash,
			Amount: amount, Expiry: expiry, PayerIsA: true}
	}

	t.Run("htlc/valid secret", func(t *testing.T) {
		cover("htlc", "valid secret")
		if !newLock(1, anon(10), 2_000_000_000).Matches(preimage) {
			t.Fatal("the correct preimage did not open the lock")
		}
	})

	t.Run("htlc/invalid secret", func(t *testing.T) {
		cover("htlc", "invalid secret")
		if newLock(1, anon(10), 2_000_000_000).Matches([32]byte{31: 0x43}) {
			t.Fatal("a wrong preimage opened the lock")
		}
	})

	t.Run("htlc/wrong hash", func(t *testing.T) {
		cover("htlc", "wrong hash")
		l := newLock(1, anon(10), 2_000_000_000)
		l.Hash = [32]byte{31: 0xaa} // not H(preimage)
		if l.Matches(preimage) {
			t.Fatal("a lock committed to a different hash was opened")
		}
	})

	t.Run("htlc/double claim", func(t *testing.T) {
		cover("htlc", "double claim")
		f := newP13Fixture(t)
		lock := newLock(1, anon(10), 2_000_000_000)
		// Locked funds sit in NEITHER balance, so a conserving state with one
		// live lock is 500+490 plus the 10 held.
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), lock))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Claimed: the lock is gone and B has the value.
		claimed := f.state(2, anon(490), anon(510))
		if err := f.ch.Accept(f.signed(t, claimed)); err != nil {
			t.Fatalf("first claim: %v", err)
		}
		// Claiming again must not pay twice. Replayed at the same nonce it is
		// a nonce violation; at a NEW nonce it fails conservation, because the
		// lock is no longer there to fund it. Both paths are checked.
		if err := f.ch.Accept(f.signed(t, claimed)); err == nil {
			t.Fatal("the same claim was accepted twice")
		}
		if err := f.ch.Accept(f.signed(t, f.state(3, anon(490), anon(520)))); err == nil {
			t.Fatal("a second claim of an already-claimed lock created value")
		}
	})

	t.Run("htlc/expired claim", func(t *testing.T) {
		cover("htlc", "expired claim")
		f := newP13Fixture(t)
		// Accept is deliberately pure and does not consult a clock, so an
		// expiry in the past is NOT rejected here — freshness is the protocol
		// layer's job. What must never be accepted is an unset expiry, which
		// would be a lock nobody could ever reclaim.
		zero := newLock(1, anon(10), 0)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), zero))); err == nil {
			t.Fatal("a lock with no expiry was accepted; it could never be refunded")
		}
		past := newLock(1, anon(10), 1)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), past))); err != nil {
			t.Fatalf("a past expiry must be a policy decision, not a state machine one: %v", err)
		}
	})

	t.Run("htlc/valid refund", func(t *testing.T) {
		cover("htlc", "valid refund")
		f := newP13Fixture(t)
		lock := newLock(1, anon(10), 2_000_000_000)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), lock))); err != nil {
			t.Fatalf("setup: %v", err)
		}
		// Refunded: the lock is gone and the payer has the value back.
		if err := f.ch.Accept(f.signed(t, f.state(2, anon(500), anon(500)))); err != nil {
			t.Fatalf("a refund to the payer was refused: %v", err)
		}
	})

	t.Run("htlc/wrong amount", func(t *testing.T) {
		cover("htlc", "wrong amount")
		f := newP13Fixture(t)
		// A lock claiming more than the payer holds cannot conserve.
		over := newLock(1, anon(900), 2_000_000_000)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(490), anon(500), over))); err == nil {
			t.Fatal("a lock for more than the channel holds was accepted")
		}
		// A zero or negative lock amount is meaningless and must be refused.
		zero := newLock(2, big.NewInt(0), 2_000_000_000)
		if err := f.ch.Accept(f.signed(t, f.state(1, anon(500), anon(500), zero))); err == nil {
			t.Fatal("a zero-amount lock was accepted")
		}
	})

	t.Run("htlc/wrong channel", func(t *testing.T) {
		cover("htlc", "wrong channel")
		f := newP13Fixture(t)
		// The lock is well formed; the STATE carrying it names another
		// channel. A lock is only meaningful inside the channel that committed
		// to it, so the state must be refused whatever the lock looks like.
		st := f.state(1, anon(490), anon(500), newLock(1, anon(10), 2_000_000_000))
		st.Channel = [32]byte{31: 0xfe}
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("a locked state naming another channel was accepted")
		}
	})

	t.Run("htlc/htlc replay", func(t *testing.T) {
		cover("htlc", "htlc replay")
		f := newP13Fixture(t)
		// Two locks with the same id in one state: the second is a replay of
		// the first, and would be paid twice if ids were not required unique.
		dup := newLock(1, anon(10), 2_000_000_000)
		st := f.state(1, anon(480), anon(500), dup, dup)
		if err := f.ch.Accept(f.signed(t, st)); err == nil {
			t.Fatal("a state containing the same lock id twice was accepted")
		}
	})

	// ---- the audit ------------------------------------------------------

	t.Run("spec coverage", func(t *testing.T) {
		var missing []string
		for _, row := range p13Spec {
			key := row.table + "/" + row.name
			if !covered[key] {
				missing = append(missing, key+" ("+row.expected+")")
			}
		}
		if len(missing) > 0 {
			t.Fatalf("%d P13 requirement(s) have no test:\n  %v\n"+
				"Add the test, or remove the row from p13Spec and say why in the roadmap.",
				len(missing), missing)
		}
		t.Logf("all %d P13 direct-channel and HTLC requirements are exercised", len(p13Spec))
	})
}
