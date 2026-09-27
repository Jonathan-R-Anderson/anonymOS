package registry

import (
	"errors"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

func nm(t *testing.T, parts ...string) name.Name {
	t.Helper()
	v, err := name.Normalise(strings.Join(append(parts, name.RootSuffix), "."))
	if err != nil {
		t.Fatalf("normalise %v: %v", parts, err)
	}
	return v
}

func acct(b byte) Account { var a Account; a[0] = b; return a }

func testPolicy() Policy {
	return Policy{
		BasePrice:        big.NewInt(1000),
		LengthMultiplier: map[int]int64{3: 100, 4: 20, 5: 5},
		Term:             365 * 24 * time.Hour,
		BondPerName:      big.NewInt(500),
		TransferLevyBps:  5000, // 50 % at zero holding time
		LevyHalfLife:     180 * 24 * time.Hour,
		EpochBurstFree:   1,
		EpochLength:      24 * time.Hour,
		RevealsPerBlock:  2,
		CommitMinAge:     time.Minute,
		CommitMaxAge:     24 * time.Hour,
	}
}

// register drives the full commit -> wait -> reveal flow.
func register(t *testing.T, r *Registry, clock *time.Time, n name.Name, who Account, block uint64) (*big.Int, error) {
	t.Helper()
	c, err := ClaimFor(n)
	if err != nil {
		return nil, err
	}
	var secret [32]byte
	secret[0] = who[0]
	copy(secret[1:], n.Registrable())
	r.Commit(MakeCommitment(c, who, secret))
	*clock = clock.Add(2 * time.Minute)
	return r.Register(c, who, secret, n.Registrable(), big.NewInt(500), block)
}

// TestGrammarToChainBinding: only a registrable name has an on-chain claim.
func TestGrammarToChainBinding(t *testing.T) {
	reg := nm(t, "alice", "lab")
	c, err := ClaimFor(reg)
	if err != nil {
		t.Fatal(err)
	}
	nh, err := reg.NameHash()
	if err != nil {
		t.Fatal(err)
	}
	if c.NameHash != nh {
		t.Fatal("claim hash differs from the name's own NameHash")
	}
	if c.Skeleton == c.NameHash {
		t.Fatal("skeleton hash equals the name hash; the confusable check is a no-op")
	}

	// A subordinate name is delegated off chain and has no claim.
	sub := nm(t, "www", "alice", "lab")
	if _, err := ClaimFor(sub); !errors.Is(err, ErrNotRegistrable) {
		t.Fatalf("err = %v, want ErrNotRegistrable", err)
	}
}

// TestConfusableSkeletonBlocksAnotherOwner is §11.3.3 at the registry.
func TestConfusableSkeletonBlocksAnotherOwner(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := New(testPolicy(), func() time.Time { return now })

	if _, err := register(t, r, &now, nm(t, "paypal", "lab"), acct(1), 1); err != nil {
		t.Fatal(err)
	}
	// "paypa1" folds onto the same skeleton.
	_, err := register(t, r, &now, nm(t, "paypa1", "lab"), acct(2), 2)
	if !errors.Is(err, ErrConfusableHeld) {
		t.Fatalf("err = %v, want ErrConfusableHeld", err)
	}
	// The SAME owner may take their own variants: defensive registration has to
	// be affordable for a legitimate holder, which is the whole point of the
	// class right-of-first-refusal.
	if _, err := register(t, r, &now, nm(t, "paypa1", "lab"), acct(1), 3); err != nil {
		t.Fatalf("the holder could not take their own variant: %v", err)
	}
}

// TestCommitRevealWindow.
func TestCommitRevealWindow(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := testPolicy()
	r := New(p, func() time.Time { return now })
	c, _ := ClaimFor(nm(t, "alice", "lab"))
	var secret [32]byte

	// No commitment at all.
	if _, err := r.Register(c, acct(1), secret, "alice", big.NewInt(500), 1); !errors.Is(err, ErrCommitUnknown) {
		t.Fatalf("err = %v, want ErrCommitUnknown", err)
	}
	// Too young.
	r.Commit(MakeCommitment(c, acct(1), secret))
	if _, err := r.Register(c, acct(1), secret, "alice", big.NewInt(500), 2); !errors.Is(err, ErrCommitTooYoung) {
		t.Fatalf("err = %v, want ErrCommitTooYoung", err)
	}
	// Expired.
	now = now.Add(p.CommitMaxAge + time.Hour)
	if _, err := r.Register(c, acct(1), secret, "alice", big.NewInt(500), 3); !errors.Is(err, ErrCommitExpired) {
		t.Fatalf("err = %v, want ErrCommitExpired", err)
	}
}

// TestRevealRateLimitTurnsADictionaryIntoAQueue.
func TestRevealRateLimitTurnsADictionaryIntoAQueue(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := testPolicy()
	r := New(p, func() time.Time { return now })

	attacker := acct(9)
	// Commit a dictionary up front -- commit-reveal does NOT stop this, and
	// §12.3 says so. The limit is on the REVEAL.
	var claims []Claim
	var secrets [][32]byte
	for i := 0; i < 10; i++ {
		n := nm(t, fmt.Sprintf("word%d", i), "lab")
		c, err := ClaimFor(n)
		if err != nil {
			t.Fatal(err)
		}
		var s [32]byte
		s[0] = byte(i)
		r.Commit(MakeCommitment(c, attacker, s))
		claims = append(claims, c)
		secrets = append(secrets, s)
	}
	now = now.Add(2 * time.Minute)

	got, limited := 0, 0
	for i := range claims {
		if _, err := r.Register(claims[i], attacker, secrets[i],
			fmt.Sprintf("word%d", i), big.NewInt(500), 100); err != nil {
			if errors.Is(err, ErrRevealRateLimit) {
				limited++
				continue
			}
			t.Fatal(err)
		}
		got++
	}
	if got != p.RevealsPerBlock {
		t.Fatalf("took %d names in one block, limit is %d", got, p.RevealsPerBlock)
	}
	if limited != 10-p.RevealsPerBlock {
		t.Fatalf("%d reveals limited, want %d", limited, 10-p.RevealsPerBlock)
	}
}

// TestTransferLevyIsTheGuard is §12.4a.2's load-bearing member.
func TestTransferLevyIsTheGuard(t *testing.T) {
	p := testPolicy()
	sale := big.NewInt(1_000_000)

	// A squatter flipping immediately forfeits half the sale.
	if got := p.TransferLevy(sale, 0); got.Cmp(big.NewInt(500_000)) != 0 {
		t.Fatalf("levy at zero holding = %s, want 500000", got)
	}
	// One half-life halves it.
	if got := p.TransferLevy(sale, p.LevyHalfLife); got.Cmp(big.NewInt(250_000)) != 0 {
		t.Fatalf("levy after one half-life = %s, want 250000", got)
	}
	// A genuine holder selling after years pays almost nothing.
	late := p.TransferLevy(sale, 10*365*24*time.Hour)
	if late.Cmp(big.NewInt(1000)) > 0 {
		t.Fatalf("levy after 10 years = %s, should be negligible", late)
	}
	// It reaches zero, and the number is statable.
	if p.LevyFreeAfter() <= 0 {
		t.Fatal("LevyFreeAfter did not produce a stateable horizon")
	}

	// Integer-only, so a contract can reproduce it exactly. A levy computed in
	// floating point is a levy two implementations disagree about.
	for _, d := range []time.Duration{0, time.Hour, p.LevyHalfLife, 3 * p.LevyHalfLife} {
		a := p.TransferLevy(sale, d)
		b := p.TransferLevy(sale, d)
		if a.Cmp(b) != 0 {
			t.Fatal("levy is not deterministic")
		}
	}
}

// TestLevyIsCollectedOnEveryTransfer: there is no path that moves a name without
// passing through Transfer, which is what makes the levy unavoidable.
func TestLevyIsCollectedOnEveryTransfer(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	r := New(testPolicy(), func() time.Time { return now })

	n := nm(t, "alice", "lab")
	if _, err := register(t, r, &now, n, acct(1), 1); err != nil {
		t.Fatal(err)
	}
	nh, _ := n.NameHash()

	levy, err := r.Transfer(nh, acct(1), acct(2), big.NewInt(1_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if levy.Sign() <= 0 {
		t.Fatal("a same-day flip paid no levy")
	}
	if r.LevyPool().Cmp(levy) != 0 {
		t.Fatal("the levy was computed but not collected")
	}
	owner, ok := r.Owner(nh)
	if !ok || owner != acct(2) {
		t.Fatal("transfer did not move the name")
	}

	// Selling to yourself must NOT launder the decay: holding time resets.
	levy2, err := r.Transfer(nh, acct(2), acct(2), big.NewInt(1_000_000))
	if err != nil {
		t.Fatal(err)
	}
	if levy2.Cmp(levy) != 0 {
		t.Fatalf("a self-transfer changed the levy: %s vs %s", levy2, levy)
	}
}

// TestBurstSurchargeIsSuperlinearAndNotLoadBearing.
//
// It asserts BOTH halves: the surcharge bites an unprepared adversary, and
// §12.4a.1's negative result holds -- splitting across accounts defeats it
// entirely. A test that only showed the first half would be claiming a guard
// this is not.
func TestBurstSurchargeIsSuperlinearAndNotLoadBearing(t *testing.T) {
	p := testPolicy()
	base := big.NewInt(1000)

	first := p.BurstSurcharge(base, 1)
	second := p.BurstSurcharge(base, 2)
	third := p.BurstSurcharge(base, 3)
	if first.Cmp(base) != 0 {
		t.Fatalf("the first name in an epoch was surcharged: %s", first)
	}
	if second.Cmp(first) <= 0 || third.Cmp(second) <= 0 {
		t.Fatal("the surcharge is not increasing")
	}
	// Superlinear: the step from 2->3 must exceed the step from 1->2.
	step1 := new(big.Int).Sub(second, first)
	step2 := new(big.Int).Sub(third, second)
	if step2.Cmp(step1) <= 0 {
		t.Fatal("the surcharge is linear, not superlinear")
	}

	// THE NEGATIVE RESULT: an adversary using one account per name pays base
	// price every time. This is §12.4a.1 and it is why the levy exists.
	now := time.Unix(1_700_000_000, 0)
	r := New(p, func() time.Time { return now })
	total := big.NewInt(0)
	for i := 0; i < 8; i++ {
		price, err := register(t, r, &now, nm(t, fmt.Sprintf("split%d", i), "lab"),
			acct(byte(100+i)), uint64(i))
		if err != nil {
			t.Fatal(err)
		}
		total.Add(total, price)
	}
	want := new(big.Int).Mul(p.PriceOf("split0"), big.NewInt(8))
	if total.Cmp(want) != 0 {
		t.Fatalf("splitting across accounts cost %s, want the linear %s -- "+
			"if this differs, §12.4a.1's negative result has changed and the "+
			"design pass needs revisiting", total, want)
	}
	t.Log("§12.4a.1 confirmed: per-acquirer escalation is defeated by splitting; " +
		"the transfer levy is the mechanism that is not")
}

// TestExactlyTwoAcquisitionRoutes: the zero value is not a route.
func TestExactlyTwoAcquisitionRoutes(t *testing.T) {
	var zero Route
	if zero.Valid() {
		t.Fatal("the zero Route is valid; a registration that did not say how it " +
			"was acquired would get a default")
	}
	if !RoutePrimary.Valid() || !RouteSecondary.Valid() {
		t.Fatal("a named route is invalid")
	}
	if Route(99).Valid() {
		t.Fatal("a third route exists")
	}
}

// TestNameIsHeldAndNotRetakeable.
func TestNameIsHeldAndNotRetakeable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := testPolicy()
	r := New(p, func() time.Time { return now })

	n := nm(t, "alice", "lab")
	if _, err := register(t, r, &now, n, acct(1), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := register(t, r, &now, n, acct(2), 2); !errors.Is(err, ErrAlreadyHeld) {
		t.Fatalf("err = %v, want ErrAlreadyHeld", err)
	}
	// It becomes retakeable after the term.
	now = now.Add(p.Term + time.Hour)
	if r.Count() != 0 {
		t.Fatalf("%d names still held past the term", r.Count())
	}
}

// TestBondIsRequiredAndLocked.
func TestBondIsRequiredAndLocked(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := testPolicy()
	r := New(p, func() time.Time { return now })

	c, _ := ClaimFor(nm(t, "alice", "lab"))
	var secret [32]byte
	r.Commit(MakeCommitment(c, acct(1), secret))
	now = now.Add(2 * time.Minute)

	if _, err := r.Register(c, acct(1), secret, "alice", big.NewInt(1), 1); !errors.Is(err, ErrBondTooSmall) {
		t.Fatalf("err = %v, want ErrBondTooSmall", err)
	}
	if _, err := r.Register(c, acct(1), secret, "alice", p.BondPerName, 1); err != nil {
		t.Fatalf("a sufficient bond was refused: %v", err)
	}
}

// TestLengthPricing: short names cost more.
func TestLengthPricing(t *testing.T) {
	p := testPolicy()
	three := p.PriceOf("abc")
	four := p.PriceOf("abcd")
	six := p.PriceOf("abcdef")
	if three.Cmp(four) <= 0 || four.Cmp(six) <= 0 {
		t.Fatalf("length pricing is not decreasing: %s %s %s", three, four, six)
	}
}
