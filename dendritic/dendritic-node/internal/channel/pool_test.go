package channel

// P15 — tipping pools.
//
// The property every test here defends: a pool is a DERIVED VIEW. It stores no
// balance, so there is no balance it can get wrong, and "non-custodial" is a
// fact about the types rather than a promise about the code.

import (
	"errors"
	"math/big"
	"reflect"
	"strings"
	"testing"
)

// memSource is a ChannelSource backed by a map — the recipient's own store,
// minus the disk.
type memSource struct {
	ch map[[32]byte]*Channel
}

func newMemSource() *memSource { return &memSource{ch: map[[32]byte]*Channel{}} }

func (m *memSource) IDs() [][32]byte {
	out := make([][32]byte, 0, len(m.ch))
	for id := range m.ch {
		out = append(out, id)
	}
	return out
}

func (m *memSource) Get(id [32]byte) (*Channel, bool) {
	c, ok := m.ch[id]
	return c, ok
}

// poolFixture builds channels between one recipient and several contributors.
type poolFixture struct {
	t         *testing.T
	src       *memSource
	recipient Address
	next      byte
}

func newPoolFixture(t *testing.T) *poolFixture {
	t.Helper()
	var r Address
	r[0] = 0xAA
	return &poolFixture{t: t, src: newMemSource(), recipient: r, next: 1}
}

// add creates a channel where the recipient holds `mine` and the contributor
// holds `theirs`, with any locks live.
func (f *poolFixture) add(mine, theirs int64, locks ...HTLC) [32]byte {
	f.t.Helper()
	var other Address
	other[0] = f.next
	f.next++

	var id [32]byte
	id[0], id[1] = 0xC0, other[0]

	// The contract orders parties by address; the recipient may be either side,
	// and the pool must read the right one.
	a, b := SortParties(f.recipient, other)
	recipientIsA := a == f.recipient
	balA, balB := big.NewInt(theirs), big.NewInt(mine)
	if recipientIsA {
		balA, balB = big.NewInt(mine), big.NewInt(theirs)
	}

	ch := &Channel{
		ID: id, PartyA: a, PartyB: b,
		DepositA: big.NewInt(1000), DepositB: big.NewInt(1000),
		Status: StatusOpen, ChainID: big.NewInt(1),
		Latest: SignedState{
			State: State{
				Channel: id, Nonce: 1,
				BalanceA: balA, BalanceB: balB, Pending: locks,
			},
			SigA: make([]byte, 65), SigB: make([]byte, 65),
		},
	}
	f.src.ch[id] = ch
	return id
}

func (f *poolFixture) pool(members ...[32]byte) Pool {
	return Pool{
		Name: "tips", Recipient: f.recipient, Members: members,
		Policy: PoolPolicy{Enabled: true},
	}
}

// ---- optionality ------------------------------------------------------------

func TestPoolIsDisabledByDefault(t *testing.T) {
	f := newPoolFixture(t)
	id := f.add(100, 0)

	// The ZERO VALUE. A recipient who never opts in never gets a pool.
	p := Pool{Name: "tips", Recipient: f.recipient, Members: [][32]byte{id}}
	if _, err := p.View(f.src); !errors.Is(err, ErrPoolDisabled) {
		t.Fatalf("a default pool answered; bilateral must stay the default. got %v", err)
	}
	if _, err := p.CheckpointPlan(f.src); !errors.Is(err, ErrPoolDisabled) {
		t.Fatalf("a default pool produced a checkpoint plan: %v", err)
	}
}

// ---- the aggregate ----------------------------------------------------------

func TestPoolViewSumsTheRecipientsSideOnly(t *testing.T) {
	f := newPoolFixture(t)
	// Deliberately several counterparties so the recipient lands on BOTH sides
	// of the contract's address ordering.
	a := f.add(25, 975)
	b := f.add(100, 900)
	c := f.add(5, 995)

	view, err := f.pool(a, b, c).View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if got, want := view.Withdrawable, big.NewInt(130); got.Cmp(want) != 0 {
		t.Errorf("aggregate %s, want %s — the recipient's side was read wrongly on "+
			"at least one channel", got, want)
	}
	if view.Members != 3 || view.Contributors != 3 {
		t.Errorf("members %d contributors %d, want 3 and 3", view.Members, view.Contributors)
	}
}

func TestLockedValueIsNotWithdrawable(t *testing.T) {
	f := newPoolFixture(t)
	plain := f.add(40, 0)
	// A live lock. KindLockAdd already took this out of the payer's balance, so
	// it must appear as in-flight and NEVER as spendable.
	locked := f.add(10, 0, HTLC{
		ID: [32]byte{1}, Amount: big.NewInt(90), Expiry: 1 << 40, PayerIsA: true,
	})

	view, err := f.pool(plain, locked).View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if got, want := view.Withdrawable, big.NewInt(50); got.Cmp(want) != 0 {
		t.Errorf("withdrawable %s, want %s — locked value must not be spendable", got, want)
	}
	if got, want := view.InFlight, big.NewInt(90); got.Cmp(want) != 0 {
		t.Errorf("in-flight %s, want %s", got, want)
	}
}

func TestNonOpenChannelsAreExcludedWithAReason(t *testing.T) {
	f := newPoolFixture(t)
	open := f.add(30, 0)
	closing := f.add(70, 0)
	f.src.ch[closing].Status = StatusClosing

	view, err := f.pool(open, closing).View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if got, want := view.Withdrawable, big.NewInt(30); got.Cmp(want) != 0 {
		t.Errorf("withdrawable %s, want %s: a closing channel cannot be checkpointed", got, want)
	}
	if len(view.Excluded) != 1 || view.Excluded[0].Channel != closing {
		t.Fatalf("the closing channel was dropped silently: %+v", view.Excluded)
	}
	if !strings.Contains(view.Excluded[0].Reason, "checkpoint requires an open channel") {
		t.Errorf("exclusion gives no usable reason: %q", view.Excluded[0].Reason)
	}
}

// A pool that lists a channel its recipient is not in is WRONG ABOUT ITSELF.
// Returning a smaller number would look like a payment that vanished.
func TestAChannelTheRecipientIsNotInIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	mine := f.add(10, 0)

	var stranger, other Address
	stranger[0], other[0] = 0xEE, 0xEF
	var id [32]byte
	id[0] = 0xDD
	a, b := SortParties(stranger, other)
	f.src.ch[id] = &Channel{
		ID: id, PartyA: a, PartyB: b, Status: StatusOpen,
		Latest: SignedState{
			State: State{Channel: id, Nonce: 1, BalanceA: big.NewInt(1), BalanceB: big.NewInt(1)},
			SigA:  make([]byte, 65), SigB: make([]byte, 65),
		},
	}

	if _, err := f.pool(mine, id).View(f.src); !errors.Is(err, ErrNotAParty) {
		t.Fatalf("a foreign channel was tolerated in a pool; got %v", err)
	}
}

// ---- the invariant nothing structural protects ------------------------------

func TestPoolsMustBeDisjoint(t *testing.T) {
	f := newPoolFixture(t)
	shared := f.add(50, 0)
	only := f.add(20, 0)

	one := f.pool(shared, only)
	one.Name = "subs"
	two := f.pool(shared)
	two.Name = "tips"

	err := CheckDisjoint([]Pool{one, two})
	if !errors.Is(err, ErrPoolOverlap) {
		t.Fatalf("two pools claimed one channel and it was accepted; the value "+
			"would be counted twice and only one view could be withdrawn. got %v", err)
	}
	if !strings.Contains(err.Error(), "subs") || !strings.Contains(err.Error(), "tips") {
		t.Errorf("the refusal does not name both pools: %v", err)
	}
	if err := CheckDisjoint([]Pool{f.pool(only), f.pool(shared)}); err != nil {
		t.Errorf("disjoint pools were refused: %v", err)
	}
}

// ---- checkpoint policy ------------------------------------------------------

func TestCheckpointPlanRespectsTheMinimum(t *testing.T) {
	f := newPoolFixture(t)
	big1 := f.add(500, 0)
	small := f.add(3, 0)
	zero := f.add(0, 100)

	p := f.pool(big1, small, zero)
	p.Policy.MinCheckpoint = big.NewInt(100)

	plan, err := p.CheckpointPlan(f.src)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan) != 1 || plan[0].Channel != big1 {
		t.Fatalf("plan %+v; only the channel above the minimum should be there", plan)
	}
	if plan[0].Amount.Cmp(big.NewInt(500)) != 0 {
		t.Errorf("amount %s, want 500", plan[0].Amount)
	}
}

// The contract ALLOWS a checkpoint with locks outstanding — closeCooperative
// does not. The plan must surface that rather than hide it.
func TestCheckpointPlanFlagsLiveLocks(t *testing.T) {
	f := newPoolFixture(t)
	clean := f.add(200, 0)
	withLock := f.add(200, 0, HTLC{
		ID: [32]byte{7}, Amount: big.NewInt(50), Expiry: 1 << 40,
	})

	plan, err := f.pool(clean, withLock).CheckpointPlan(f.src)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if len(plan) != 2 {
		t.Fatalf("plan has %d entries, want 2 — a live lock does not bar a checkpoint", len(plan))
	}
	byID := map[[32]byte]CheckpointCandidate{}
	for _, c := range plan {
		byID[c.Channel] = c
	}
	if byID[clean].LocksLive {
		t.Error("a channel with no locks was flagged as having them")
	}
	if !byID[withLock].LocksLive {
		t.Error("a channel with a live lock was NOT flagged; the caller needs to " +
			"pass the lock set to the contract's checkpoint")
	}
}

// ---- it is a view, and that is structural -----------------------------------

// Pool must not grow a field that could hold value. The moment it does, it is a
// ledger and somebody has to be trusted to keep it right.
func TestPoolStoresNoBalance(t *testing.T) {
	banned := []string{"balance", "amount", "total", "aggregate", "credit",
		"owed", "value", "sum", "ledger"}
	pt := reflect.TypeOf(Pool{})
	for i := 0; i < pt.NumField(); i++ {
		name := strings.ToLower(pt.Field(i).Name)
		for _, b := range banned {
			if strings.Contains(name, b) {
				t.Errorf("Pool.%s looks like stored value. A pool is a DERIVED VIEW; "+
					"the moment it holds a balance it becomes a custodian.", pt.Field(i).Name)
			}
		}
		// A *big.Int on the Pool itself is the giveaway.
		if pt.Field(i).Type == reflect.TypeOf((*big.Int)(nil)) {
			t.Errorf("Pool.%s is a *big.Int; a pool must carry no value",
				pt.Field(i).Name)
		}
	}
}

// The aggregate follows the store because it is recomputed. This is also the
// recovery property: there is no pool state to restore.
func TestViewIsRecomputedNotCached(t *testing.T) {
	f := newPoolFixture(t)
	id := f.add(10, 90)
	p := f.pool(id)

	first, err := p.View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if first.Withdrawable.Cmp(big.NewInt(10)) != 0 {
		t.Fatalf("aggregate %s, want 10", first.Withdrawable)
	}

	// A tip arrives: the signed state moves.
	ch := f.src.ch[id]
	recipientIsA := ch.PartyA == f.recipient
	if recipientIsA {
		ch.Latest.State.BalanceA = big.NewInt(60)
		ch.Latest.State.BalanceB = big.NewInt(40)
	} else {
		ch.Latest.State.BalanceB = big.NewInt(60)
		ch.Latest.State.BalanceA = big.NewInt(40)
	}
	ch.Latest.State.Nonce = 2

	second, err := p.View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if second.Withdrawable.Cmp(big.NewInt(60)) != 0 {
		t.Errorf("aggregate %s after the state moved, want 60 — the view is being "+
			"cached somewhere", second.Withdrawable)
	}
	if first.Withdrawable.Cmp(big.NewInt(10)) != 0 {
		t.Error("the earlier view mutated; View must return an independent value")
	}
}

// "How is pool state recovered after a restart?" — there is none. A brand-new
// Pool value over the same store gives the same answer.
func TestViewSurvivesRestartBecauseThereIsNoState(t *testing.T) {
	f := newPoolFixture(t)
	a, b := f.add(15, 0), f.add(35, 0)

	before, err := f.pool(a, b).View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}

	// "Restart": a freshly constructed Pool, nothing carried over but config.
	restarted := Pool{
		Name: "tips", Recipient: f.recipient, Members: [][32]byte{a, b},
		Policy: PoolPolicy{Enabled: true},
	}
	after, err := restarted.View(f.src)
	if err != nil {
		t.Fatalf("view after restart: %v", err)
	}
	if before.Withdrawable.Cmp(after.Withdrawable) != 0 {
		t.Errorf("aggregate changed across restart: %s then %s",
			before.Withdrawable, after.Withdrawable)
	}
	if after.Withdrawable.Cmp(big.NewInt(50)) != 0 {
		t.Errorf("aggregate %s, want 50", after.Withdrawable)
	}
}

// A member the node does not hold is reported, not silently dropped.
func TestUnknownMemberIsReported(t *testing.T) {
	f := newPoolFixture(t)
	known := f.add(10, 0)
	var missing [32]byte
	missing[0] = 0x99

	view, err := f.pool(known, missing).View(f.src)
	if err != nil {
		t.Fatalf("view: %v", err)
	}
	if len(view.Excluded) != 1 || view.Excluded[0].Channel != missing {
		t.Fatalf("a missing member was not reported: %+v", view.Excluded)
	}
	if view.Withdrawable.Cmp(big.NewInt(10)) != 0 {
		t.Errorf("aggregate %s, want 10", view.Withdrawable)
	}
}

func TestEmptyPoolIsRefused(t *testing.T) {
	f := newPoolFixture(t)
	p := f.pool()
	if _, err := p.View(f.src); !errors.Is(err, ErrPoolEmpty) {
		t.Fatalf("an empty pool produced a view: %v", err)
	}
}
