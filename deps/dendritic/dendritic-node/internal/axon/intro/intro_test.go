package intro

import (
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func testPoint(t *testing.T, queueCap int) *IntroPoint {
	t.Helper()
	ip, err := New(Config{
		Scheme:                   ReferenceHashcash{},
		KBlind:                   []byte("service-key"),
		QueueCap:                 queueCap,
		AllowNonMemoryHardScheme: true, // a fixture; see reference_test_scheme.go
	})
	if err != nil {
		t.Fatal(err)
	}
	return ip
}

// TestT6a1NoPuzzleWhenNotUnderAttack is T6a.1 and PuzzleDifficultyMin.
//
// "A permanent puzzle taxes every honest user to defend against an attack that
// is not happening."
func TestT6a1NoPuzzleWhenNotUnderAttack(t *testing.T) {
	ip := testPoint(t, 100)
	p := ip.Puzzle()
	if p.Difficulty != 0 {
		t.Fatalf("a quiet intro point published difficulty %d, not 0", p.Difficulty)
	}
	if EffortOf(p.Difficulty) != 1 {
		t.Fatalf("difficulty 0 means effort %d, not 1", EffortOf(p.Difficulty))
	}
	// An honest client's solve is one nonce: no search, no latency cost.
	start := time.Now()
	sol, err := Solve(ReferenceHashcash{}, p, []byte("service-key"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if sol.Nonce != 0 {
		t.Fatalf("difficulty 0 still required a nonce search (reached %d)", sol.Nonce)
	}
	if d := time.Since(start); d > 50*time.Millisecond {
		t.Fatalf("difficulty 0 cost the client %v", d)
	}
	if _, err := ip.Verify(sol); err != nil {
		t.Fatalf("a difficulty-0 solution was refused: %v", err)
	}
}

// TestT6a2SolutionForOneSeedIsRefusedAgainstTheNext is T6a.2 — the whole value
// of seed rotation, which bounds a precomputed solution bank to one period.
func TestT6a2SolutionForOneSeedIsRefusedAgainstTheNext(t *testing.T) {
	ip := testPoint(t, 100)
	ip.ctrl.effort = 64 // make the puzzle non-trivial so the proof is seed-bound

	p := ip.Puzzle()
	sol, err := Solve(ReferenceHashcash{}, p, []byte("service-key"), 1<<22)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ip.Verify(sol); err != nil {
		t.Fatalf("a fresh solution was refused: %v", err)
	}

	if err := ip.RotateSeed(); err != nil {
		t.Fatal(err)
	}
	if _, err := ip.Verify(sol); err == nil {
		t.Fatal("a solution for the previous seed was accepted after rotation; a " +
			"precomputed bank outlives the period it was mined for")
	}
}

// TestT6a3VerificationIsAsymmetric is T6a.3 and E6a.2.
//
// The measurement is of THE EFFORT DIAL, not of memory-hardness: the reference
// scheme is a SHA-256 preimage and establishes nothing about resistance to
// specialised hardware. What it does establish is that the dial's cost lands on
// the solver, which is the half of the asymmetry this package implements.
func TestT6a3VerificationIsAsymmetric(t *testing.T) {
	ip := testPoint(t, 100)
	ip.ctrl.effort = 4096
	p := ip.Puzzle()

	start := time.Now()
	sol, err := Solve(ReferenceHashcash{}, p, []byte("service-key"), 1<<24)
	if err != nil {
		t.Skipf("no solution within budget: %v", err)
	}
	solveTime := time.Since(start)

	const reps = 200
	start = time.Now()
	for i := 0; i < reps; i++ {
		if _, err := ip.Verify(sol); err != nil {
			t.Fatal(err)
		}
	}
	verifyTime := time.Since(start) / reps

	if verifyTime*100 > solveTime {
		t.Fatalf("verification (%v) costs more than 1%% of solving (%v); E6a.2 fails "+
			"and the puzzle is itself the DoS", verifyTime, solveTime)
	}
	t.Logf("solve %v, verify %v (ratio %.0fx)", solveTime, verifyTime,
		float64(solveTime)/float64(verifyTime))
}

// TestT6a4NoAsymmetricCryptoBeforeVerification is T6a.4, as a source audit.
//
// An intro point that did a key exchange before checking the puzzle would be
// performing the attacker's chosen work at the attacker's chosen rate.
func TestT6a4NoAsymmetricCryptoBeforeVerification(t *testing.T) {
	for _, file := range []string{"puzzle.go", "point.go", "queue.go", "controller.go"} {
		body := readFile(t, file)
		code := stripComments(body)
		for _, forbidden := range []string{
			"ed25519.", "ecdsa.", "rsa.", "curve25519.", "ecdh.", "x509.",
		} {
			if strings.Contains(code, forbidden) {
				t.Errorf("T6a.4 violated: %s performs %s on the verification path; the "+
					"intro point would do asymmetric work at the attacker's chosen rate",
					file, forbidden)
			}
		}
	}
}

// TestT6a5DifficultyRisesUnderFloodAndReturns is T6a.5.
func TestT6a5DifficultyRisesUnderFloodAndReturns(t *testing.T) {
	c := NewController()
	if c.Difficulty() != 0 {
		t.Fatalf("a quiet controller starts at difficulty %d", c.Difficulty())
	}
	for i := 0; i < 30; i++ {
		c.Tick(QueueTarget * 10)
	}
	if c.Difficulty() == 0 {
		t.Fatal("difficulty did not rise under a sustained flood")
	}
	if c.Effort() > EffortCeiling {
		t.Fatalf("effort %d exceeded the ceiling %d", c.Effort(), EffortCeiling)
	}
	raised := c.Effort()

	for i := 0; i < 500; i++ {
		c.Tick(0)
	}
	if c.Difficulty() != 0 {
		t.Fatalf("difficulty stayed at %d after the flood stopped; an attacker who "+
			"stops paying keeps taxing every honest user", c.Difficulty())
	}
	if c.Effort() != 1 {
		t.Fatalf("effort settled at %d, not 1", c.Effort())
	}
	t.Logf("rose to effort %d, returned to %d", raised, c.Effort())
}

// TestControllerRisesFasterThanItFalls is conflict (2) from the package comment.
//
// §23.6 SPECIFIES ±1 BIT PER 10 s AND CALLS IT "asymmetric: rise fast, fall
// slow". ±1 bit is ×2 up and ÷2 down — symmetric in log space — so that
// parameter contradicts its own rationale and permits exactly the pulsing attack
// it was written to prevent. §9.6's ×1.5+1 / ×0.75 is what §23.6 meant.
func TestControllerRisesFasterThanItFalls(t *testing.T) {
	if !RisesFasterThanItFalls() {
		t.Fatal("the controller falls at least as fast as it rises; an attacker can " +
			"pulse the load, paying for the peaks and riding the troughs")
	}
	// The comparison must be in LOG space. In linear terms every multiplicative
	// controller looks asymmetric -- ×2 from 1000 gains 1000 while ÷2 loses 500
	// -- so a linear check scores ±1 bit as "rises faster than it falls", which
	// is the exact parameter this property exists to reject.
	if math.Log2(1.5) <= -math.Log2(0.75) {
		t.Fatal("the §9.6 step values are not asymmetric in log space")
	}
	if math.Log2(2.0) > -math.Log2(0.5) {
		t.Fatal("±1 bit was scored as asymmetric; the check cannot tell a symmetric " +
			"step from an asymmetric one")
	}
}

// TestT6a6HigherEffortIsAdmittedFirst is T6a.6.
func TestT6a6HigherEffortIsAdmittedFirst(t *testing.T) {
	q := NewQueue(100)
	q.Push(Admission{Effort: 4, Payload: []byte("cheap")})
	q.Push(Admission{Effort: 4096, Payload: []byte("expensive")})
	q.Push(Admission{Effort: 64, Payload: []byte("middling")})

	var order []string
	for {
		a, ok := q.Pop()
		if !ok {
			break
		}
		order = append(order, string(a.Payload))
	}
	want := []string{"expensive", "middling", "cheap"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("admitted in order %v, want %v", order, want)
		}
	}
}

// TestQueueIsFIFOAtDifficultyZero is T6a.1's other half.
//
// With no attack in progress every effort is 1, and the queue must behave
// exactly as it did before P6a existed.
func TestQueueIsFIFOAtDifficultyZero(t *testing.T) {
	q := NewQueue(100)
	for i := 0; i < 20; i++ {
		q.Push(Admission{Effort: 1, Payload: []byte{byte(i)}})
	}
	for i := 0; i < 20; i++ {
		a, _ := q.Pop()
		if a.Payload[0] != byte(i) {
			t.Fatalf("at difficulty 0 the queue reordered: got %d at position %d",
				a.Payload[0], i)
		}
	}
}

// TestFullQueueCanStillBeBoughtIntoByHigherEffort is why the LOWEST entry is
// displaced rather than the newest rejected.
//
// Dropping the newcomer would make the queue a first-come lock: an attacker who
// filled it once would hold it for the whole flood and no honest client could
// buy in at any price.
func TestFullQueueCanStillBeBoughtIntoByHigherEffort(t *testing.T) {
	q := NewQueue(4)
	for i := 0; i < 4; i++ {
		q.Push(Admission{Effort: 2, Payload: []byte("squatter")})
	}
	if !q.Push(Admission{Effort: 1000, Payload: []byte("honest")}) {
		t.Fatal("a high-effort client could not enter a full queue; an attacker who " +
			"fills it once holds it for the whole flood")
	}
	// STILL FULL at this point. A lower-effort newcomer is refused, or the bound
	// means nothing -- checked BEFORE popping, since popping makes room and the
	// push would then succeed for a reason that has nothing to do with effort.
	if q.Push(Admission{Effort: 1, Payload: []byte("cheap")}) {
		t.Fatal("a full queue accepted a lower-effort entry; the bound is not a bound")
	}
	if q.Len() != 4 {
		t.Fatalf("the queue holds %d entries, above its cap of 4", q.Len())
	}
	a, _ := q.Pop()
	if string(a.Payload) != "honest" {
		t.Fatalf("the high-effort entry did not reach the front: %s", a.Payload)
	}
}

// TestNonMemoryHardSchemeIsRefusedByDefault is §9.6's requirement (2).
func TestNonMemoryHardSchemeIsRefusedByDefault(t *testing.T) {
	_, err := New(Config{Scheme: ReferenceHashcash{}, KBlind: []byte("k")})
	if err == nil {
		t.Fatal("a non-memory-hard scheme was accepted without an explicit opt-in; a " +
			"CPU-only puzzle excludes phones and favours the attacker's hardware")
	}
	if !strings.Contains(err.Error(), "memory-hard") {
		t.Fatalf("the refusal did not name the reason: %v", err)
	}
	// And no scheme at all fails closed rather than defaulting to one.
	if _, err := New(Config{KBlind: []byte("k")}); err == nil {
		t.Fatal("an intro point was built with no scheme at all")
	}
	if _, err := Verify(nil, Puzzle{}, nil, Solution{}); err == nil {
		t.Fatal("Verify with no scheme did not fail closed; §9.6 leaves the scheme " +
			"[NEEDS RESEARCH] and this package must not invent one")
	}
}

// TestEffortEncodingRoundTrips pins the quarter-bit wire encoding.
func TestEffortEncodingRoundTrips(t *testing.T) {
	if EffortOf(0) != 1 {
		t.Fatalf("difficulty 0 is effort %d, not 1", EffortOf(0))
	}
	// Monotonic: a higher wire value is never a lower effort, or the controller
	// could raise difficulty and lower cost.
	prev := uint64(0)
	for d := 0; d <= 255; d++ {
		e := EffortOf(uint8(d))
		if e < prev {
			t.Fatalf("difficulty %d gives effort %d, below %d at %d", d, e, prev, d-1)
		}
		prev = e
	}
	// DifficultyFor rounds UP: publishing an easier difficulty than the
	// controller asked for would quietly admit more than the service decided.
	for _, effort := range []uint64{1, 2, 3, 10, 100, 1000, 1 << 20} {
		d := DifficultyFor(effort)
		if EffortOf(d) < effort {
			t.Fatalf("DifficultyFor(%d) = %d, whose effort %d is BELOW what was asked",
				effort, d, EffortOf(d))
		}
	}
	// Quarter bits are finer than the controller's smallest step (×0.75), or the
	// quantisation eats the asymmetry.
	if EffortOf(4)*100/EffortOf(3) > 125 {
		t.Fatalf("one difficulty step is a %d%% jump, coarser than the controller's "+
			"25%% fall", EffortOf(4)*100/EffortOf(3)-100)
	}
}

// TestChallengeBindsServiceAndEffort keeps a solution from being portable.
func TestChallengeBindsServiceAndEffort(t *testing.T) {
	var seed [32]byte
	seed[0] = 1
	base := Challenge(seed, []byte("service-a"), 100, 7)

	if string(base) == string(Challenge(seed, []byte("service-b"), 100, 7)) {
		t.Fatal("a solution mined for one service is valid against another")
	}
	if string(base) == string(Challenge(seed, []byte("service-a"), 200, 7)) {
		t.Fatal("effort is not bound into the challenge; a client could solve once " +
			"cheaply and claim any effort")
	}
	var other [32]byte
	other[0] = 2
	if string(base) == string(Challenge(other, []byte("service-a"), 100, 7)) {
		t.Fatal("the seed is not bound into the challenge")
	}
}

// TestEffortIsVerifiedNotClaimed guards the queue's ordering input.
func TestEffortIsVerifiedNotClaimed(t *testing.T) {
	ip := testPoint(t, 100)
	ip.ctrl.effort = 256
	p := ip.Puzzle()
	sol, err := Solve(ReferenceHashcash{}, p, []byte("service-key"), 1<<24)
	if err != nil {
		t.Skipf("no solution within budget: %v", err)
	}
	// Inflate the claim without redoing the work.
	sol.Effort = 1 << 30
	if _, err := ip.Verify(sol); err == nil {
		t.Fatal("an inflated effort claim was accepted; the queue would be ordered " +
			"by whoever lies hardest, and lying is free")
	}
}

// TestEffortDialIsWhatCostsTheClient is §9.6's second condition, on its own.
//
// IT EXISTS BECAUSE THE OTHER TESTS DID NOT COVER IT. Deleting the
// `meetsEffort` check from Verify broke nothing: the inflated-claim test is
// caught one line earlier, because effort is bound into the challenge, so a
// forged claim produces a proof for a different challenge and fails the scheme
// check instead. The dial — the thing that makes a high effort actually COST
// something rather than merely be asserted — had no test at all.
//
// So this one constructs the case only the dial can reject: a proof that is
// genuinely correct for its challenge and simply is not lucky enough.
func TestEffortDialIsWhatCostsTheClient(t *testing.T) {
	var seed [32]byte
	seed[0] = 9
	kBlind := []byte("service-key")
	const effort = 4096

	// Find a nonce whose proof VERIFIES (it always does — the scheme is
	// deterministic) but does NOT clear the effort target.
	var bad Solution
	found := false
	for nonce := uint32(0); nonce < 1<<16; nonce++ {
		ch := Challenge(seed, kBlind, effort, nonce)
		proof, err := (ReferenceHashcash{}).Solve(ch)
		if err != nil {
			t.Fatal(err)
		}
		if !(ReferenceHashcash{}).Verify(ch, proof) {
			t.Fatal("the reference scheme does not verify its own output")
		}
		if !meetsEffort(ch, proof, effort) {
			bad = Solution{Nonce: nonce, Proof: proof, Effort: effort}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("no proof failed the effort target; the dial is not filtering at all")
	}

	p := Puzzle{Seed: seed, Difficulty: DifficultyFor(effort), SchemeName: (ReferenceHashcash{}).Name()}
	if _, err := Verify(ReferenceHashcash{}, p, kBlind, bad); err == nil {
		t.Fatal("a correct-but-insufficient proof was admitted; the effort dial is " +
			"not being applied, so a high difficulty costs the client nothing")
	} else if !errors.Is(err, ErrEffortNotMet) {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// And the dial is off entirely at effort 1 (difficulty 0), or T6a.1 fails.
	if !meetsEffort([]byte("anything"), []byte("at all"), 1) {
		t.Fatal("the effort dial filters at effort 1; difficulty 0 is not free")
	}
}
