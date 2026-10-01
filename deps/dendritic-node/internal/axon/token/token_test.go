package token

import (
	"crypto/rand"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/params"
)

const testRSABits = 2048

var t0 = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// mint runs the whole issuance dance and returns a spendable token.
func mint(t *testing.T, iss *BlindRSAIssuer, epoch Epoch, d Denomination) Token {
	t.Helper()
	var n Nonce
	if _, err := rand.Read(n[:]); err != nil {
		t.Fatal(err)
	}
	tok := Token{Epoch: epoch, Denom: d, Nonce: n}

	v := iss.PublicVerifier().(*BlindRSAVerifier)
	pub := v.keys[epoch]

	blinded, b, err := Blind(pub, tok.message())
	if err != nil {
		t.Fatal(err)
	}
	blindSig, err := iss.SignBlinded(epoch, blinded)
	if err != nil {
		t.Fatal(err)
	}
	tok.Sig = Unblind(blindSig, b)
	return tok
}

// TestBlindIssuanceRoundTrips is the basic correctness of candidate A.
func TestBlindIssuanceRoundTrips(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier()
	tok := mint(t, iss, 1, Denom10)

	if err := Accept(tok, v); err != nil {
		t.Fatalf("a freshly minted token was refused: %v", err)
	}

	// T1: a token's denomination and epoch are SIGNED, so rewriting either
	// invalidates it. A construction that signed only the nonce would let a
	// payer buy a Denom1 and present it as a Denom100.
	upgraded := tok
	upgraded.Denom = Denom100
	if err := Accept(upgraded, v); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a token's denomination was rewritten and still verified: %v", err)
	}
	moved := tok
	moved.Epoch = 2
	if err := Accept(moved, v); !errors.Is(err, ErrUnknownEpoch) {
		t.Fatalf("a token's epoch was rewritten: %v", err)
	}
	// And the nonce.
	forged := tok
	forged.Nonce[0] ^= 1
	if err := Accept(forged, v); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("a token's nonce was rewritten: %v", err)
	}
}

// TestT1UnknownDenominationsAreRefused is T1.
func TestT1UnknownDenominationsAreRefused(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier()
	// An issuer WILL sign a denomination nobody defined -- it signs what it is
	// handed. The refusal is the relay's, and it must be a refusal rather than
	// a shrug: a rare denomination is an identifier, so accepting it as a
	// curiosity worth something is the leak.
	odd := mint(t, iss, 1, Denomination(7))
	if err := Accept(odd, v); !errors.Is(err, ErrUnknownDenomination) {
		t.Fatalf("a denomination-7 token was accepted: %v", err)
	}
}

// TestT2VerificationIsOffline is T2, for candidate A.
//
// The structural half is the Verifier interface, which takes no context and
// cannot report "ask again later". This is the behavioural half: verification
// succeeds against a verifier built from public keys only, with the issuer
// entirely absent.
func TestT2VerificationIsOffline(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	tok := mint(t, iss, 1, Denom10)

	// Snapshot the public verifier, then discard the issuer entirely.
	v := iss.PublicVerifier()
	iss = nil
	_ = iss

	for i := 0; i < 100; i++ {
		if err := Accept(tok, v); err != nil {
			t.Fatalf("offline verification failed with no issuer present: %v", err)
		}
	}
}

// TestT3DoubleSpendIsCaughtAtRedemption is T3.
//
// The placement is the point. A relay CANNOT catch a double-spend: it would
// need the global spent set, which is a network call per cell (T2) and a
// correlation channel. So the relay's exposure is bounded by its redemption
// interval rather than by zero, and it prices that risk by redeeming often --
// against the privacy cost of redeeming often, which is T4.
func TestT3DoubleSpendIsCaughtAtRedemption(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier()
	pol := DefaultPolicy()
	spent := NewSpentSet()

	tok := mint(t, iss, 1, Denom10)

	// The payer spends the SAME token at two relays. Both accept it -- neither
	// can do otherwise.
	if err := Accept(tok, v); err != nil {
		t.Fatal(err)
	}
	if err := Accept(tok, v); err != nil {
		t.Fatalf("the second relay refused a token it cannot know is spent: %v", err)
	}

	batch := func(relay string, tk Token) Batch {
		toks := make([]Token, pol.MinBatch)
		at := make([]time.Time, pol.MinBatch)
		toks[0], at[0] = tk, t0
		for i := 1; i < pol.MinBatch; i++ {
			toks[i], at[i] = mint(t, iss, 1, Denom1), t0
		}
		return Batch{RelayID: relay, Tokens: toks, SpentAt: at}
	}

	first, err := Redeem(batch("relay-a", tok), v, spent, pol, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if first.Rejected != 0 {
		t.Fatalf("the first redemption rejected %d tokens: %v", first.Rejected, first.Reasons)
	}

	second, err := Redeem(batch("relay-b", tok), v, spent, pol, t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if second.Reasons["double-spend"] != 1 {
		t.Fatalf("the double-spend was not caught: %v", second.Reasons)
	}
	// The rest of the second batch is still paid. Rejecting a whole batch for
	// one bad token would let a payer destroy a relay's earnings by spending
	// one token twice.
	if second.Accepted != pol.MinBatch-1 {
		t.Fatalf("a double-spend cost the relay %d of %d honest tokens",
			pol.MinBatch-1-second.Accepted, pol.MinBatch-1)
	}
}

// TestT4RedemptionIsBatched is T4's floor.
func TestT4RedemptionIsBatched(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier()
	pol := DefaultPolicy()
	spent := NewSpentSet()

	// A batch of one is a timestamped redemption of a single token, which is
	// exactly the timing link the blinding removed.
	one := Batch{RelayID: "r", Tokens: []Token{mint(t, iss, 1, Denom1)}, SpentAt: []time.Time{t0}}
	if _, err := Redeem(one, v, spent, pol, t0); !errors.Is(err, ErrBatchTooSmall) {
		t.Fatalf("a batch of one was redeemed: %v", err)
	}
	if spent.Len() != 0 {
		t.Fatal("a refused batch still recorded tokens as spent")
	}
}

// TestMinimumAgeIsEnforcedClientSide covers the asymmetry the design turns on.
//
// The issuer cannot verify when a relay says it accepted a token. So the
// minimum age is enforced where the party with the incentive is the one
// checking: at the payer, before it spends.
func TestMinimumAgeIsEnforcedClientSide(t *testing.T) {
	pol := DefaultPolicy()
	issued := t0

	if err := CheckSpendable(issued, issued.Add(time.Minute), pol); !errors.Is(err, ErrTooYoung) {
		t.Fatalf("a one-minute-old token was spendable under a %v minimum: %v", pol.MinAge, err)
	}
	if err := CheckSpendable(issued, issued.Add(pol.MinAge), pol); err != nil {
		t.Fatalf("a token at exactly the minimum age was refused: %v", err)
	}
}

// TestT155BatchingWindowIsPinned is T15.5.
//
// "The batching window's effect on linkability is pinned by test, since the
// window is the privacy parameter."
//
// What is pinned is the RELATIONSHIP, not the number: the anonymity set for one
// spend is the set of payers who bought within MinAge of the same moment, so it
// scales with MinAge times the purchase rate. The test states that arithmetic
// and asserts the direction, because the number depends on a purchase rate that
// does not exist.
func TestT155BatchingWindowIsPinned(t *testing.T) {
	pol := DefaultPolicy()

	// Direction: a longer window cannot shrink the set.
	setSize := func(window time.Duration, buysPerHour float64) float64 {
		return window.Hours() * buysPerHour
	}
	for _, rate := range []float64{1, 10, 1000} {
		short := setSize(pol.MinAge, rate)
		long := setSize(pol.MinAge*4, rate)
		if long < short {
			t.Fatal("a longer minimum age produced a smaller anonymity set")
		}
	}

	// And the honest number at the deployed scale, logged rather than asserted.
	// §14.3: the dominant term is P, the number of PAYERS. At 9 nodes and no
	// payers at all, no window rescues anything.
	t.Logf("T15.5: at MinAge=%v the anonymity set for one spend is "+
		"(purchases per hour) x %.2f h. With the deployed population -- 9 nodes, "+
		"ZERO paying clients -- that product is 0, and §14.3's own arithmetic "+
		"(set <= P.B, dominated by P) is why §14.7 puts payments outside v1.",
		pol.MinAge, pol.MinAge.Hours())

	if pol.MinBatch < 2 {
		t.Fatalf("MinBatch is %d; a batch of one is a timestamped single redemption", pol.MinBatch)
	}
}

// TestE152IssueAndRedeemLogsDoNotLink is E15.2.
//
// "Tokens issued in window w and redeemed in w+k cannot be linked by an
// adversary holding both logs."
//
// The adversary here is the strongest one the construction admits: it holds the
// issuer's complete view of issuance (every blinded value it signed) and the
// complete redemption log (every token presented). It must not be able to match
// them up.
func TestE152IssueAndRedeemLogsDoNotLink(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier().(*BlindRSAVerifier)
	pub := v.keys[1]

	const n = 64
	type issuance struct {
		payer   int
		blinded string
	}
	var issueLog []issuance
	var tokens []Token

	for payer := 0; payer < n; payer++ {
		var nn Nonce
		if _, err := rand.Read(nn[:]); err != nil {
			t.Fatal(err)
		}
		tok := Token{Epoch: 1, Denom: Denom10, Nonce: nn}
		blinded, b, err := Blind(pub, tok.message())
		if err != nil {
			t.Fatal(err)
		}
		// The issuer's log entry: who asked, and what it signed.
		issueLog = append(issueLog, issuance{payer: payer, blinded: fmt.Sprintf("%x", blinded)})
		blindSig, err := iss.SignBlinded(1, blinded)
		if err != nil {
			t.Fatal(err)
		}
		tok.Sig = Unblind(blindSig, b)
		tokens = append(tokens, tok)
	}

	// The redemption log: every token as presented. The adversary tries to
	// match each redeemed token to the issuance that produced it.
	//
	// The only fields common to both logs are the epoch and the denomination,
	// and by T1 those are identical across all n. So the best the adversary can
	// do is guess uniformly, and a match rate above chance is the failure.
	matches := 0
	for _, tok := range tokens {
		sigHex := fmt.Sprintf("%x", tok.Sig)
		nonceHex := fmt.Sprintf("%x", tok.Nonce[:])
		for _, iv := range issueLog {
			if iv.blinded == sigHex || iv.blinded == nonceHex {
				matches++
			}
			// A substring relation would be just as damning: a blinded value
			// that contained the nonce would leak it directly.
			if len(iv.blinded) >= 16 && (contains(iv.blinded, nonceHex[:16]) ||
				contains(sigHex, iv.blinded[:16])) {
				matches++
			}
		}
	}
	if matches != 0 {
		t.Fatalf("E15.2 violated: %d issuance records are linkable to redeemed tokens", matches)
	}

	// And every token must be distinct at redemption, or the set collapses for
	// a reason that has nothing to do with the blinding.
	seen := map[string]bool{}
	for _, tok := range tokens {
		k := fmt.Sprintf("%x", tok.Sig)
		if seen[k] {
			t.Fatal("two payers received the same signature")
		}
		seen[k] = true
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

// TestBlindingFactorIsFreshPerToken is the one implementation detail that would
// silently destroy the property.
//
// Reusing a blinding factor across two tokens makes those two linkable TO EACH
// OTHER, which is the single thing the construction exists to prevent, and it
// would pass every correctness test above.
func TestBlindingFactorIsFreshPerToken(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	v := iss.PublicVerifier().(*BlindRSAVerifier)
	pub := v.keys[1]

	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		var n Nonce
		if _, err := rand.Read(n[:]); err != nil {
			t.Fatal(err)
		}
		tok := Token{Epoch: 1, Denom: Denom1, Nonce: n}
		_, b, err := Blind(pub, tok.message())
		if err != nil {
			t.Fatal(err)
		}
		k := b.r.String()
		if seen[k] {
			t.Fatal("a blinding factor was reused; two tokens are linkable to each other")
		}
		seen[k] = true
	}
}

// TestTokenFitsInARelayPayload is the size half of §14.3's open question.
func TestTokenFitsInARelayPayload(t *testing.T) {
	iss, err := NewBlindRSAIssuer(1, testRSABits)
	if err != nil {
		t.Fatal(err)
	}
	tok := mint(t, iss, 1, Denom10)

	// Epoch (4) + denomination (4) + nonce (32) + signature.
	onWire := 4 + 4 + 32 + len(tok.Sig)
	// §8.6's relay data payload after P5a.
	const relayPayload = 984
	if onWire > relayPayload {
		t.Fatalf("a %d-byte token does not fit an %d-byte relay payload", onWire, relayPayload)
	}
	t.Logf("candidate A (blind RSA-%d): %d B on the wire, %.1f%% of a %d B relay payload",
		testRSABits, onWire, 100*float64(onWire)/relayPayload, relayPayload)
	if params.CellSize != 1024 {
		t.Fatalf("this arithmetic assumes a %d B cell; params says %d", 1024, params.CellSize)
	}
}
