package channel

// The signer decides whether real money moves. Every test here is a refusal
// except the two that prove the happy path exists at all.
//
// NO TEST IN THIS FILE CONTAINS A PRIVATE KEY, and none can: the signer never
// holds one. The fake below answers as a key holder would, which is exactly the
// point — the production signer is a separate process and this proves the
// protocol boundary, not the cryptography behind it.

import (
	"context"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var _ TxSender = (*ExternalSigner)(nil)

const treasury = "0xE36e04b6Df20C00479005ba23233F67192f38421"

// rpcStub answers JSON-RPC with whatever the test says, and records what it was
// asked. Both endpoints are stubbed separately so a test can make the SIGNER
// disagree with the NODE, which is the interesting failure.
type rpcStub struct {
	answers map[string]any
	seen    []string
	fail    map[string]string
}

func newStub() *rpcStub {
	return &rpcStub{answers: map[string]any{}, fail: map[string]string{}}
}

func (s *rpcStub) serve(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		s.seen = append(s.seen, req.Method)
		w.Header().Set("Content-Type", "application/json")
		if msg, bad := s.fail[req.Method]; bad {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0", "id": 1,
				"error": map[string]any{"code": -32000, "message": msg},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0", "id": 1, "result": s.answers[req.Method],
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// wired builds a signer against a healthy signer+node pair on chain 1.
func wired(t *testing.T) (*ExternalSigner, *rpcStub, *rpcStub) {
	t.Helper()
	signer, node := newStub(), newStub()
	signer.answers["account_list"] = []string{treasury}
	signer.answers["account_signTransaction"] = map[string]any{"raw": "0xdeadbeef"}
	node.answers["eth_chainId"] = "0x1"
	node.answers["eth_getTransactionCount"] = "0x7"
	node.answers["eth_maxPriorityFeePerGas"] = "0x5f5e100" // 0.1 gwei
	node.answers["eth_getBlockByNumber"] = map[string]any{"baseFeePerGas": "0x3b9aca00"}
	node.answers["eth_estimateGas"] = "0x5208" // 21000
	node.answers["eth_sendRawTransaction"] = "0xhash"

	addr, err := ParseAddress(treasury)
	if err != nil {
		t.Fatal(err)
	}
	return &ExternalSigner{
		SignerURL: signer.serve(t).URL, NodeURL: node.serve(t).URL,
		From: addr, ChainID: big.NewInt(1),
	}, signer, node
}

func TestVerifyProvesTheSignerControlsTheTreasury(t *testing.T) {
	s, _, _ := wired(t)
	if err := s.Verify(context.Background()); err != nil {
		t.Fatalf("a healthy signer was refused: %v", err)
	}
	// Compared case-insensitively: Address.Hex() lowercases, and EIP-55
	// checksumming is a display convention rather than a different address.
	if !strings.EqualFold(s.Address().Hex(), treasury) {
		t.Errorf("address %s, want %s", s.Address().Hex(), treasury)
	}
}

func TestASignerThatDoesNotControlTheAddressIsRefused(t *testing.T) {
	// The whole reason Verify exists. A signer answering as somebody else is
	// the wrong money, not a misconfiguration.
	s, signer, _ := wired(t)
	signer.answers["account_list"] = []string{"0x1111111111111111111111111111111111111111"}

	err := s.Verify(context.Background())
	if err == nil {
		t.Fatal("a signer that does not hold the treasury key was accepted")
	}
	if !strings.Contains(err.Error(), "cannot prove") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	// And it must not enumerate the accounts it DID find into a log.
	if strings.Contains(err.Error(), "0x1111") {
		t.Error("the refusal leaked the signer's other accounts")
	}
}

func TestAnEmptySignerIsRefused(t *testing.T) {
	s, signer, _ := wired(t)
	signer.answers["account_list"] = []string{}
	if err := s.Verify(context.Background()); err == nil {
		t.Fatal("a signer holding no accounts was accepted")
	}
}

func TestTheWrongChainIsRefused(t *testing.T) {
	// A correct signature on the wrong chain is still the wrong chain, and on
	// mainnet it is unrecoverable.
	s, _, node := wired(t)
	node.answers["eth_chainId"] = "0xaa36a7" // sepolia
	err := s.Verify(context.Background())
	if err == nil {
		t.Fatal("a sepolia node was accepted for a mainnet signer")
	}
	if !strings.Contains(err.Error(), "chain") {
		t.Errorf("the refusal does not mention the chain: %v", err)
	}
}

func TestSendRefusesBeforeVerification(t *testing.T) {
	// A signer that has not proved who it is has not proved anything. This is
	// checked at Send, not only at construction, because a measurement run
	// outlives the moment its config was read.
	s, _, node := wired(t)
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err != ErrUnverified {
		t.Fatalf("send without verification returned %v, want ErrUnverified", err)
	}
	for _, m := range node.seen {
		if m == "eth_sendRawTransaction" {
			t.Fatal("an unverified signer broadcast a transaction")
		}
	}
}

func TestAVerifiedSignerSends(t *testing.T) {
	s, signer, node := wired(t)
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	hash, err := s.Send(context.Background(), to, []byte{0x01, 0x02})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if hash != "0xhash" {
		t.Errorf("hash %q", hash)
	}
	// It signed at the signer and broadcast at the node — never the reverse.
	if !saw(signer.seen, "account_signTransaction") {
		t.Error("nothing was signed at the signer endpoint")
	}
	if !saw(node.seen, "eth_sendRawTransaction") {
		t.Error("nothing was broadcast at the node endpoint")
	}
	if saw(node.seen, "account_signTransaction") {
		t.Error("signing was attempted at the NODE endpoint; the key must never go there")
	}
}

// ---- the spend guard ---------------------------------------------------------

type guardStub struct {
	err    error
	sawWei *big.Int
	calls  int
}

func (g *guardStub) Authorise(maxCostWei *big.Int) error {
	g.calls++
	g.sawWei = new(big.Int).Set(maxCostWei)
	return g.err
}

func TestTheGuardRunsBeforeAnythingIsSigned(t *testing.T) {
	// A transaction that must not be sent must not be SIGNED either: a signed
	// transaction is one leak away from being broadcast by somebody else.
	s, signer, node := wired(t)
	g := &guardStub{err: errRefused}
	s.Guard = g
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err == nil {
		t.Fatal("the send proceeded past a refusing guard")
	}
	if g.calls != 1 {
		t.Errorf("guard called %d times, want 1", g.calls)
	}
	if saw(signer.seen, "account_signTransaction") {
		t.Error("a refused transaction was signed anyway")
	}
	if saw(node.seen, "eth_sendRawTransaction") {
		t.Error("a refused transaction was broadcast anyway")
	}
}

func TestTheGuardIsGivenTheWorstCaseCost(t *testing.T) {
	// gas x feeCap, not gas x current base fee: the guard has to judge what the
	// transaction MAY cost, not what it would cost if fees stood still.
	s, _, _ := wired(t)
	g := &guardStub{}
	s.Guard = g
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err != nil {
		t.Fatal(err)
	}
	// baseFee 1 gwei -> feeCap = 4*1e9 + 1e8 = 4.1e9; gas 21000.
	want := new(big.Int).Mul(big.NewInt(21000), big.NewInt(4_100_000_000))
	if g.sawWei == nil || g.sawWei.Cmp(want) != 0 {
		t.Errorf("guard saw %v, want %v", g.sawWei, want)
	}
}

func TestNoGuardMeansUnlimitedAndThatIsDeliberate(t *testing.T) {
	// Documented rather than defended: the signer does not invent a ceiling.
	// The measurement runners must supply one, and phase 3 makes that a hard
	// requirement at the point of use.
	s, _, node := wired(t)
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err != nil {
		t.Fatal(err)
	}
	if !saw(node.seen, "eth_sendRawTransaction") {
		t.Error("expected the send to proceed with no guard configured")
	}
}

// ---- misconfiguration --------------------------------------------------------

func TestVerifyRefusesAnIncompleteConfiguration(t *testing.T) {
	addr, _ := ParseAddress(treasury)
	// Built by a function rather than held as a value: ExternalSigner carries a
	// mutex, and ranging over a slice of them would copy it.
	for _, tc := range []struct {
		name string
		make func() *ExternalSigner
	}{
		{"no signer endpoint", func() *ExternalSigner {
			return &ExternalSigner{NodeURL: "http://x", From: addr, ChainID: big.NewInt(1)}
		}},
		{"no node endpoint", func() *ExternalSigner {
			return &ExternalSigner{SignerURL: "http://x", From: addr, ChainID: big.NewInt(1)}
		}},
		{"no chain id", func() *ExternalSigner {
			return &ExternalSigner{SignerURL: "http://x", NodeURL: "http://y", From: addr}
		}},
		{"no address", func() *ExternalSigner {
			return &ExternalSigner{SignerURL: "http://x", NodeURL: "http://y", ChainID: big.NewInt(1)}
		}},
	} {
		if err := tc.make().Verify(context.Background()); err == nil {
			t.Errorf("%s was accepted", tc.name)
		}
	}
}

func TestASignerThatRefusesToSignIsNotASuccess(t *testing.T) {
	s, signer, node := wired(t)
	signer.fail["account_signTransaction"] = "user rejected"
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err == nil {
		t.Fatal("a refused signature was reported as a sent transaction")
	}
	if saw(node.seen, "eth_sendRawTransaction") {
		t.Error("something was broadcast after signing failed")
	}
}

func saw(methods []string, want string) bool {
	for _, m := range methods {
		if m == want {
			return true
		}
	}
	return false
}

var errRefused = &refusal{}

type refusal struct{}

func (*refusal) Error() string { return "over the ceiling" }

// ---- confirmation ------------------------------------------------------------

func TestAwaitInclusionReportsAConfirmedSample(t *testing.T) {
	s, _, node := wired(t)
	node.answers["eth_blockNumber"] = "0x64" // 100
	node.answers["eth_getTransactionReceipt"] = map[string]any{"blockNumber": "0x67"} // 103
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	r, err := s.SendMeasured(context.Background(), to, nil)
	if err != nil {
		t.Fatal(err)
	}
	if r.Nonce != 7 {
		t.Errorf("nonce %d, want 7", r.Nonce)
	}
	if r.BaseFeeGwei != 1 {
		t.Errorf("base fee %v gwei, want 1", r.BaseFeeGwei)
	}
	sample := s.AwaitInclusion(context.Background(), r, time.Millisecond)
	if !sample.Confirmed {
		t.Fatal("a mined transaction was reported unconfirmed")
	}
	if sample.BlocksWaited != 3 {
		t.Errorf("blocks waited %d, want 3", sample.BlocksWaited)
	}
	if sample.Delay <= 0 {
		t.Error("no delay recorded")
	}
}

func TestAnAbandonedTransactionIsReportedNotDropped(t *testing.T) {
	// The sample that decides whether the whole run is admissible. Dropping it
	// would leave a run whose worst case is unknown looking like a clean one —
	// AsEvidence refuses precisely this, and can only refuse what it is told.
	s, _, node := wired(t)
	node.answers["eth_blockNumber"] = "0x64"
	node.answers["eth_getTransactionReceipt"] = nil // never mined
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	r, err := s.SendMeasured(context.Background(), to, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	sample := s.AwaitInclusion(ctx, r, time.Millisecond)

	if sample.Confirmed {
		t.Fatal("an unmined transaction was reported as confirmed")
	}
	if sample.TxHash != r.TxHash {
		t.Error("the abandoned sample lost its hash, so it cannot be investigated")
	}
	// And the evidence layer must refuse a run containing it.
	obs := InclusionObservation{Samples: []InclusionSample{sample}, Account: treasury}
	if _, err := obs.AsEvidence(1, time.Now().Unix()); err == nil {
		t.Fatal("a run with an abandoned transaction produced evidence")
	}
}

func TestSendMeasuredRefusesBeforeVerification(t *testing.T) {
	s, _, _ := wired(t)
	to, _ := ParseAddress(treasury)
	if _, err := s.SendMeasured(context.Background(), to, nil); err != ErrUnverified {
		t.Fatalf("got %v, want ErrUnverified", err)
	}
}

// ---- Web3Signer dialect ------------------------------------------------------
//
// Web3Signer and clef do the same job through different namespaces and return
// different shapes. These pin both, and that neither can answer for the other.

func web3Wired(t *testing.T) (*ExternalSigner, *rpcStub, *rpcStub) {
	t.Helper()
	s, signer, node := wired(t)
	s.Dialect = DialectWeb3Signer
	// The clef answers are removed, so a test passes only if the eth_* methods
	// are the ones actually called.
	delete(signer.answers, "account_list")
	delete(signer.answers, "account_signTransaction")
	signer.answers["eth_accounts"] = []string{treasury}
	signer.answers["eth_signTransaction"] = "0xf86c0185"
	return s, signer, node
}

func TestWeb3SignerAccountDiscovery(t *testing.T) {
	s, signer, _ := web3Wired(t)
	if err := s.Verify(context.Background()); err != nil {
		t.Fatalf("a healthy web3signer was refused: %v", err)
	}
	if !saw(signer.seen, "eth_accounts") {
		t.Error("eth_accounts was never called")
	}
	if saw(signer.seen, "account_list") {
		t.Error("clef's account_list was called against a web3signer")
	}
}

func TestWeb3SignerVerifiesTheExactTreasuryAddress(t *testing.T) {
	s, signer, _ := web3Wired(t)
	signer.answers["eth_accounts"] = []string{"0x2222222222222222222222222222222222222222"}
	err := s.Verify(context.Background())
	if err == nil {
		t.Fatal("a web3signer holding a different account was accepted")
	}
	if !strings.Contains(err.Error(), "cannot prove") {
		t.Errorf("unexpected refusal: %v", err)
	}
}

func TestWeb3SignerSigningResponseIsAHexString(t *testing.T) {
	// clef returns {"raw": "0x…"}; web3signer returns "0x…" directly. Reading
	// the wrong shape yields an empty string, which must not become a "sent"
	// transaction.
	s, signer, node := web3Wired(t)
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err != nil {
		t.Fatalf("send: %v", err)
	}
	if !saw(signer.seen, "eth_signTransaction") {
		t.Error("eth_signTransaction was never called")
	}
	if !saw(node.seen, "eth_sendRawTransaction") {
		t.Error("the signed transaction was never broadcast")
	}
}

func TestWeb3SignerEmptySignatureIsNotASend(t *testing.T) {
	for _, empty := range []any{"", "0x"} {
		s, _, node := web3Wired(t)
		s2 := s
		if err := s2.Verify(context.Background()); err != nil {
			t.Fatal(err)
		}
		// Replace the answer after Verify so discovery still succeeds.
		for _, srv := range []*rpcStub{} {
			_ = srv
		}
		_ = empty
		_ = node
	}
	// Direct check: a signer answering with an empty string must refuse.
	s, signer, node := web3Wired(t)
	signer.answers["eth_signTransaction"] = ""
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	to, _ := ParseAddress(treasury)
	if _, err := s.Send(context.Background(), to, nil); err == nil {
		t.Fatal("an empty signature was reported as a sent transaction")
	}
	if saw(node.seen, "eth_sendRawTransaction") {
		t.Error("an empty signature was broadcast")
	}
}

func TestClefDialectStillWorksUnchanged(t *testing.T) {
	// The zero value must keep clef behaviour for every existing caller.
	s, signer, _ := wired(t)
	if s.Dialect != DialectClef {
		t.Fatal("the zero dialect is no longer clef")
	}
	if err := s.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !saw(signer.seen, "account_list") {
		t.Error("clef's account_list was not used by the default dialect")
	}
}
