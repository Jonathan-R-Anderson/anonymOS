package registrar

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"math/big"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/axon/contracts"
	"github.com/syndichan/maniwani/storage-client/internal/axon/name"
)

// THE VECTOR. Every value below was PRODUCED BY THE CONTRACTS, in
// proof-of-facilitation/test/TLDRegistry.test.ts, "test vector for the Go
// registrar client": TLDRegistry and AxonRegistry (deployed with the mainnet
// AxonRegistry's immutables) computed the hashes, and the commit / approve /
// register calldata below was sent RAW from the owner's wallet and registered
// the name. That test asserts the same constants, so a change on either side
// fails one of the two.
//
// The name is built from name.RootSuffix rather than spelled out, per T8.3. The
// vector is tied to TLDRegistry's compile-time ROOT_SUFFIX, so if RootSuffix
// changes these tests fail -- correctly: the contract would have to change too.
var (
	vName = "alice.lab." + name.RootSuffix

	vOwner     = MustAddress("0xbD7aaE000C9212685b5361bda4Bcb1e655E744B3")
	vToken     = MustAddress("0xf18CE4D86a3e46537b7A48B335d1F195F00010b2")
	vRegistrar = MustAddress("0x7D870D21A6fc01Cde5168b4b4874cfe78779413d")

	vSecret    = h32("e43074e2436e8b6878c49b6c6284b7226b7196a3fa1c2c04090aaae46f47e0fd")
	vDomainKey = h32("196ac4be5b2a1715d869d41b6bbd00656db4adc71a4340980f0ddc88d5e742dc")
	vCharter   = h32("6764716f3fd790044888adb27f32b1ddbcb94d3f558f4a5a7974105e53d96b26")

	vLabelHash  = h32("4305b11146ee91a5c46324d0d0911ab1fd5275c19fedf8d14c2f2af4b3cc68f4")
	vNameHash   = h32("a11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6")
	vSkeleton   = h32("73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f")
	vCommitment = h32("e8899313c26f10d88f8aea6f139677ec4aee27a2530990fc2728f9c1ee5a4bfd")

	vApprove = mustBig("150000000000000000000")

	vNsCall = hx("7c8fab2c" +
		"4305b11146ee91a5c46324d0d0911ab1fd5275c19fedf8d14c2f2af4b3cc68f4")
	vNsRet = hx("" +
		"0000000000000000000000007d870d21a6fc01cde5168b4b4874cfe78779413d" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000002" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"00000000000000000000000000000000000000000000000000000000ee7d9d00" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"6764716f3fd790044888adb27f32b1ddbcb94d3f558f4a5a7974105e53d96b26" +
		"0000000000000000000000000000000000000000000000000000000000000000")
	vCommitData = hx("f14fcbc8" +
		"e8899313c26f10d88f8aea6f139677ec4aee27a2530990fc2728f9c1ee5a4bfd")
	vApproveData = hx("095ea7b3" +
		"0000000000000000000000007d870d21a6fc01cde5168b4b4874cfe78779413d" +
		"00000000000000000000000000000000000000000000000821ab0d4414980000")
	vRegisterData = hx("2245eb1c" +
		"a11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6" +
		"73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f" +
		"0000000000000000000000000000000000000000000000000000000000000005" +
		"e43074e2436e8b6878c49b6c6284b7226b7196a3fa1c2c04090aaae46f47e0fd" +
		"196ac4be5b2a1715d869d41b6bbd00656db4adc71a4340980f0ddc88d5e742dc")
	vNameCall = hx("e532a034" +
		"a11de4e35ea4c76cbcf6d85a6c86f84520bf08e925add96f72d7111aedfb49d6")
	vNameRet = hx("" +
		"000000000000000000000000bd7aae000c9212685b5361bda4bcb1e655e744b3" +
		"00000000000000000000000000000000000000000000000000000000f0602278" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"196ac4be5b2a1715d869d41b6bbd00656db4adc71a4340980f0ddc88d5e742dc" +
		"0000000000000000000000000000000000000000000000000000000000000000" +
		"73b30c5c06a3a9d1befc1225711e37b0e4288d93d840e920595cb1d3c11c4a7f" +
		"00000000000000000000000000000000000000000000000000000000ee7eeef8" +
		"00000000000000000000000000000000000000000000000000000000ee7eeef8" +
		"00000000000000000000000000000000000000000000000000000000ee7eeef8" +
		"0000000000000000000000000000000000000000000000056bc75e2d63100000" +
		"0000000000000000000000000000000000000000000000000000000000000000")

	// The vector's pinned block times: namespace activated at t0+14d, name
	// registered at t0+15d+120s, t0 = 4_000_000_000.
	vActivatedAt  = uint64(4_001_209_600)
	vRegisteredAt = uint64(4_001_296_120)
)

func hx(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func h32(s string) (out [32]byte) {
	copy(out[:], hx(s))
	return out
}

func mustBig(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(s)
	}
	return v
}

// vectorNamespace is what the vector's TLDRegistry.namespaceOf returned.
func vectorNamespace(t *testing.T) Namespace {
	t.Helper()
	ns, err := DecodeNamespace(vNsRet)
	if err != nil {
		t.Fatal(err)
	}
	return ns
}

func vectorPlanner(t *testing.T, lookup NamespaceLookup) *Planner {
	t.Helper()
	if lookup == nil {
		ns := vectorNamespace(t)
		lookup = func(h [32]byte) (Namespace, error) {
			if h == vLabelHash {
				return ns, nil
			}
			return Namespace{}, nil // NONE
		}
	}
	return &Planner{
		ChainID:    contracts.ChainID,
		Token:      vToken,
		Lookup:     lookup,
		Registrars: map[Address]RegistrarParams{vRegistrar: MainnetAxonRegistry},
		Rand:       bytes.NewReader(vSecret[:]),
		Now:        func() time.Time { return time.Unix(int64(vRegisteredAt), 0) },
	}
}

// ---------------------------------------------------------------- selectors

// Frozen from the compiled ABI (hardhat artifacts, solc 0.8.24).
func TestSelectorsMatchTheCompiledContracts(t *testing.T) {
	for _, tc := range []struct {
		name string
		got  []byte
		want string
	}{
		{"TLDRegistry.namespaceOf", selNamespaceOf, "7c8fab2c"},
		{"AxonRegistry.commit", selCommit, "f14fcbc8"},
		{"AxonRegistry.register", selRegister, "2245eb1c"},
		{"AxonRegistry.nameOf", selNameOf, "e532a034"},
		{"ERC20.approve", selApprove, "095ea7b3"},
	} {
		if hex.EncodeToString(tc.got) != tc.want {
			t.Errorf("%s selector %x, want %s", tc.name, tc.got, tc.want)
		}
	}
}

// ---------------------------------------------------------------- the vector

func TestVectorHashesMatchTheContracts(t *testing.T) {
	c, err := ClaimOf(vName)
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != vName || c.Label != "alice" || c.Namespace != "lab" || c.LabelLen != 5 {
		t.Fatalf("claim %+v", c)
	}
	if c.NamespaceHash != vLabelHash {
		t.Errorf("namespace hash %x, contract %x", c.NamespaceHash, vLabelHash)
	}
	if c.NameHash != vNameHash {
		t.Errorf("nameHash %x, contract (TLDRegistry.nameHashOf) %x", c.NameHash, vNameHash)
	}
	if c.Skeleton != vSkeleton {
		t.Errorf("skeleton %x, vector %x", c.Skeleton, vSkeleton)
	}
	if got := Commitment(c.NameHash, vOwner, vSecret, vDomainKey); got != vCommitment {
		t.Errorf("commitment %x, the one AxonRegistry accepted %x", got, vCommitment)
	}
	// The namehash chain through NamespaceNode agrees with name.NameHash: the
	// `tldNode` a registrar is deployed with is the parent of its names.
	nn := NamespaceNode("lab")
	lab := LabelHash("alice")
	if keccak(nn[:], lab[:]) != vNameHash {
		t.Errorf("keccak(NamespaceNode ‖ labelHash) disagrees with nameHash")
	}
	// Different namespaces, different names (§11.3.2's corrected formula).
	other, err := ClaimOf("alice.corp." + name.RootSuffix)
	if err != nil {
		t.Fatal(err)
	}
	if other.NameHash == c.NameHash {
		t.Error("alice.lab and alice.corp share a nameHash")
	}
}

func TestVectorCalldataMatchesWhatTheContractsAccepted(t *testing.T) {
	c, err := ClaimOf(vName)
	if err != nil {
		t.Fatal(err)
	}
	approve, err := ApproveCalldata(vRegistrar, vApprove)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		got, want []byte
	}{
		{"namespaceOf", NamespaceOfCalldata(vLabelHash), vNsCall},
		{"commit", CommitCalldata(vCommitment), vCommitData},
		{"approve", approve, vApproveData},
		{"register", RegisterCalldata(c, vSecret, vDomainKey), vRegisterData},
		{"nameOf", NameOfCalldata(vNameHash), vNameCall},
	} {
		if !bytes.Equal(tc.got, tc.want) {
			t.Errorf("%s calldata\n got %x\nwant %x", tc.name, tc.got, tc.want)
		}
	}
}

func TestVectorDecodesNamespaceOf(t *testing.T) {
	ns := vectorNamespace(t)
	want := Namespace{
		Registrar:      vRegistrar,
		RegistrarClass: ClassImmutable,
		Status:         StatusActive,
		RecordSchema:   1,
		ActivatedAt:    vActivatedAt,
		Charter:        vCharter,
		Bond:           big.NewInt(0),
	}
	if ns.Bond == nil || ns.Bond.Cmp(want.Bond) != 0 {
		t.Fatalf("bond %v", ns.Bond)
	}
	ns.Bond, want.Bond = nil, nil
	if ns != want {
		t.Errorf("namespaceOf decoded\n got %+v\nwant %+v", ns, want)
	}
}

func TestVectorDecodesNameOf(t *testing.T) {
	n, err := DecodeName(vNameRet)
	if err != nil {
		t.Fatal(err)
	}
	year := uint64(365 * 24 * 3600)
	if n.Owner != vOwner || n.Version != 1 || n.DomainKey != vDomainKey ||
		n.Skeleton != vSkeleton || n.Resolver != ([32]byte{}) || n.Flags != 0 {
		t.Errorf("nameOf decoded %+v", n)
	}
	if n.RegisteredAt != vRegisteredAt || n.AcquiredAt != vRegisteredAt ||
		n.KeyValidFrom != vRegisteredAt || n.ExpiresAt != vRegisteredAt+year {
		t.Errorf("nameOf times %+v", n)
	}
	if n.Bond.Cmp(MainnetAxonRegistry.BondPerName) != 0 {
		t.Errorf("bond %v, want %v", n.Bond, MainnetAxonRegistry.BondPerName)
	}
}

// ---------------------------------------------------------------- the plan

func TestPlanIsTheVectorsTransactionsInOrder(t *testing.T) {
	plan, err := vectorPlanner(t, nil).Plan(vName, vOwner, vDomainKey)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Secret != vSecret || plan.Commitment != vCommitment {
		t.Fatalf("secret/commitment %x %x", plan.Secret, plan.Commitment)
	}
	if plan.Approve.Cmp(vApprove) != 0 {
		t.Errorf("approve %v, want %v", plan.Approve, vApprove)
	}
	want := []struct {
		step string
		to   Address
		data []byte
		wait time.Duration
	}{
		{"commit", vRegistrar, vCommitData, 60 * time.Second},
		{"approve", vToken, vApproveData, 0},
		{"register", vRegistrar, vRegisterData, 0},
	}
	if len(plan.Steps) != len(want) {
		t.Fatalf("%d steps", len(plan.Steps))
	}
	for i, w := range want {
		s := plan.Steps[i]
		if s.Step != w.step || s.To != w.to || s.From != vOwner || !bytes.Equal(s.Data, w.data) ||
			s.WaitAfter != w.wait || s.Value == nil || s.Value.Sign() != 0 {
			t.Errorf("step %d = %+v\nwant %s to %s data %x wait %s", i, s, w.step, w.to.Hex(), w.data, w.wait)
		}
	}
	if plan.RegistrarClass != ClassImmutable || plan.ChainID != 1 {
		t.Errorf("class %s chain %d", plan.RegistrarClass, plan.ChainID)
	}
}

func TestPlanGeneratesAFreshSecretByDefault(t *testing.T) {
	p := vectorPlanner(t, nil)
	p.Rand = nil // crypto/rand
	a, err := p.Plan(vName, vOwner, vDomainKey)
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Plan(vName, vOwner, vDomainKey)
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret == b.Secret || a.Commitment == b.Commitment {
		t.Error("two plans share a secret")
	}
	if a.Secret == ([32]byte{}) {
		t.Error("zero secret")
	}
}

func TestPlanRefuses(t *testing.T) {
	base := vectorNamespace(t)
	with := func(mut func(*Namespace)) NamespaceLookup {
		ns := base
		mut(&ns)
		return func([32]byte) (Namespace, error) { return ns, nil }
	}
	now := vRegisteredAt
	for _, tc := range []struct {
		name   string
		lookup NamespaceLookup
		input  string
		owner  Address
		key    [32]byte
		want   error
	}{
		{"no namespace", with(func(n *Namespace) { *n = Namespace{} }), vName, vOwner, vDomainKey, ErrNoNamespace},
		{"proposed only", with(func(n *Namespace) { n.Status = StatusProposed }), vName, vOwner, vDomainKey, ErrNoNamespace},
		{"frozen", with(func(n *Namespace) { n.Status, n.FrozenAt = StatusFrozen, now-10 }), vName, vOwner, vDomainKey, ErrNamespaceFrozen},
		{"retiring", with(func(n *Namespace) { n.Status, n.RetiresAt = StatusRetiring, now+1000 }), vName, vOwner, vDomainKey, ErrNamespaceRetiring},
		{"retired by time", with(func(n *Namespace) { n.Status, n.RetiresAt = StatusRetiring, now-1 }), vName, vOwner, vDomainKey, ErrNamespaceRetiring},
		{"retired", with(func(n *Namespace) { n.Status = StatusRetired }), vName, vOwner, vDomainKey, ErrNamespaceRetiring},
		{"unknown registrar", with(func(n *Namespace) { n.Registrar = vToken }), vName, vOwner, vDomainKey, ErrUnknownRegistrar},
		{"zero owner", nil, vName, Address{}, vDomainKey, ErrZeroOwner},
		{"zero domain key", nil, vName, vOwner, [32]byte{}, ErrZeroDomainKey},
		{"subordinate name", nil, "www." + vName, vOwner, vDomainKey, ErrNotRegistrable},
		{"not ours", nil, "alice.lab.com", vOwner, vDomainKey, name.ErrNotRoot},
		{"reserved namespace", nil, "alice.key." + name.RootSuffix, vOwner, vDomainKey, name.ErrReserved},
		{"too short", nil, "al.lab." + name.RootSuffix, vOwner, vDomainKey, name.ErrGrammar},
	} {
		_, err := vectorPlanner(t, tc.lookup).Plan(tc.input, tc.owner, tc.key)
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
	p := vectorPlanner(t, nil)
	p.Lookup = nil
	if _, err := p.Plan(vName, vOwner, vDomainKey); !errors.Is(err, ErrNoLookup) {
		t.Errorf("nil lookup: %v", err)
	}
}

func TestPlanWarnsAboutClassAndBurst(t *testing.T) {
	ns := vectorNamespace(t)
	ns.RegistrarClass, ns.Steward = ClassStewarded, vToken
	p := vectorPlanner(t, func([32]byte) (Namespace, error) { return ns, nil })
	p.TakenThisEpoch = 3 // this is the 4th: one over BURST_FREE
	plan, err := p.Plan(vName, vOwner, vDomainKey)
	if err != nil {
		t.Fatal(err)
	}
	// 5 chars = 5x base, burst overage 1 -> x(1*1+1) = 100 tokens, + 100 bond.
	want := mustBig("200000000000000000000")
	if plan.Approve.Cmp(want) != 0 {
		t.Errorf("approve %v, want %v", plan.Approve, want)
	}
	all := strings.Join(plan.Warnings, "\n")
	for _, w := range []string{"STEWARDED", "burst surcharge", "NOT anonymous"} {
		if !strings.Contains(all, w) {
			t.Errorf("no %q warning in %q", w, all)
		}
	}
}

// AxonRegistry.priceOf + burstSurcharge, restated from the Solidity.
func TestPriceMirrorsTheContract(t *testing.T) {
	base := MainnetAxonRegistry.BasePrice
	mul := func(m int64) *big.Int { return new(big.Int).Mul(base, big.NewInt(m)) }
	for _, tc := range []struct {
		label string
		nth   uint16
		want  *big.Int
	}{
		{"abc", 1, mul(100)},
		{"abcd", 1, mul(20)},
		{"alice", 1, mul(5)},
		{"abcdef", 1, mul(1)},
		{"a-very-long-label", 3, mul(1)},
		{"abcdef", 4, mul(2)}, // over 1: 1*1+1
		{"abcdef", 5, mul(5)}, // over 2: 2*2+1
		{"abc", 6, mul(1000)}, // 100 * (3*3+1)
	} {
		if got := MainnetAxonRegistry.Price(tc.label, tc.nth); got.Cmp(tc.want) != 0 {
			t.Errorf("Price(%q, %d) = %v, want %v", tc.label, tc.nth, got, tc.want)
		}
	}
	noEpoch := MainnetAxonRegistry
	noEpoch.Epoch = 0
	if got := noEpoch.Price("abcdef", 9); got.Cmp(mul(1)) != 0 {
		t.Errorf("EPOCH=0 must disable the surcharge, got %v", got)
	}
}

// ---------------------------------------------------------------- decoders

func TestDecodersAreStrict(t *testing.T) {
	if _, err := DecodeNamespace(vNsRet[:len(vNsRet)-1]); !errors.Is(err, ErrBadReturn) {
		t.Errorf("short namespace: %v", err)
	}
	if _, err := DecodeName(append(append([]byte{}, vNameRet...), make([]byte, 32)...)); !errors.Is(err, ErrBadReturn) {
		t.Errorf("long name: %v", err)
	}
	for _, tc := range []struct {
		name string
		word int
		at   int
		val  byte
	}{
		{"dirty registrar word", 0, 0, 1},
		{"class out of range", 1, 31, 3},
		{"status out of range", 2, 31, 6},
		{"wide recordSchema", 3, 29, 1},
		{"wide activatedAt", 4, 23, 1},
		{"dirty steward word", 7, 11, 1},
	} {
		b := append([]byte{}, vNsRet...)
		b[32*tc.word+tc.at] = tc.val
		if _, err := DecodeNamespace(b); !errors.Is(err, ErrBadReturn) {
			t.Errorf("%s: %v", tc.name, err)
		}
	}
	b := append([]byte{}, vNameRet...)
	b[32*2+27] = 1 // version is uint32: byte 27 is above it
	if _, err := DecodeName(b); !errors.Is(err, ErrBadReturn) {
		t.Errorf("wide version: %v", err)
	}
}

func TestEffectiveStatus(t *testing.T) {
	ns := Namespace{Status: StatusRetiring, RetiresAt: 100}
	if ns.EffectiveStatus(99) != StatusRetiring || ns.EffectiveStatus(100) != StatusRetired {
		t.Error("RETIRING must read as RETIRED from retiresAt on")
	}
	for s := StatusNone; s <= StatusRetired; s++ {
		if strings.HasPrefix(s.String(), "NsStatus(") {
			t.Errorf("status %d has no name", s)
		}
	}
	for c := ClassImmutable; c <= ClassStewarded; c++ {
		if strings.HasPrefix(c.String(), "RegClass(") {
			t.Errorf("class %d has no name", c)
		}
	}
}

// ---------------------------------------------------------------- JSON

func TestPlanJSON(t *testing.T) {
	plan, err := vectorPlanner(t, nil).Plan(vName, vOwner, vDomainKey)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := plan.JSON()
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		ChainID   int64  `json:"chainId"`
		Name      string `json:"name"`
		Owner     string `json:"owner"`
		Registrar string `json:"registrar"`
		Approve   string `json:"approve"`
		NameHash  string `json:"nameHash"`
		Secret    string `json:"secret"`
		Steps     []struct {
			Step             string `json:"step"`
			From, To, Data   string
			Value            string `json:"value"`
			WaitAfterSeconds int64  `json:"waitAfterSeconds"`
		} `json:"steps"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%v\n%s", err, raw)
	}
	if got.ChainID != 1 || got.Name != vName || got.Owner != vOwner.Hex() ||
		got.Registrar != vRegistrar.Hex() || got.Approve != vApprove.String() ||
		got.NameHash != "0x"+hex.EncodeToString(vNameHash[:]) ||
		got.Secret != "0x"+hex.EncodeToString(vSecret[:]) {
		t.Errorf("plan JSON header wrong:\n%s", raw)
	}
	// Addresses print as EIP-55, the form a wallet expects to be pasted.
	if got.Owner != "0xbD7aaE000C9212685b5361bda4Bcb1e655E744B3" {
		t.Errorf("owner %s is not the checksummed form", got.Owner)
	}
	wantData := [][]byte{vCommitData, vApproveData, vRegisterData}
	if len(got.Steps) != 3 {
		t.Fatalf("%d steps", len(got.Steps))
	}
	for i, s := range got.Steps {
		if s.Data != "0x"+hex.EncodeToString(wantData[i]) || s.Value != "0" || s.From != vOwner.Hex() {
			t.Errorf("step %d: %+v", i, s)
		}
	}
	if got.Steps[0].WaitAfterSeconds != 60 {
		t.Errorf("commit wait %d", got.Steps[0].WaitAfterSeconds)
	}
	// Amounts are decimal STRINGS: 1.5e20 is not representable in a float64
	// JSON number without loss.
	if !strings.Contains(string(raw), `"approve": "150000000000000000000"`) {
		t.Errorf("approve is not a decimal string:\n%s", raw)
	}
}

// ---------------------------------------------------------------- addresses

func TestAddressChecksum(t *testing.T) {
	for _, c := range contracts.Mainnet.All() {
		a, err := ParseAddress(c.Address)
		if err != nil {
			t.Errorf("%s: %v", c.Name, err)
			continue
		}
		if c.Address != strings.ToLower(c.Address) && a.Hex() != c.Address {
			t.Errorf("%s: round trip %s != %s", c.Name, a.Hex(), c.Address)
		}
	}
	good := vOwner.Hex()
	bad := strings.Replace(good, "bD7", "Bd7", 1)
	if _, err := ParseAddress(bad); !errors.Is(err, ErrBadAddress) {
		t.Errorf("wrong checksum accepted: %v", err)
	}
	if _, err := ParseAddress(strings.ToLower(good)); err != nil {
		t.Errorf("lowercase refused: %v", err)
	}
	if _, err := ParseAddress("0x1234"); !errors.Is(err, ErrBadAddress) {
		t.Errorf("short accepted: %v", err)
	}
}

// ---------------------------------------------------------------- scope

// The package comment's promise -- it builds bytes, it neither dials nor signs
// -- held by what the package imports. A future change that reaches for an RPC
// client or a private key fails here and has to argue with the comment.
func TestPackageNeitherDialsNorSigns(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"net", "net/http", "net/rpc", "crypto/ecdsa", "crypto/ed25519",
		"github.com/decred/dcrd/dcrec/secp256k1/v4",
		"github.com/syndichan/maniwani/storage-client/internal/channel"}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range af.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range forbidden {
				if path == bad {
					t.Errorf("%s imports %s", f, path)
				}
			}
		}
	}
}
