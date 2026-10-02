package registrar

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/rabbiit/maniwani/storage-client/internal/axon/registry"
)

var (
	ErrNoLookup          = errors.New("axon/registrar: no namespace lookup configured")
	ErrNoNamespace       = errors.New("axon/registrar: namespace does not exist on the root (NXNAMESPACE)")
	ErrNamespaceFrozen   = errors.New("axon/registrar: namespace is FROZEN; new registrations are blocked")
	ErrNamespaceRetiring = errors.New("axon/registrar: namespace is retiring or retired")
	ErrUnknownRegistrar  = errors.New("axon/registrar: no known parameters for this namespace's registrar")
	ErrZeroOwner         = errors.New("axon/registrar: owner is the zero address")
	ErrZeroDomainKey     = errors.New("axon/registrar: domain key is zero, which every resolver reads as 'does not resolve'")
)

// RegistrarParams are the immutables of one AxonRegistry deployment that a
// registration plan depends on.
type RegistrarParams struct {
	BasePrice    *big.Int      // BASE_PRICE, token base units
	BondPerName  *big.Int      // BOND_PER_NAME, locked at registration
	BurstFree    uint16        // BURST_FREE
	Epoch        time.Duration // EPOCH; 0 disables the burst surcharge
	CommitMinAge time.Duration // COMMIT_MIN_AGE
	CommitMaxAge time.Duration // COMMIT_MAX_AGE; 0 = unbounded
}

// MainnetAxonRegistry are the immutables of the mainnet AxonRegistry
// (contracts.Mainnet.AxonRegistry), read by eth_call on 2026-09-30.
//
// Safe to hold as constants for one reason: they are Solidity IMMUTABLES, part
// of the deployed code, and cannot change at that address. They are keyed by
// address in Planner.Registrars so they are never applied to a different
// registrar that merely speaks the same ABI.
//
// NOTE, recorded where a caller will see it: the mainnet AxonToken supply was 0
// on the same date (mintGenesis not yet sent), so every registration plan for
// this registrar is currently unpayable -- register() pulls price + bond in
// the token.
var MainnetAxonRegistry = RegistrarParams{
	BasePrice:    new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18)),
	BondPerName:  new(big.Int).Mul(big.NewInt(100), big.NewInt(1e18)),
	BurstFree:    3,
	Epoch:        7 * 24 * time.Hour,
	CommitMinAge: 60 * time.Second,
	CommitMaxAge: 24 * time.Hour,
}

// Price mirrors AxonRegistry.priceOf(labelLen) followed by
// burstSurcharge(price, nth), where nth counts this registration (so the first
// name an account takes in an epoch is nth = 1). The arithmetic is
// registry.Policy's, so the model and the client cannot drift apart.
func (p RegistrarParams) Price(label string, nthThisEpoch uint16) *big.Int {
	pol := registry.Policy{
		BasePrice:        p.BasePrice,
		LengthMultiplier: map[int]int64{3: 100, 4: 20, 5: 5},
		EpochBurstFree:   int(p.BurstFree),
	}
	price := pol.PriceOf(label)
	if p.Epoch == 0 {
		return price
	}
	return pol.BurstSurcharge(price, int(nthThisEpoch))
}

// NamespaceLookup answers TLDRegistry.namespaceOf for a namespace label hash.
// The caller implements it -- an eth_call with NamespaceOfCalldata and
// DecodeNamespace, ideally verified against a proven state root (§12.5) --
// because this package does no I/O.
//
// The registrar a plan sends to COMES FROM HERE, never from configuration
// (10-resolver.md R3a): a hardcoded registrar address is a hardcoded namespace
// set, which §11.3 calls non-conformant.
type NamespaceLookup func(namespaceHash [32]byte) (Namespace, error)

// Tx is one unsigned transaction.
type Tx struct {
	// Step names it: "commit", "approve" or "register".
	Step string
	// From is the account that MUST send it. For all three steps this is the
	// owner: AxonRegistry binds the commitment to msg.sender and pulls the
	// token from msg.sender.
	From Address
	To   Address
	Data []byte
	// Value is wei. Always zero: AxonRegistry is paid in the token (§12.4a).
	Value *big.Int
	// WaitAfter: once this transaction is MINED, wait at least this long
	// (measured against block time) before sending the next. Zero means "send
	// the next once this one is mined".
	WaitAfter time.Duration
	Note      string
}

// Plan is a complete, unsigned registration of one name.
type Plan struct {
	ChainID   int64
	Claim     Claim
	Owner     Address
	DomainKey [32]byte
	// Secret is embedded in the register step's calldata. Until that step is
	// mined it is the one thing an observer of the commitment lacks to learn
	// which name is being taken; treat the plan as private until then.
	Secret         [32]byte
	Commitment     [32]byte
	Registrar      Address
	RegistrarClass RegClass
	Token          Address
	Price, Bond    *big.Int
	Approve        *big.Int // Price + Bond
	CommitMaxAge   time.Duration
	Warnings       []string
	Steps          []Tx
}

// Planner builds Plans. It holds the chain context; it holds no key.
type Planner struct {
	// ChainID the transactions are for (contracts.ChainID for mainnet). Carried
	// so a printed plan says which chain it belongs to.
	ChainID int64
	// Token is the network token register() pulls price + bond in
	// (contracts.Mainnet.AxonToken).
	Token Address
	// Lookup resolves the namespace binding. Required.
	Lookup NamespaceLookup
	// Registrars maps a registrar address to its immutables. A namespace whose
	// registrar is not listed is REFUSED: the plan speaks AxonRegistry's ABI
	// and prices with its parameters, and both are only known to be right for
	// a registrar somebody has actually read.
	Registrars map[Address]RegistrarParams
	// TakenThisEpoch is AxonRegistry.epochTakes(owner, now / EPOCH) as read
	// from the chain: names this owner has already registered this epoch. If
	// it is understated the approval is too small and register() reverts --
	// no tokens move, only gas is lost.
	TakenThisEpoch uint16
	// Rand supplies the secret. nil means crypto/rand.
	Rand io.Reader
	// Now is block-ish time, for the RETIRING rule. nil means time.Now.
	Now func() time.Time
}

// Plan describes commit -> wait COMMIT_MIN_AGE -> approve -> register for
// `input` (e.g. "alice.lab.axon"), owned by `owner`, with DomainIdentity
// `domainKey` (an Ed25519 public key, verbatim). It signs nothing and sends
// nothing.
func (p *Planner) Plan(input string, owner Address, domainKey [32]byte) (*Plan, error) {
	if p.Lookup == nil {
		return nil, ErrNoLookup
	}
	if owner.IsZero() {
		return nil, ErrZeroOwner
	}
	if domainKey == ([32]byte{}) {
		return nil, ErrZeroDomainKey
	}
	c, err := ClaimOf(input)
	if err != nil {
		return nil, err
	}

	ns, err := p.Lookup(c.NamespaceHash)
	if err != nil {
		return nil, fmt.Errorf("axon/registrar: namespace %q: %w", c.Namespace, err)
	}
	now := time.Now
	if p.Now != nil {
		now = p.Now
	}
	switch st := ns.EffectiveStatus(uint64(now().Unix())); st {
	case StatusActive:
	case StatusNone, StatusProposed:
		// PROPOSED does not resolve (TLDRegistry's NsStatus note).
		return nil, fmt.Errorf("%w: %q is %s", ErrNoNamespace, c.Namespace, st)
	case StatusFrozen:
		// The registrar may still ACCEPT the transaction -- the root never
		// touches it -- but a resolver will refuse a name registered after
		// frozenAt. Paying for a name that will not resolve is refused here.
		return nil, fmt.Errorf("%w: %q frozen at %d", ErrNamespaceFrozen, c.Namespace, ns.FrozenAt)
	default:
		return nil, fmt.Errorf("%w: %q is %s (retiresAt %d)", ErrNamespaceRetiring,
			c.Namespace, st, ns.RetiresAt)
	}
	if ns.Registrar.IsZero() {
		return nil, fmt.Errorf("%w: %q has no registrar", ErrNoNamespace, c.Namespace)
	}
	params, ok := p.Registrars[ns.Registrar]
	if !ok {
		return nil, fmt.Errorf("%w: %s serves %q", ErrUnknownRegistrar, ns.Registrar.Hex(), c.Namespace)
	}

	var secret [32]byte
	rnd := p.Rand
	if rnd == nil {
		rnd = rand.Reader
	}
	if _, err := io.ReadFull(rnd, secret[:]); err != nil {
		return nil, fmt.Errorf("axon/registrar: secret: %w", err)
	}

	nth := p.TakenThisEpoch + 1
	price := params.Price(c.Label, nth)
	bond := new(big.Int).Set(params.BondPerName)
	approve := new(big.Int).Add(price, bond)
	approveData, err := ApproveCalldata(ns.Registrar, approve)
	if err != nil {
		return nil, err
	}
	commitment := Commitment(c.NameHash, owner, secret, domainKey)

	plan := &Plan{
		ChainID:        p.ChainID,
		Claim:          c,
		Owner:          owner,
		DomainKey:      domainKey,
		Secret:         secret,
		Commitment:     commitment,
		Registrar:      ns.Registrar,
		RegistrarClass: ns.RegistrarClass,
		Token:          p.Token,
		Price:          price,
		Bond:           bond,
		Approve:        approve,
		CommitMaxAge:   params.CommitMaxAge,
	}

	// §13.3a: show the registrar class at registration time.
	switch ns.RegistrarClass {
	case ClassUpgradeable:
		plan.Warnings = append(plan.Warnings, "registrar class UPGRADEABLE: its upgrade key can rewrite the rules under existing holders (§12.0)")
	case ClassStewarded:
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("registrar class STEWARDED: steward %s holds powers over names in %q, per its charter (§12.0)", ns.Steward.Hex(), c.Namespace))
	}
	if params.Epoch != 0 && nth > params.BurstFree {
		plan.Warnings = append(plan.Warnings, fmt.Sprintf("name %d this epoch: the price includes the burst surcharge (§12.4a)", nth))
	}
	// §12.3 and R6, stated on every plan because it is routinely assumed away.
	plan.Warnings = append(plan.Warnings, "ownership is NOT anonymous: the sending account becomes the owner on chain and is linkable through its funding history (§12.3, R6); use an account with no other history")

	plan.Steps = []Tx{
		{
			Step: "commit", From: owner, To: ns.Registrar, Value: new(big.Int),
			Data:      CommitCalldata(commitment),
			WaitAfter: params.CommitMinAge,
			Note: fmt.Sprintf("Publishes only a hash: no label, no key. Wait at least %s after this is mined "+
				"(block time) before step 3, and get step 3 mined within %s of it or the commitment expires.",
				params.CommitMinAge, params.CommitMaxAge),
		},
		{
			Step: "approve", From: owner, To: p.Token, Value: new(big.Int),
			Data: approveData,
			Note: fmt.Sprintf("Lets the registrar pull exactly price %s + bond %s. The bond stays locked in the registrar until release.",
				price, bond),
		},
		{
			Step: "register", From: owner, To: ns.Registrar, Value: new(big.Int),
			Data: RegisterCalldata(c, secret, domainKey),
			Note: "Reveals the label and the secret and registers " + c.Name + " to the sender.",
		},
	}
	return plan, nil
}

// ---------------------------------------------------------------- JSON

func hex0x(b []byte) string { return "0x" + hex.EncodeToString(b) }

type txJSON struct {
	Step             string `json:"step"`
	From             string `json:"from"`
	To               string `json:"to"`
	Data             string `json:"data"`
	Value            string `json:"value"`
	WaitAfterSeconds int64  `json:"waitAfterSeconds"`
	Note             string `json:"note"`
}

type planJSON struct {
	ChainID             int64    `json:"chainId"`
	Name                string   `json:"name"`
	Namespace           string   `json:"namespace"`
	NamespaceHash       string   `json:"namespaceHash"`
	NameHash            string   `json:"nameHash"`
	Skeleton            string   `json:"skeleton"`
	LabelLength         uint8    `json:"labelLength"`
	Owner               string   `json:"owner"`
	DomainKey           string   `json:"domainKey"`
	Registrar           string   `json:"registrar"`
	RegistrarClass      string   `json:"registrarClass"`
	Token               string   `json:"token"`
	Price               string   `json:"price"`
	Bond                string   `json:"bond"`
	Approve             string   `json:"approve"`
	Commitment          string   `json:"commitment"`
	Secret              string   `json:"secret"`
	SecretWarning       string   `json:"secretWarning"`
	CommitMaxAgeSeconds int64    `json:"commitMaxAgeSeconds"`
	Warnings            []string `json:"warnings"`
	Steps               []txJSON `json:"steps"`
}

// MarshalJSON renders the plan for a CLI or wallet: hex for bytes and
// addresses (EIP-55), decimal strings for token amounts (they exceed 2^53, and
// a JSON number would be silently rounded by half the readers of it).
func (p *Plan) MarshalJSON() ([]byte, error) {
	out := planJSON{
		ChainID:             p.ChainID,
		Name:                p.Claim.Name,
		Namespace:           p.Claim.Namespace,
		NamespaceHash:       hex0x(p.Claim.NamespaceHash[:]),
		NameHash:            hex0x(p.Claim.NameHash[:]),
		Skeleton:            hex0x(p.Claim.Skeleton[:]),
		LabelLength:         p.Claim.LabelLen,
		Owner:               p.Owner.Hex(),
		DomainKey:           hex0x(p.DomainKey[:]),
		Registrar:           p.Registrar.Hex(),
		RegistrarClass:      p.RegistrarClass.String(),
		Token:               p.Token.Hex(),
		Price:               p.Price.String(),
		Bond:                p.Bond.String(),
		Approve:             p.Approve.String(),
		Commitment:          hex0x(p.Commitment[:]),
		Secret:              hex0x(p.Secret[:]),
		SecretWarning:       "the secret is in step 3's calldata; keep this plan private until step 3 is mined",
		CommitMaxAgeSeconds: int64(p.CommitMaxAge / time.Second),
		Warnings:            p.Warnings,
	}
	for _, t := range p.Steps {
		v := "0"
		if t.Value != nil {
			v = t.Value.String()
		}
		out.Steps = append(out.Steps, txJSON{
			Step: t.Step, From: t.From.Hex(), To: t.To.Hex(), Data: hex0x(t.Data), Value: v,
			WaitAfterSeconds: int64(t.WaitAfter / time.Second), Note: t.Note,
		})
	}
	return json.Marshal(out)
}

// JSON is MarshalJSON, indented for a terminal.
func (p *Plan) JSON() ([]byte, error) {
	b, err := p.MarshalJSON()
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
