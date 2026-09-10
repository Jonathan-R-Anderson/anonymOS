package channel

// Linking a service receipt to a private payment, without publishing either.
//
// THE CONFLICT THIS RESOLVES
// --------------------------
// A ServiceReceipt is PUBLICLY REPLICATED — it travels the DHT so anyone can
// verify infrastructure work happened. A private payment is the opposite. Tying
// them together naively publishes the payment.
//
// The earlier proposal was to put the ChannelID in the receipt so an auditor
// could detect double-settlement. That is wrong once privacy is on: a raw
// channel id in a public record names both participants and links every payment
// through that channel — undoing the routing layer in a single field.
//
// SCOPED PSEUDONYMS
// -----------------
// Instead the receipt carries H(channel ‖ epoch ‖ domain), which rotates every
// epoch. Double-settlement stays detectable WITHIN an epoch — the window that
// actually matters, since that is the settlement period — and nothing
// correlates across epochs.
//
// The asymmetry is deliberate: an auditor gets exactly the power they need for
// the job (catch a receipt settled twice this epoch) and none of the power they
// do not (follow a channel through time).
//
// WHAT AN OBSERVER CAN AND CANNOT DO
// ----------------------------------
//	can    see that some channel settled some receipt this epoch
//	can    detect the same receipt settled twice in one epoch
//	cannot tell which channel, or link it to last epoch's pseudonym
//	cannot tell the amount, the payer, or the provider's counterparties

import (
	"errors"
	"sync"
)

const (
	domainSettlePseudonym = "syndichan/settle/pseudonym/v1"
	domainSettleCommit    = "syndichan/settle/commitment/v1"
)

// SettlementMode says how a receipt was paid, so a verifier knows which rules
// apply rather than guessing from which fields are populated.
type SettlementMode uint8

const (
	SettleEpoch          SettlementMode = iota // the existing PoF path, unchanged
	SettleChannel                              // a channel, no privacy
	SettlePrivateChannel                       // a channel, privately routed
)

var (
	ErrDoubleSettled = errors.New("settle: receipt already settled this epoch")
	ErrWrongEpoch    = errors.New("settle: pseudonym is from a different epoch")
	ErrCommitmentBad = errors.New("settle: payment commitment does not open")
)

// ReceiptLink is what a public receipt carries about its payment. Three fields,
// none of which names anything.
type ReceiptLink struct {
	// PaymentCommitment binds the receipt to a specific payment. The payer and
	// the provider can open it; nobody else can tell which payment it is, or
	// whether two receipts refer to the same one.
	PaymentCommitment [32]byte
	// SettlementPseudonym is H(channel ‖ epoch ‖ domain). Rotates per epoch.
	SettlementPseudonym [32]byte
	Mode                SettlementMode
	PrivacyVersion      uint16
}

// PseudonymFor derives a channel's pseudonym for one epoch.
//
// Takes the epoch explicitly rather than reading a clock: two parties must
// derive the same value, and a pseudonym that depended on when it was computed
// would differ between them at an epoch boundary.
func PseudonymFor(ch ChannelID, epoch uint64) [32]byte {
	return derive(domainSettlePseudonym, []byte(ch), uint64Bytes(epoch))
}

// CommitPayment binds a receipt to a payment.
//
// Includes a per-payment nonce, so two identical payments for identical work do
// NOT produce the same commitment. Without it, a provider paid the same amount
// twice would emit two identical commitments and an observer could count how
// often a given job recurs.
func CommitPayment(ch ChannelID, nonce uint64, amount Amount, secret [32]byte) [32]byte {
	return derive(domainSettleCommit,
		[]byte(ch), uint64Bytes(nonce), amountBytes(amount), secret[:])
}

// OpenPayment checks a commitment against known values.
//
// Only the payer and the provider hold `secret`, so only they can do this. An
// auditor holding the receipt cannot — which is the point.
func OpenPayment(link ReceiptLink, ch ChannelID, nonce uint64, amount Amount, secret [32]byte) error {
	if CommitPayment(ch, nonce, amount, secret) != link.PaymentCommitment {
		return ErrCommitmentBad
	}
	return nil
}

// NewReceiptLink builds the link a receipt should carry.
func NewReceiptLink(ch ChannelID, epoch, nonce uint64, amount Amount,
	secret [32]byte, mode SettlementMode) ReceiptLink {
	return ReceiptLink{
		PaymentCommitment:   CommitPayment(ch, nonce, amount, secret),
		SettlementPseudonym: PseudonymFor(ch, epoch),
		Mode:                mode,
		PrivacyVersion:      1,
	}
}

// SettlementAudit detects double-settlement within one epoch.
//
// Scoped to a single epoch on purpose. An auditor that carried state across
// epochs could link pseudonyms and rebuild exactly the channel history the
// rotation exists to break — so the audit is deliberately forgetful, and its
// forgetfulness is a feature rather than a limitation to work around.
type SettlementAudit struct {
	epoch uint64
	mu    sync.Mutex
	seen  map[[32]byte]bool // payment commitments settled this epoch
}

func NewSettlementAudit(epoch uint64) *SettlementAudit {
	return &SettlementAudit{epoch: epoch, seen: map[[32]byte]bool{}}
}

// Record accepts a receipt's link, refusing a repeat.
func (a *SettlementAudit) Record(link ReceiptLink, ch ChannelID) error {
	// The pseudonym must match this epoch, or a receipt from another epoch is
	// being replayed into this one's accounting.
	if link.SettlementPseudonym != PseudonymFor(ch, a.epoch) {
		return ErrWrongEpoch
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seen[link.PaymentCommitment] {
		return ErrDoubleSettled
	}
	a.seen[link.PaymentCommitment] = true
	return nil
}

// Settled reports how many payments this epoch recorded. A count, never a list:
// returning the commitments would hand a caller the correlation set.
func (a *SettlementAudit) Settled() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.seen)
}

// Linkable reports whether two links can be shown to involve the same channel.
//
// Exists to be TESTED against, not called in production. It answers "would an
// observer be able to correlate these?", and the answer must be false across
// epochs — which is the property the whole scheme rests on.
func Linkable(a, b ReceiptLink) bool {
	return a.SettlementPseudonym == b.SettlementPseudonym
}
