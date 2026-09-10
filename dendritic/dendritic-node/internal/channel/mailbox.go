package channel

// The volunteer mailbox — roadmap P15.
//
// WHAT PROBLEM THIS SOLVES
// -----------------------
// A bilateral payment needs the recipient's signature at the moment it happens.
// That is why receiving a tip has, until now, meant running a node: something
// holding your key had to be reachable. Most people will never run a node, so
// most people could never be tipped.
//
// A mailbox is the smallest thing that fixes it without anybody becoming a
// custodian. A volunteer accepts frames addressed to a recipient and holds them
// until that recipient's own browser collects them, signs with their own wallet,
// and hands the replies back.
//
//	contributor ──frame──► volunteer mailbox ──held──► recipient's browser
//	                              ▲                          │ signs with
//	                              └──────reply───────────────┘ their own key
//
// WHY IT CANNOT STEAL
// -------------------
// It has no key. Not "it is not supposed to sign" — there is no field on this
// struct that could hold a signer, and a test asserts that by reflection. A
// mailbox that could sign would be a delegate, and delegation is a separate,
// explicit, on-chain thing (see delegate.go).
//
// It also holds no value: every frame it carries is a message between two other
// parties, and the contract pays neither of them on its say-so.
//
// WHAT IT NECESSARILY LEARNS
// --------------------------
// Who is talking to whom, and how often. A frame names a channel and a channel
// names both parties, so a mailbox serving many recipients sees the shape of
// their tipping. That is real and is NOT fixed by anything here; it is what
// onion-wrapping the terminal hop would address, and that is a later phase.
// Saying so plainly is better than implying a privacy this does not provide.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
)

var (
	// ErrNotServed means this volunteer holds no live authorization for that
	// recipient. Refused rather than served-anyway: a mailbox that accepted
	// frames for anybody would let a stranger fill its disk, and would let a
	// contributor believe a tip was delivered somewhere it will never be read.
	ErrNotServed = errors.New("mailbox: this node does not serve that recipient")
	// ErrAuthorizationExpired means the recipient's authorization has lapsed.
	ErrAuthorizationExpired = errors.New("mailbox: the authorization has expired")
	// ErrAuthorizationInvalid means the signature does not belong to the
	// recipient it names.
	ErrAuthorizationInvalid = errors.New("mailbox: the authorization is not signed by that recipient")
	// ErrWrongNode means the authorization names a different volunteer. A node
	// that ignored this could serve a recipient who chose somebody else, and two
	// mailboxes for one recipient is how two states get signed at one nonce.
	ErrWrongNode = errors.New("mailbox: the authorization names another node")
	// ErrMailboxFull means the queue for that recipient is at its cap.
	ErrMailboxFull = errors.New("mailbox: too many undelivered frames for that recipient")
)

// MailboxAuthorizationPrefix is what a recipient signs to appoint a volunteer.
//
// Versioned, and it includes the NODE and the EXPIRY as well as the recipient,
// for the reason PofRegistration.proof_message gives: a proof that did not name
// what it was authorising could be replayed to point the same consent somewhere
// else. This one cannot be lifted onto another volunteer or another window.
const MailboxAuthorizationPrefix = "syndichan-mailbox:v1"

// MailboxAuthorization is a recipient's signed statement that a volunteer may
// hold their mail.
//
// NOT AN AUTHORITY TO SIGN. It authorises storage and forwarding, nothing more.
// The on-chain delegation is the only thing that grants signing, deliberately
// kept separate so that appointing a mailbox can never be mistaken for — or
// silently upgraded into — appointing a delegate.
type MailboxAuthorization struct {
	Recipient Address
	// NodeID identifies the volunteer this consent is for.
	NodeID string
	// Endpoint is where the recipient told contributors to reach that node.
	Endpoint string
	// Expires is a unix time. Authorizations expire so that an abandoned one
	// stops being usable without the recipient having to come back and say so.
	Expires int64
	// Sig is the recipient's EIP-191 signature over Message().
	Sig []byte
}

// Message is the exact text signed. Built from the fields rather than supplied,
// so a caller cannot present one statement and store another.
func (a MailboxAuthorization) Message() string {
	return fmt.Sprintf("%s\nrecipient=%s\nnode=%s\nendpoint=%s\nexpires=%d",
		MailboxAuthorizationPrefix, strings.ToLower(a.Recipient.Hex()),
		a.NodeID, a.Endpoint, a.Expires)
}

// Verify checks that the recipient really signed this, for this node, in time.
func (a MailboxAuthorization) Verify(nodeID string, now int64) error {
	if a.NodeID == "" || a.NodeID != nodeID {
		return ErrWrongNode
	}
	if a.Expires <= now {
		return ErrAuthorizationExpired
	}
	signer, err := RecoverSigner(PersonalDigest(keccak32([]byte(a.Message()))), a.Sig)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAuthorizationInvalid, err)
	}
	if signer != a.Recipient {
		return ErrAuthorizationInvalid
	}
	return nil
}

// keccak32 hashes the authorization text to the 32 bytes the wallet signs.
func keccak32(b []byte) [32]byte {
	var out [32]byte
	copy(out[:], keccak(b))
	return out
}

// DefaultMailboxDepth bounds undelivered frames per recipient.
//
// A cap rather than a promise of unlimited storage: a volunteer is donating
// disk, and a recipient who never collects should cost it a bounded amount.
// Sized so that an ordinary recipient collecting daily never approaches it.
const DefaultMailboxDepth = 512

// Mailbox holds frames for recipients that authorized this node.
//
// NOTE WHAT IS ABSENT: no signer, no key, no store of channel state, no
// balances. It is a queue with an access rule.
type Mailbox struct {
	// NodeID is this volunteer's identity, and authorizations must name it.
	NodeID string
	// Depth caps undelivered frames per recipient. Zero means the default.
	Depth int
	// Now is injectable so expiry is testable without sleeping.
	Now func() int64

	mu    sync.Mutex
	auth  map[Address]MailboxAuthorization
	queue map[Address][]Envelope
	// retained is indexed by CHANNEL, not by recipient, and outlives
	// collection: a contributor rebuilding its chain needs these after the
	// recipient has emptied their queue.
	retained map[string][]Envelope
}

// NewMailbox builds one. It takes no key, and there is nowhere to put one.
func NewMailbox(nodeID string, now func() int64) *Mailbox {
	return &Mailbox{
		NodeID: nodeID, Now: now,
		auth:     make(map[Address]MailboxAuthorization),
		queue:    make(map[Address][]Envelope),
		retained: make(map[string][]Envelope),
	}
}

func (m *Mailbox) depth() int {
	if m.Depth > 0 {
		return m.Depth
	}
	return DefaultMailboxDepth
}

func (m *Mailbox) now() int64 {
	if m.Now != nil {
		return m.Now()
	}
	return 0
}

// Serve records a recipient's authorization for this node.
//
// Verified before it is stored, so an unverified authorization never exists in
// memory to be trusted later by something that forgot to check.
func (m *Mailbox) Serve(a MailboxAuthorization) error {
	if err := a.Verify(m.NodeID, m.now()); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// ONE AUTHORIZATION PER RECIPIENT on this node. Replacing rather than
	// appending: two live authorizations would be two answers to "am I allowed
	// to hold this", and the later one is the recipient's current intent.
	m.auth[a.Recipient] = a
	return nil
}

// Stop forgets a recipient, dropping anything still queued for them.
//
// The frames are proposals nobody has accepted, so nothing is lost that was
// ever money — but a recipient leaving should be told that undelivered mail
// goes with them, which is why this is explicit rather than a silent expiry.
func (m *Mailbox) Stop(recipient Address) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.auth, recipient)
	delete(m.queue, recipient)
}

// Serves reports whether this node currently holds a live authorization.
func (m *Mailbox) Serves(recipient Address) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auth[recipient]
	return ok && a.Expires > m.now()
}

// Recipients lists who this node serves. For the operator's own console.
func (m *Mailbox) Recipients() []Address {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Address, 0, len(m.auth))
	for who, a := range m.auth {
		if a.Expires > m.now() {
			out = append(out, who)
		}
	}
	return out
}

// Deliver queues a frame for a recipient.
//
// The frame is stored VERBATIM and never inspected. A mailbox that parsed
// payments would be a mailbox that could get them wrong, and everything
// transport.go says about staying dumb applies here word for word.
func (m *Mailbox) Deliver(recipient Address, env Envelope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auth[recipient]
	if !ok || a.Expires <= m.now() {
		return ErrNotServed
	}
	if len(m.queue[recipient]) >= m.depth() {
		return ErrMailboxFull
	}
	m.queue[recipient] = append(m.queue[recipient], env)
	// Retained under the same lock, so a frame is never queued-but-unretained.
	if env.Channel != "" {
		if m.retained == nil {
			m.retained = make(map[string][]Envelope)
		}
		if len(m.retained[env.Channel]) >= m.depth() {
			m.retained[env.Channel] = m.retained[env.Channel][1:]
		}
		m.retained[env.Channel] = append(m.retained[env.Channel], env)
	}
	return nil
}

// Collect hands a recipient their queued frames.
//
// THE ACCESS RULE. `proof` must be the recipient's own signature over a
// challenge naming them, so one recipient cannot read another's mail merely by
// asking for it. The queue is emptied only once the caller has proved who they
// are.
func (m *Mailbox) Collect(recipient Address, challenge [32]byte, proof []byte) ([]Envelope, error) {
	signer, err := RecoverSigner(PersonalDigest(challenge), proof)
	if err != nil {
		return nil, fmt.Errorf("mailbox: unreadable proof: %w", err)
	}
	if signer != recipient {
		// Deliberately the same refusal whether the recipient is unknown or the
		// proof is wrong: an attacker learns nothing about who this node serves.
		return nil, ErrNotServed
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auth[recipient]
	if !ok || a.Expires <= m.now() {
		return nil, ErrNotServed
	}
	out := m.queue[recipient]
	m.queue[recipient] = nil
	return out, nil
}

// Peek returns the recipient's waiting frames WITHOUT consuming them.
//
// WHY THIS EXISTS SEPARATELY FROM Collect
// ---------------------------------------
// A recipient's console has to show "a tip is waiting" before the recipient has
// decided anything. Collect is the only other recipient-authorized read and it
// EMPTIES THE QUEUE, so using it for discovery would destroy the proposal at
// page load — before it had been reviewed, let alone accepted.
//
// StatesFor cannot serve this either: it authorises the CONTRIBUTOR, deriving
// the channel from caller+recipient, and a recipient asking about their own
// mailbox derives nothing.
//
// So this is Collect's authorization with Collect's side effect removed. It is
// strictly the weaker of the two: same proof, same recipient, and it changes
// nothing. Collect remains the consuming path, and acceptance still goes
// through the recipient's own node.
func (m *Mailbox) Peek(recipient Address, challenge [32]byte, proof []byte) ([]Envelope, error) {
	signer, err := RecoverSigner(PersonalDigest(challenge), proof)
	if err != nil {
		return nil, fmt.Errorf("mailbox: unreadable proof: %w", err)
	}
	if signer != recipient {
		// Same refusal as an unknown recipient: asking teaches nothing about
		// who this node serves.
		return nil, ErrNotServed
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.auth[recipient]
	if !ok || a.Expires <= m.now() {
		return nil, ErrNotServed
	}
	// A COPY. Handing back the slice itself would let a caller's later append
	// reach into the queue this promised not to touch.
	out := make([]Envelope, len(m.queue[recipient]))
	copy(out, m.queue[recipient])
	return out, nil
}

// Pending reports how many frames are waiting, for the operator's console.
func (m *Mailbox) Pending(recipient Address) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.queue[recipient])
}

// MailboxChallenge is the value a recipient signs to collect their mail.
//
// Bound to the node and to a caller-supplied token so a signature collected on
// one volunteer cannot be replayed on another. The token comes from the node so
// that a stale one cannot be reused indefinitely.
func MailboxChallenge(nodeID string, recipient Address, token string) [32]byte {
	return keccak32([]byte("syndichan-mailbox-collect:v1\n" +
		nodeID + "\n" + strings.ToLower(recipient.Hex()) + "\n" + token))
}

// ParseAuthorizationSig decodes a hex signature from a request.
func ParseAuthorizationSig(s string) ([]byte, error) {
	raw, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "0x"))
	if err != nil {
		return nil, fmt.Errorf("mailbox: signature is not hex: %w", err)
	}
	if len(raw) != 65 {
		return nil, fmt.Errorf("mailbox: signature must be 65 bytes, got %d", len(raw))
	}
	return raw, nil
}

// ---- retained frames, so a contributor can rebuild its own chain -------------
//
// THE PROBLEM THIS SOLVES. A contributor tipping an offline recipient signs
// state N+1 and hands it to a mailbox. To tip again it needs N+1 to build N+2
// from — and N+1 exists nowhere else: the recipient never saw it, and it is
// off-chain by definition. The mailbox is already holding the exact frame.
//
// WHAT THE MAILBOX IS TRUSTED FOR HERE: NOTHING.
// It returns frames verbatim and picks no winner. Every returned frame carries
// the contributor's OWN signature, so a volunteer that forged or altered one
// produces something the contributor's own verification rejects. The worst a
// hostile volunteer can do is withhold, which stalls the next tip and steals
// nothing.
//
// Deliberately NOT "return the highest": that would make the volunteer choose
// which economic state matters, and choosing is the one thing it must not do.
// It returns candidates; the contributor verifies and selects.

// Retain keeps a copy of a frame indexed by its channel.
//
// Separate from the delivery queue on purpose. Collecting empties the
// recipient's queue — that is what collection means — but a contributor still
// needs its own chain afterwards, so retention outlives delivery.
func (m *Mailbox) Retain(channel string, env Envelope) {
	if channel == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.retained == nil {
		m.retained = make(map[string][]Envelope)
	}
	if len(m.retained[channel]) >= m.depth() {
		// Bounded like everything else here. Dropping the OLDEST is right: a
		// contributor rebuilding its chain needs the newest states, and the
		// older ones are subsumed by them anyway.
		m.retained[channel] = m.retained[channel][1:]
	}
	m.retained[channel] = append(m.retained[channel], env)
}

// StatesFor returns the frames retained for one channel, to a caller that
// proves it is a party to that channel.
//
// The access rule is DERIVED, not asserted: a channel id is
// keccak(sorted(partyA, partyB)), so given the caller's proven address and the
// recipient this node serves, the id can be recomputed. A caller asking about a
// channel that does not derive from those two addresses is not a party to it,
// and no lookup happens. That check is pure derivation — the mailbox still
// parses no economic state.
func (m *Mailbox) StatesFor(recipient, caller Address, channel string,
	challenge [32]byte, proof []byte) ([]Envelope, error) {

	signer, err := RecoverSigner(PersonalDigest(challenge), proof)
	if err != nil {
		return nil, fmt.Errorf("mailbox: unreadable proof: %w", err)
	}
	if signer != caller {
		return nil, ErrNotServed
	}
	want := DeriveChannelID(caller, recipient)
	if !strings.EqualFold(strings.TrimPrefix(channel, "0x"),
		hex.EncodeToString(want[:])) {
		// Not this caller's channel with this recipient. Same refusal as an
		// unknown recipient, so nothing is learned by asking.
		return nil, ErrNotServed
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if a, ok := m.auth[recipient]; !ok || a.Expires <= m.now() {
		return nil, ErrNotServed
	}
	out := make([]Envelope, len(m.retained[channel]))
	copy(out, m.retained[channel])
	return out, nil
}

// Retained reports how many frames are held for a channel. Operator console.
func (m *Mailbox) Retained(channel string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.retained[channel])
}

// PublishAccepted records a co-signed state the recipient has accepted.
//
// CASE A's MISSING HALF. A contributor that handed a proposal to a volunteer
// learns nothing more: the reply that would normally carry the countersignature
// does not exist, because the recipient was not there. So the recipient
// publishes the result, and the contributor reads it back through the same
// retained-frames path it already uses.
//
// The volunteer verifies NOTHING about the state and is trusted with nothing:
// the contributor re-derives the digest and checks both signatures before using
// it as a base. What is checked here is only that the publisher is the
// recipient this node serves, which bounds who may spend its disk.
//
// If this call fails, the recipient must NOT roll back what it accepted. The
// state is committed in its own store and is real; failing to cache it costs
// the contributor a discovery, not a payment.
func (m *Mailbox) PublishAccepted(recipient Address, channel string, env Envelope,
	challenge [32]byte, proof []byte) error {

	signer, err := RecoverSigner(PersonalDigest(challenge), proof)
	if err != nil {
		return fmt.Errorf("mailbox: unreadable proof: %w", err)
	}
	if signer != recipient {
		return ErrNotServed
	}
	m.mu.Lock()
	served := false
	if a, ok := m.auth[recipient]; ok && a.Expires > m.now() {
		served = true
	}
	m.mu.Unlock()
	if !served {
		return ErrNotServed
	}
	if channel == "" {
		return errors.New("mailbox: an accepted state must name its channel")
	}
	m.Retain(channel, env)
	return nil
}
