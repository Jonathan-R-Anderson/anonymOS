package channel

// Asking a volunteer whether anything is waiting — roadmap P15.5.
//
// WHY THIS IS A NODE CAPABILITY AND NOT A BROWSER ONE
// ----------------------------------------------------
// Only the recipient can authorise a read of the recipient's mailbox, and the
// recipient's channel key lives in their node — that is the entire point of
// mailbox mode, which exists so somebody can be tipped while their browser is
// closed. A page cannot produce this proof without holding that key, and a page
// holding that key would be a page with custody.
//
// The alternative that was NOT taken was a wallet-signed peek from the browser:
// it would work, and it would train recipients to approve signature prompts for
// a read, on a page whose only job is to display a number. The node already has
// the authority; it should use it.
//
// WHAT IT DELIBERATELY CANNOT DO
// ------------------------------
// Discovery only. It reads, and reading is all it can do:
//
//   - it calls /mailbox/v1/peek, never /collect, so the proposal survives
//     the read and is still there when the recipient decides;
//   - it never accepts, countersigns, or commits — acceptance stays where it
//     was, on the recipient's own explicit action through Store.Accept;
//   - it returns frames verbatim and parses no payments.
//
// The signature it produces covers a mailbox challenge, which is not a channel
// state digest and cannot be replayed as one: state digests are domain-tagged
// with an operation byte and computed over the channel, and this is neither.

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// MailboxDiscovery asks volunteers what is waiting for this node's operator.
//
// It holds the recipient's authority explicitly rather than reaching into the
// coordinator for it, so what this can sign is visible at the construction site.
type MailboxDiscovery struct {
	// Self is the recipient this node speaks for — the only address whose
	// mailbox it can read.
	Self Address
	// Sign covers mailbox challenges. It is the node's channel key.
	Sign StateSigner
	// HTTP is the client used for volunteer calls. Nil means a defaulted one.
	HTTP *http.Client

	// nonce keeps two nearly simultaneous reads from building the same
	// challenge, so a captured proof cannot answer a later request.
	nonce atomic.Uint64
}

// NewMailboxDiscovery builds the reader, refusing to exist without an authority.
//
// A discovery client with no signer would compile, return "nothing waiting" for
// every recipient, and look exactly like an empty mailbox.
func NewMailboxDiscovery(self Address, sign StateSigner) (*MailboxDiscovery, error) {
	if sign == nil {
		return nil, fmt.Errorf("mailbox discovery: no signing authority")
	}
	var zero Address
	if self == zero {
		return nil, fmt.Errorf("mailbox discovery: no recipient address")
	}
	return &MailboxDiscovery{Self: self, Sign: sign}, nil
}

// Waiting returns the frames a volunteer is holding for this node, WITHOUT
// consuming them.
//
// An error here means "not known", never "nothing waiting". The distinction is
// the point: a recipient shown an empty inbox because their authorization
// lapsed would conclude nobody had tipped them.
func (d *MailboxDiscovery) Waiting(ctx context.Context, endpoint, nodeID string) ([]Envelope, error) {
	if d == nil {
		return nil, fmt.Errorf("mailbox discovery: not configured")
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil, fmt.Errorf("mailbox discovery: no volunteer endpoint")
	}

	// A per-call token, so the challenge — and therefore the proof — differs
	// between reads.
	token := fmt.Sprintf("peek-%d-%d", time.Now().UnixNano(), d.nonce.Add(1))
	challenge := MailboxChallenge(nodeID, d.Self, token)

	// PersonalDigest here because the mailbox recovers through PersonalDigest.
	// Signing the bare challenge recovers a stranger, and the volunteer would
	// refuse with a message about the wrong party — a failure that reads as a
	// permission problem and is really an encoding one.
	sig, err := d.Sign(PersonalDigest(challenge))
	if err != nil {
		return nil, fmt.Errorf("mailbox discovery: could not sign: %w", err)
	}

	body, _ := json.Marshal(map[string]string{
		"recipient": d.Self.Hex(),
		"token":     token,
		"sig":       "0x" + hex.EncodeToString(sig),
	})
	url := strings.TrimRight(endpoint, "/") + "/mailbox/v1/peek"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("mailbox discovery: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mailbox discovery: %w", err)
	}
	defer resp.Body.Close()

	var out struct {
		Frames []Envelope `json:"frames"`
		Error  string     `json:"error"`
	}
	// Decoded before the status is judged so the volunteer's own reason
	// survives. Defaulting a 403 body to an empty frame list is precisely how
	// a refusal becomes an empty inbox.
	dec := json.NewDecoder(resp.Body)
	decErr := dec.Decode(&out)

	if resp.StatusCode != http.StatusOK {
		if out.Error != "" {
			return nil, fmt.Errorf("mailbox discovery: volunteer refused: %s", out.Error)
		}
		return nil, fmt.Errorf("mailbox discovery: volunteer returned %d", resp.StatusCode)
	}
	if decErr != nil {
		return nil, fmt.Errorf("mailbox discovery: unreadable answer: %w", decErr)
	}
	return out.Frames, nil
}

// PublishAccepted caches a co-signed state at the volunteer so the contributor
// can find it.
//
// DISCOVERY ONLY. Nothing here moves value: the acceptance already happened in
// Store.Accept, and this makes the result findable by the person who sent it.
// A failure is therefore not a failed payment, and the caller must report
// "accepted but unpublished" rather than rolling anything back.
func (d *MailboxDiscovery) PublishAccepted(ctx context.Context, endpoint, nodeID,
	channel string, env Envelope) error {

	if d == nil {
		return fmt.Errorf("mailbox discovery: not configured")
	}
	token := fmt.Sprintf("publish-%d-%d", time.Now().UnixNano(), d.nonce.Add(1))
	sig, err := d.Sign(PersonalDigest(MailboxChallenge(nodeID, d.Self, token)))
	if err != nil {
		return fmt.Errorf("mailbox discovery: could not sign: %w", err)
	}
	body, _ := json.Marshal(map[string]any{
		"recipient": d.Self.Hex(), "channel": channel, "token": token,
		"sig": "0x" + hex.EncodeToString(sig), "envelope": env,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(endpoint, "/")+"/mailbox/v1/accepted", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := d.HTTP
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("mailbox discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		var out struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if out.Error != "" {
			return fmt.Errorf("mailbox discovery: volunteer refused: %s", out.Error)
		}
		return fmt.Errorf("mailbox discovery: volunteer returned %d", resp.StatusCode)
	}
	return nil
}
