package channel

// The recipient's own pool view over HTTP — roadmap P15 phase 5.
//
// WHOSE VIEW THIS IS
// ------------------
// The recipient's, and only the recipient's. It runs on the node THEY operate,
// behind the same bearer token as every other /v1 route, over loopback. That is
// what makes it safe to be detailed: a person is being shown their own money,
// computed from states they already hold.
//
// The website is not in this path and never sees the answer. If it did, the
// platform would learn every recipient's balance, contributor count and channel
// set — the exact metadata chokepoint P15 exists to avoid — and it would learn
// it without ever holding a coin, which is the failure mode that looks safe.
//
//	recipient's browser ──► recipient's node ──► Pool.View()
//	                                 (never through the website)
//
// STILL NOT A LEDGER
// ------------------
// Nothing here is stored. Every response is recomputed from co-signed states by
// Pool.View, so this endpoint cannot report a number that the signatures do not
// support. There is no field to corrupt and no cache to invalidate.

import (
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strings"
)

// PoolName is what a node calls the single pool it aggregates over.
//
// One pool per node, deliberately. Multiple pools would have to partition the
// channel set (a channel's value can be checkpointed once, so two views listing
// it would both count it — see CheckDisjoint), and nothing in the node knows how
// a recipient would want them split. A recipient who wants several runs several
// nodes, and disjointness is then physical rather than a rule to enforce.
const PoolName = "tips"

// PoolOf builds the recipient's pool over every channel this node holds.
//
// Membership is "channels I am a party to", which is the only definition the
// node can compute without being told a policy. Channels the recipient is not
// party to cannot appear: they are not in this store.
func (c *Coordinator) PoolOf(policy PoolPolicy) Pool {
	return Pool{
		Name:      PoolName,
		Recipient: c.self,
		Members:   c.store.IDs(),
		Policy:    policy,
	}
}

// poolSummary is the recipient's private view. Amounts are strings for the same
// reason the channel summary uses them: a uint256 does not survive JSON's float.
type poolSummary struct {
	Pool string `json:"pool"`
	// Withdrawable is the sum the recipient could checkpoint out right now.
	Withdrawable string `json:"withdrawable"`
	// InFlight is committed to live locks. Shown so it is not mistaken for
	// missing money, never added to the withdrawable total.
	InFlight     string `json:"in_flight"`
	Members      int    `json:"members"`
	Contributors int    `json:"contributors"`

	// Excluded says why a channel did not count. A view that silently dropped
	// them would under-report, and the recipient would read the difference as a
	// payment that vanished.
	Excluded []poolExclusion `json:"excluded"`

	// Candidates are the channels worth checkpointing under the policy. Each
	// still needs its counterparty's signature — this authorises nothing.
	Candidates []poolCandidate `json:"candidates"`
}

type poolExclusion struct {
	Channel string `json:"channel"`
	Reason  string `json:"reason"`
}

type poolCandidate struct {
	Channel string `json:"channel"`
	Amount  string `json:"amount"`
	// LocksLive is true when HTLCs are still pending. checkpoint() tolerates
	// them (it conserves them in its balance check) where closeCooperative
	// refuses any non-zero root, so this is informational, not a blocker.
	LocksLive bool `json:"locks_live"`
}

// pool answers GET /v1/pool.
func (a *API) pool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "GET only"})
		return
	}

	// Enabled here because reaching this route IS the recipient asking. The
	// off-by-default switch that matters is the one on the website profile,
	// which decides whether anyone is ever offered a tip button; refusing to
	// compute a view for the operator of the node would only hide their own
	// money from them.
	pool := a.coord.PoolOf(PoolPolicy{Enabled: true})

	view, err := pool.View(a.coord.store)
	if errors.Is(err, ErrPoolEmpty) {
		// No channels yet is an ordinary state for a new recipient, not an
		// error. Answering 404 would make "nobody has tipped you" look broken.
		writeJSON(w, http.StatusOK, poolSummary{
			Pool: PoolName, Withdrawable: "0", InFlight: "0",
			Excluded: []poolExclusion{}, Candidates: []poolCandidate{},
		})
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}

	out := poolSummary{
		Pool:         view.Pool,
		Withdrawable: decString(view.Withdrawable),
		InFlight:     decString(view.InFlight),
		Members:      view.Members,
		Contributors: view.Contributors,
		Excluded:     []poolExclusion{},
		Candidates:   []poolCandidate{},
	}
	for _, ex := range view.Excluded {
		out.Excluded = append(out.Excluded, poolExclusion{
			Channel: poolChannelHex(ex.Channel), Reason: ex.Reason,
		})
	}

	// The plan is computed from the same store in the same request, so the
	// candidate list cannot describe a channel set the aggregate above did not.
	plan, err := pool.CheckpointPlan(a.coord.store)
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, cand := range plan {
		out.Candidates = append(out.Candidates, poolCandidate{
			Channel:   poolChannelHex(cand.Channel),
			Amount:    decString(cand.Amount),
			LocksLive: cand.LocksLive,
		})
	}

	writeJSON(w, http.StatusOK, out)
}

// checkpointRequest is what the recipient's dashboard sends.
//
// It NAMES a channel and may state an amount. It does not describe the channel's
// state, and nothing in it is trusted as financial authority — the node reads
// the co-signed state from its own Store and validates the request against it.
// There is deliberately no nonce, no balance, no signature and no party field:
// every one of those is knowable from the Store, and accepting them would let a
// request assert something the signatures do not support.
type checkpointRequest struct {
	Channel string `json:"channel"`
	// Amount is optional and decimal. Omitted means "everything eligible",
	// which is what the Withdraw button asks for.
	Amount string `json:"amount,omitempty"`
}

type checkpointResponse struct {
	Outcome string `json:"outcome"`
	Amount  string `json:"amount"`
	Nonce   uint64 `json:"nonce"`
	TxHash  string `json:"tx_hash,omitempty"`
}

// poolCheckpoint answers POST /v1/pool/checkpoint — withdraw pooled value from
// one bilateral channel.
//
// ONE CHANNEL PER CALL, because a checkpoint is bilateral: the contract takes a
// single channel id and both parties' signatures. A batching endpoint would be
// a lie about what the chain does, and the honest cost of non-custodial pooling
// is N transactions. The dashboard loops; the protocol does not.
func (a *API) poolCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST only"})
		return
	}

	var req checkpointRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "malformed request"})
		return
	}

	id, err := parseBytes32(req.Channel)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad channel id"})
		return
	}

	var requested *big.Int
	if strings.TrimSpace(req.Amount) != "" {
		parsed, ok := new(big.Int).SetString(strings.TrimSpace(req.Amount), 10)
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "amount must be a decimal integer"})
			return
		}
		requested = parsed
	}

	// Eligibility is decided BEFORE the peer is contacted, from the Store. A
	// channel this node is not party to, or holds nothing in, never reaches the
	// network — so a probe cannot use the endpoint to discover who it can talk
	// to.
	if _, err := a.coord.CheckpointEligible(id); err != nil {
		writeErr(w, err)
		return
	}

	ch, ok := a.coord.store.Get(id)
	if !ok {
		writeErr(w, ErrNoSuchChannel)
		return
	}
	counterparty := ch.PartyB
	if ch.PartyB == a.coord.self {
		counterparty = ch.PartyA
	}
	var peer Peer
	if a.peers != nil {
		peer, err = a.peers(id, counterparty)
		if err != nil {
			// Could not even work out how to reach the contributor. Nothing was
			// sent, so this is the offline case, not an indeterminate one.
			eligible, eligErr := a.coord.CheckpointEligible(id)
			if eligErr != nil {
				writeErr(w, eligErr)
				return
			}
			writeJSON(w, http.StatusServiceUnavailable, checkpointResponse{
				Outcome: string(CheckpointContributorOffline),
				Amount:  decString(eligible),
			})
			return
		}
	}

	result, err := a.coord.Checkpoint(r.Context(), id, requested, peer)
	if err != nil {
		if result.Outcome == CheckpointContributorOffline {
			// 503, not 4xx: the request was valid and the money is there. The
			// amount is included so the dashboard can name it.
			writeJSON(w, http.StatusServiceUnavailable, checkpointResponse{
				Outcome: string(CheckpointContributorOffline),
				Amount:  decString(result.Amount),
			})
			return
		}
		if result.Outcome == CheckpointUnknown {
			// NOT AN ERROR THE CALLER MAY RETRY. The contributor may have
			// signed. 409 rather than 5xx so the dashboard can tell this apart
			// from a refusal and show its own UNKNOWN state.
			writeJSON(w, http.StatusConflict, checkpointResponse{
				Outcome: string(CheckpointUnknown), Amount: "0",
			})
			return
		}
		writeErr(w, err)
		return
	}

	out := checkpointResponse{
		Outcome: string(result.Outcome),
		Amount:  decString(result.Amount),
		Nonce:   result.Nonce,
	}

	// Broadcasting is separate and may be absent: a node with no chain writer
	// can still co-sign, and saying so is better than pretending the value has
	// been paid out.
	if a.payout == nil {
		writeJSON(w, http.StatusOK, out)
		return
	}

	txHash, err := a.payout.BroadcastCheckpoint(r.Context(), id)
	if err != nil {
		// SIGNED BUT NOT SENT. The state is safe and re-sendable; reporting a
		// failure here would invite a second withdrawal against a state that
		// already took the value out.
		out.Outcome = string(CheckpointUnknown)
		writeJSON(w, http.StatusConflict, out)
		return
	}
	out.Outcome = string(CheckpointBroadcast)
	out.TxHash = txHash
	writeJSON(w, http.StatusOK, out)
}

// hexID renders a channel id for the recipient's own view.
//
// Safe HERE and nowhere else: this response goes to the person who is a party
// to these channels and already holds their signed states. The same string in a
// website response, a metric or a log would be the identifier P15 forbids
// recording.
func poolChannelHex(id [32]byte) string {
	const digits = "0123456789abcdef"
	var b strings.Builder
	b.Grow(64)
	for _, c := range id {
		b.WriteByte(digits[c>>4])
		b.WriteByte(digits[c&0x0f])
	}
	return b.String()
}
