package main

import (
	"context"
	"crypto/ed25519"
	"log"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/facilitation"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/store"
)

// Wiring the node into Proof-of-Facilitation.
//
// Three jobs, all on one p2p protocol: answer challenges about what this node
// holds, witness other nodes' claims when drawn to, and issue the challenges
// this node is drawn to issue.
//
// The witness half is what makes a receipt evidence rather than a diary entry.
// A receipt signed only by its provider is that provider's own account of its
// own work; settlement wants signatures from the specific nodes the protocol
// drew for that claim, and it will reject anything else. So a provider collects
// them, and every node answers requests to give them — after checking, itself,
// that it was actually drawn and that the proof it is endorsing holds up.

type facilitationRuntime struct {
	agent     *facilitation.Agent
	scheduler *facilitation.Scheduler
	spool     *facilitation.ReceiptStore
	views     *facilitation.EpochViews
}

// startFacilitation installs the challenge responder. Returns nil (and logs
// why) whenever the node is not in a position to be audited, rather than
// failing startup: earning credits is optional, serving the network is not.
func startFacilitation(ctx context.Context, cfg config.Config, node *p2p.Node,
	storageNode *store.Store, logger *log.Logger) *facilitationRuntime {
	if node == nil || storageNode == nil {
		return nil
	}

	pub, priv, err := loadNodeSigningKey(node)
	if err != nil {
		logger.Printf("proof-of-facilitation disabled: %v", err)
		return nil
	}
	agent := facilitation.NewAgent(pub, priv)

	// The node id the network knows must be the one derived from the libp2p
	// identity, or receipts would be attributed to a node nobody can find.
	if derived, err := node.LocalNodeID(); err == nil && derived != agent.NodeID() {
		logger.Printf("proof-of-facilitation disabled: node id mismatch between p2p identity and signing key")
		return nil
	}

	spool, err := facilitation.OpenReceiptStore(filepath.Join(cfg.DataDir, "facilitation"))
	if err != nil {
		logger.Printf("proof-of-facilitation disabled: receipt spool unavailable: %v", err)
		return nil
	}

	send := func(ctx context.Context, target [32]byte, payload []byte) ([]byte, error) {
		peerID, ok := node.PeerForNodeID(target)
		if !ok {
			// Unreachable, NOT failed: the caller must not record an offline
			// peer as one that lost its data.
			return nil, facilitation.ErrPeerUnreachable
		}
		return node.SendChallenge(ctx, peerID, payload)
	}
	gateway := facilitation.NewGatewayClient(siteBaseURL(cfg))
	views := facilitation.NewEpochViews(gateway)

	scheduler := &facilitation.Scheduler{
		Agent:     agent,
		Store:     spool,
		Transport: facilitation.P2PTransport{Send: send},
	}
	// Collect attestations for every receipt this node earns. Installed as a
	// hook rather than called inline so the scheduler stays testable without a
	// network, and so a node that cannot reach the witness pool still spools
	// its receipts instead of losing the proof.
	scheduler.Attest = func(ctx context.Context, sr *facilitation.SignedReceipt,
		c facilitation.StorageChallenge, resp facilitation.StorageResponse,
		provenBytes uint64) error {
		view, err := views.For(ctx, sr.Receipt.Epoch)
		if err != nil {
			return err
		}
		got, err := collectErr(facilitation.CollectAttestations(
			ctx, sr, c, resp, provenBytes, view, send))
		if err != nil {
			return err
		}
		need := facilitation.ThresholdFor(sr.Receipt.ServiceType).Need
		if got < need {
			hash := sr.Hash()
			// Logged, not failed: the receipt is still spooled and witnesses
			// can still arrive. Silence here would hide the difference between
			// "not paid yet" and "will never be paid".
			logger.Printf("proof-of-facilitation: receipt %x has %d of the %d "+
				"attestations it needs", hash[:6], got, need)
		}
		return nil
	}

	node.SetChallengeHandler(facilitation.FacilitationResponder(
		scheduler, views, facilitation.StoreShardLoader(storageNode)))

	// Publish where earnings should go, and file for registration. Without a
	// payout address the node does the work and the credits have nowhere to
	// land, so it is announced loudly rather than left as a silent default.
	if cfg.PayoutAddress == "" {
		logger.Printf("proof-of-facilitation: NO PAYOUT ADDRESS SET — this node will earn nothing. " +
			"Set one with -payout 0x… or in the config file.")
	} else {
		declaration := facilitation.DeclarePayout(pub, priv, cfg.PayoutAddress, uint64(time.Now().Unix()))
		publishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		if err := gateway.PublishPayout(publishCtx, declaration); err != nil {
			// Not fatal: the node still serves and still earns receipts. The
			// declaration is retried next start, and until it lands the
			// aggregator falls back to the registry owner.
			logger.Printf("proof-of-facilitation: could not publish payout address (%v) — will retry next start", err)
		} else {
			logger.Printf("proof-of-facilitation: earnings will be paid to %s", cfg.PayoutAddress)
		}
		cancel()
		registerSelf(ctx, cfg, gateway, pub, priv, logger)
	}

	assignments, err := facilitation.LocalAssignments(agent.NodeID(), storageNode)
	if err != nil {
		logger.Printf("proof-of-facilitation: could not enumerate shards: %v", err)
	} else {
		nodeID := agent.NodeID()
		logger.Printf("proof-of-facilitation: answering audits for %d shard(s) as node %x",
			len(assignments), nodeID[:8])
	}
	// The registry binds this key to a wallet, and registering is what makes the
	// node eligible to be paid. It is printed in full because an operator may
	// have to paste it somewhere — deriving it from the peer id by hand means
	// base58-decoding a multihash and unwrapping a protobuf, which nobody
	// should have to do to get paid for their disk.
	logger.Printf("proof-of-facilitation: p2p public key %x", []byte(pub))
	// The epoch loop: advertise, audit whoever we were drawn to audit, upload
	// what we earned. Runs in the background so a slow relay never delays the
	// node serving data.
	go facilitation.RunEpochLoop(ctx, facilitation.EpochLoopConfig{
		Agent:     agent,
		Scheduler: scheduler,
		Store:     storageNode,
		Spool:     spool,
		Gateway:   gateway,
		Pub:       pub,
		Logger:    logger,
		Interval:  10 * time.Minute,
	})
	// The epoch number is not logged here: it is not knowable until the loop
	// has read the network's anchor, and printing a clock-derived guess would
	// put a number in the log that no other node agrees with.
	logger.Printf("proof-of-facilitation: epoch loop started")

	return &facilitationRuntime{agent: agent, scheduler: scheduler, spool: spool, views: views}
}

func (f *facilitationRuntime) Close() {
	if f == nil || f.spool == nil {
		return
	}
	_ = f.spool.Close()
}

// loadNodeSigningKey returns the ed25519 keypair backing the libp2p identity —
// the same key whose keccak256 is the node id, so a receipt's signature and the
// identity it claims cannot be separated.
func loadNodeSigningKey(node *p2p.Node) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return node.SigningKey()
}

// siteBaseURL derives the website root from the configured registration API, so
// there is one place to point a node at a different deployment rather than a
// second URL to keep in sync.
func siteBaseURL(cfg config.Config) string {
	raw := strings.TrimSpace(cfg.Gateway.RegistrationAPI)
	if raw == "" {
		return "https://syndichan.org"
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "https://syndichan.org"
	}
	return parsed.Scheme + "://" + parsed.Host
}

// nodeCapabilities is the bitmap this node files with the registry: what it
// actually offers, derived from the config rather than assumed.
//
// Witness is unconditional. Auditing a peer needs no stored data and no public
// port — it is a signature over a Merkle proof someone else produced — so every
// node can do it, and a network whose auditors must also be providers has an
// audit pool made entirely of people with a shared interest in lenient audits.
func nodeCapabilities(cfg config.Config) uint64 {
	caps := facilitation.CapDHT | facilitation.CapWitness
	if !cfg.CacheOnly {
		caps |= facilitation.CapStorage
	}
	if cfg.Gateway.Enabled {
		caps |= facilitation.CapGateway
	}
	if cfg.DCS.Enabled && cfg.DCS.Role.Worker {
		caps |= facilitation.CapDockerWorker
	}
	return caps
}

// registerSelf files this node's registration with the site.
//
// The node cannot put itself on-chain: NodeRegistry needs a transaction, which
// needs a wallet key, and a rented server holding one would give away exactly
// what the signed payout declaration exists to protect. So it files the half
// only it can produce — proof that this p2p key consented to this payout
// address — and the wallet owner turns that into a registry entry.
//
// Failure is logged, never fatal. An unregistered node still serves the network
// and still spools receipts; it just has no wallet on-chain for settlement to
// pay, and it retries on the next start.
func registerSelf(ctx context.Context, cfg config.Config, gateway *facilitation.GatewayClient,
	pub ed25519.PublicKey, priv ed25519.PrivateKey, logger *log.Logger) {
	caps := nodeCapabilities(cfg)
	req := facilitation.SelfRegistration(pub, priv, cfg.PayoutAddress, caps, uint64(time.Now().Unix()))

	registerCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	status, err := gateway.Register(registerCtx, req)
	if err != nil {
		logger.Printf("proof-of-facilitation: could not file registration (%v) — will retry next start", err)
		return
	}
	switch status {
	case "submitted":
		logger.Printf("proof-of-facilitation: registered on-chain (capabilities %d)", caps)
	default:
		// Only say this when it is true. Printing "go and register" beneath
		// "registered on-chain" trains an operator to ignore both.
		logger.Printf("proof-of-facilitation: registration filed (capabilities %d, status %q) — "+
			"until the wallet owner submits it at %s/admin/contracts, settlement has no "+
			"wallet to pay and rejects this node's receipts", caps, status, siteBaseURL(cfg))
	}
}

// collectErr keeps the attestation hook readable: CollectAttestations returns a
// count and an error together, and the count is meaningful even when the error
// is not nil.
func collectErr(n int, err error) (int, error) { return n, err }
