package main

// Mounting the payment stack — roadmap P15.
//
// WHAT THIS FIXES
// ---------------
// `internal/channel` has been complete and tested for several phases and was
// imported by exactly one non-test file in the tree: the dashboard adapter. No
// running node served SCPP/1, no running node served the operator API, and
// `Profile.channel_endpoint` was a field on the website that nobody could
// satisfy. The protocol worked; the product had nowhere to run.
//
// THE TWO SURFACES, AND WHY THEY ARE NOT THE SAME LISTENER
// --------------------------------------------------------
//	/scpp/v1   PUBLIC. How strangers pay this node's operator, and how a
//	           volunteer receives frames for the recipients it serves.
//	           Unauthenticated BY DESIGN — a tipper has no token and must never
//	           be given one — and authorised by the signature inside each
//	           message.
//
//	/v1/*      LOOPBACK. The operator's own API. It can move this node's money
//	           and change its payout policy. Config validation refuses to bind
//	           it anywhere but loopback, because a typo there would publish the
//	           ability to spend.
//
// Anything that blurs those two is the mistake this file exists to avoid.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/syndichan/maniwani/storage-client/internal/channel"
	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/ui"
)

// paymentStack is everything the node runs for channels, held together so
// shutdown has one thing to stop.
type paymentStack struct {
	coord    *channel.Coordinator
	payout   *channel.PayoutWorker
	mailbox  *channel.Mailbox
	// collector reads this node's own mailbox at a volunteer. Nil when no
	// volunteer is configured, and the console then says so rather than showing
	// an empty list.
	collector *ui.Collector
	delegate *channel.DelegateSigner
	peerSrv  *http.Server
	apiSrv   *http.Server
}

// startPaymentStack builds and serves the channel node, or returns nil when
// channels are switched off.
//
// Returns an error rather than logging and continuing: a node told to handle
// money that cannot do so should refuse to start, not run in a state where
// tips silently go nowhere.
func startPaymentStack(cfg config.Config, logger *log.Logger) (*paymentStack, error) {
	cc := cfg.Channels
	if !cc.Enabled {
		return nil, nil
	}
	if err := cc.Validate(); err != nil {
		return nil, err
	}

	key, err := loadChannelKey(cc.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("channel key: %w", err)
	}
	self := channel.PubkeyAddress(key.PubKey())

	manager, err := channel.ParseAddress(cc.Manager)
	if err != nil {
		return nil, fmt.Errorf("channels.manager: %w", err)
	}
	chainID := big.NewInt(cc.ChainID)

	store, err := channel.OpenStore(cfg.DataDir + "/channels")
	if err != nil {
		return nil, fmt.Errorf("channel store: %w", err)
	}
	reader := channel.NewRPCChainReader(cc.RPC)

	coord := channel.NewCoordinator(store, reader, chainID, manager, self,
		func(raw [32]byte) ([]byte, error) { return channel.SignDigest(key, raw) })

	stack := &paymentStack{coord: coord}

	// ---- collecting from a volunteer ---------------------------------------
	//
	// The endpoint comes from THIS FILE'S config, never from a request. A
	// caller who could name the volunteer could name their own and choose which
	// proposals this node is shown.
	if cc.Volunteer.Configured() {
		disc, err := channel.NewMailboxDiscovery(self,
			func(raw [32]byte) ([]byte, error) { return channel.SignDigest(key, raw) })
		if err != nil {
			return nil, fmt.Errorf("mailbox discovery: %w", err)
		}
		stack.collector = &ui.Collector{
			Discovery: disc, Endpoint: cc.Volunteer.Endpoint, NodeID: cc.Volunteer.NodeID,
		}
		logger.Printf("channels: collecting tips from volunteer %q at %s",
			cc.Volunteer.NodeID, cc.Volunteer.Endpoint)
	}

	// ---- the volunteer mailbox ---------------------------------------------
	if cc.Mailbox.Enabled {
		mb := channel.NewMailbox(cc.Mailbox.NodeID, func() int64 { return time.Now().Unix() })
		mb.Depth = cc.Mailbox.Depth
		stack.mailbox = mb
		logger.Printf("channels: serving as a volunteer mailbox, node id %q", cc.Mailbox.NodeID)
	}

	// ---- the delegate signer ------------------------------------------------
	if cc.Delegate.Enabled {
		dkey, err := loadChannelKey(cc.Delegate.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("delegate key: %w", err)
		}
		// A SEPARATE KEY from the channel key above, and neither is any
		// recipient's wallet. This one only ever signs OP_STATE for people who
		// authorized it on chain; it receives nothing, because every payout in
		// the contract goes to the channel party.
		ds, err := channel.NewDelegateSigner(
			channel.PubkeyAddress(dkey.PubKey()),
			func(raw [32]byte) ([]byte, error) { return channel.SignDigest(dkey, raw) },
			channel.RPCDelegateAuthority{Chain: reader}, manager)
		if err != nil {
			return nil, err
		}
		stack.delegate = ds
		logger.Printf("channels: delegate signer active as %s (OP_STATE only)",
			ds.Address.Hex())
	}

	// ---- the public peer surface -------------------------------------------
	if cc.PeerListen != "" {
		wp := &channel.WebPeer{Handler: coord, Timeout: 20 * time.Second}
		mux := http.NewServeMux()
		mux.Handle("/scpp/v1", wp.HTTPHandler())
		if stack.mailbox != nil {
			mux.Handle("/mailbox/v1/", channel.MailboxHandler(stack.mailbox))
		}
		stack.peerSrv = &http.Server{
			Addr: cc.PeerListen, Handler: mux,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
			MaxHeaderBytes: 64 << 10,
		}
		tls := cc.PeerTLSCert != "" && cc.PeerTLSKey != ""
		go func() {
			var err error
			if tls {
				err = stack.peerSrv.ListenAndServeTLS(cc.PeerTLSCert, cc.PeerTLSKey)
			} else {
				err = stack.peerSrv.ListenAndServe()
			}
			if err != nil && err != http.ErrServerClosed {
				logger.Printf("channels: peer surface failed: %v", err)
			}
		}()
		scheme := "http"
		if tls {
			scheme = "https"
		}
		logger.Printf("channels: SCPP/1 listening on %s://%s (public, signature-authorised)",
			scheme, cc.PeerListen)
		if !tls {
			// Said loudly rather than logged once at debug: a volunteer without
			// TLS looks healthy and is unreachable, because every browser
			// refuses to send a signed proposal to a plain-http mailbox.
			logger.Printf("channels: WARNING — the peer surface has no TLS, so no browser " +
				"will deliver to this mailbox; set channels.peer_tls_cert/peer_tls_key")
		}
	}

	// ---- the operator API, loopback only ------------------------------------
	if cc.APIListen != "" {
		api, err := channel.NewAPI(coord, nil, cc.APIToken)
		if err != nil {
			return nil, err
		}
		// Reading this operator's own mailbox at a volunteer. The same channel
		// key as above, because only the recipient can authorise a read of the
		// recipient's mailbox — and it reads only: /mailbox/v1/peek leaves the
		// proposal in place for the recipient to decide on.
		disc, err := channel.NewMailboxDiscovery(self,
			func(raw [32]byte) ([]byte, error) { return channel.SignDigest(key, raw) })
		if err != nil {
			return nil, fmt.Errorf("mailbox discovery: %w", err)
		}
		api = api.WithMailboxDiscovery(disc)
		stack.apiSrv = &http.Server{
			Addr: cc.APIListen, Handler: api.Handler(),
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
			WriteTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
		}
		go func() {
			if err := stack.apiSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				logger.Printf("channels: operator API failed: %v", err)
			}
		}()
		logger.Printf("channels: operator API on %s (loopback, token required)", cc.APIListen)
	}

	return stack, nil
}

// attachDashboard wires the recipient's own console to this stack.
//
// The P7 seam, used as intended: the dashboard talks to the Receiving
// interface and `receiving_adapter.go` is the one file that knows what a
// channel is.
func (p *paymentStack) attachDashboard(srv *ui.Server) {
	if p == nil || srv == nil {
		return
	}
	node := ui.NewPaymentNode(p.coord, p.payout)
	node.SetCollector(p.collector)
	srv.SetReceiving(node)
}

// stop shuts the listeners down.
func (p *paymentStack) stop(ctx context.Context) {
	if p == nil {
		return
	}
	for _, s := range []*http.Server{p.peerSrv, p.apiSrv} {
		if s != nil {
			_ = s.Shutdown(ctx)
		}
	}
}

// loadChannelKey reads a hex secp256k1 key.
//
// From a FILE rather than the config JSON: a key in the config is a key in
// every backup of the config, and the operator page renders that file.
func loadChannelKey(path string) (*secp256k1.PrivateKey, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("no key file configured")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimPrefix(strings.TrimSpace(string(raw)), "0x"))
	if err != nil {
		return nil, fmt.Errorf("key file is not hex: %w", err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("key must be 32 bytes, got %d", len(b))
	}
	return secp256k1.PrivKeyFromBytes(b), nil
}
