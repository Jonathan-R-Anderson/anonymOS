package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"github.com/syndichan/maniwani/storage-client/internal/compute"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/syndichan/maniwani/storage-client/internal/bootstrap"
	"github.com/syndichan/maniwani/storage-client/internal/config"
	"github.com/syndichan/maniwani/storage-client/internal/directive"
	"github.com/syndichan/maniwani/storage-client/internal/gateway"
	gatewayfrontend "github.com/syndichan/maniwani/storage-client/internal/gateway/frontend"
	"github.com/syndichan/maniwani/storage-client/internal/heartbeat"
	"github.com/syndichan/maniwani/storage-client/internal/monitor"
	"github.com/syndichan/maniwani/storage-client/internal/p2p"
	"github.com/syndichan/maniwani/storage-client/internal/s3api"
	"github.com/syndichan/maniwani/storage-client/internal/store"
	"github.com/syndichan/maniwani/storage-client/internal/traffic"
	"github.com/syndichan/maniwani/storage-client/internal/ui"
)

var runTray func(context.Context, string, *log.Logger, func())

func main() {
	// The node launches with NO posture flags: gateway, storage and Docker
	// settings all live in the config file and are edited on the management page
	// at UIListen. The only flag is where that file lives.
	var configFile string
	flag.StringVar(&configFile, "config", "",
		"path to config.json (default: the OS config location)")
	// Headless operation: a rented server has no browser, and the management
	// page binds loopback only, so the settings people change on first run also
	// have flags. Everything else remains editable in the config JSON.
	headless := registerHeadlessFlags()
	flag.Parse()

	logger := log.New(os.Stderr, "syndichan-node ", log.LstdFlags|log.LUTC)

	// One meter for the whole process. Everything that serves bytes to somebody
	// else adds to it; exactly ONE place drains it (the heartbeat), because
	// Window() resets and a second drainer would silently swallow part of the
	// interval -- no error, just a throughput number quietly too low.
	meter := &traffic.Meter{}

	path, err := config.ConfigPath(configFile)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Printf("loading configuration: %s", path)
	// Load the file (creating a default one if absent), then resolve the run mode
	// FROM the config -- storage, gateway-only or probe-only -- and validate for
	// exactly that role. LoadOrCreate returns the parsed config even when the
	// provisional-role validation fails, so RunMode is readable first.
	cfg, created, err := config.LoadOrCreate(path, config.RoleStorage)
	role := cfg.ResolvedRole()
	if role != config.RoleStorage {
		// The file asks for a storage-free role; hold it to that role's
		// requirements, not storage's.
		err = cfg.ValidateForRole(role)
	}
	if err != nil {
		logger.Fatalf("configuration %s: %v", path, err)
	}
	if done, ferr := applyHeadlessFlags(headless, &cfg, path); ferr != nil {
		logger.Fatal(ferr)
	} else if done {
		return
	}
	// Before anything sends a beacon: a node deployed on a non-default origin
	// must not keep heartbeating the compiled-in domain, which fails silently
	// (logged, retried) and leaves the node invisible to its own network.
	if cfg.HeartbeatEndpoint != "" {
		p2p.SetHeartbeatEndpoint(cfg.HeartbeatEndpoint)
		logger.Printf("presence endpoint overridden by config: %s", cfg.HeartbeatEndpoint)
	}
	logger.Printf("runtime role: %s (%s)", role, role.Description())
	logger.Print(headlessSummary(cfg, path))
	if cfg.UIListen != "" {
		logger.Printf("configure gateway, storage and Docker at the management page: http://%s/ "+
			"(or edit %s directly — every setting lives there)", cfg.UIListen, path)
	} else {
		logger.Printf("management page disabled; edit %s to configure this node", path)
	}

	noStorage := !role.NeedsStorage()
	if created {
		// The credentials authenticate the LOOPBACK S3 gateway only; they never
		// leave this machine. The secret stays in the mode-0600 file and is shown
		// on the management page, not echoed into shell scrollback or journals.
		fmt.Fprintf(os.Stderr, "Created secure configuration: %s\n", path)
		fmt.Fprintf(os.Stderr, "S3 access key: %s\n", cfg.AccessKey)
		fmt.Fprintln(os.Stderr, "The secret key is in that mode-0600 file; view it on the management page.")
	}

	// Guards cfg against concurrent edits from the management page's handlers.
	var cfgMu sync.Mutex
	var storageNode *store.Store
	if noStorage {
		logger.Printf("storage subsystems skipped: shard store, S3, I2P (management page stays up)")
	}
	if !noStorage {
		logger.Printf("opening encrypted shard store: %s", filepath.Join(cfg.DataDir, "storage"))
		storageNode, err = store.Open(
			filepath.Join(cfg.DataDir, "storage"),
			cfg.DataShards, cfg.ParityShards, cfg.ChunkBytes, cfg.CapacityBytes,
		)
		if err != nil {
			logger.Fatal(err)
		}
		defer storageNode.Close()
		if err := storageNode.CleanupObjectPrefix(".syndichan-multipart/"); err != nil {
			logger.Fatal("clean interrupted multipart uploads: ", err)
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var node *p2p.Node
	var signer gateway.Signer
	if noStorage {
		logger.Printf("loading standalone gateway identity from %s", cfg.DataDir)
		signer, err = gateway.LoadOrCreateFileIdentity(cfg.DataDir)
	} else {
		logger.Printf("starting I2P transport and storage DHT via SAM %s", cfg.I2PSAM)
		node, err = p2p.Open(ctx, cfg.DataDir, cfg.I2PSAM, cfg.I2PHTTPProxy, storageNode, logger)
	}
	if err != nil {
		logger.Fatal(err)
	}
	if node != nil {
		defer node.Close()
		// Same meter the S3 gateway adds to. The node drains it once per
		// heartbeat, so shard traffic and object reads land in one figure
		// rather than two nobody sums.
		node.SetMeter(meter)
		node.SetMonitorEnabled(cfg.Monitor.Enabled)
		node.SetComputeRoles(cfg.Compute.Enabled, cfg.Compute.OfferCPU, cfg.Compute.OfferGPU)
		// Measured, not configured. Only advertised when compute is actually
		// offered: isolation this node will not lend is not a capability.
		node.SetMicroVM(cfg.Compute.Enabled &&
			compute.Probe(compute.Options{SkipBenchmark: true}).MicroVM.Isolated())
		signer = node
		// Opt-in: a config with no `bootstrap` section keeps the single-URL
		// behaviour it has always had. The discovered path refuses a lone
		// unverifiable source, which is correct for an install that was given a
		// pinned coordinator key and would take an upgraded node off the DHT
		// entirely if applied to one that was not.
		if cfg.Bootstrap.Configured() {
			node.SetBootstrapConfig(bootstrap.Config{
				CoordinatorKey:   cfg.Bootstrap.CoordinatorKey,
				SRVName:          cfg.Bootstrap.SRVName,
				URLs:             cfg.Bootstrap.URLs,
				MinimumAgreement: cfg.Bootstrap.MinimumAgreement,
			})
			if cfg.Bootstrap.CoordinatorKey == "" {
				logger.Printf("bootstrap: no coordinator key pinned, so the " +
					"document can only be corroborated across sources, never " +
					"verified. Set bootstrap.coordinator_key to fix that.")
			} else {
				logger.Printf("bootstrap: discovering sources via %s, verifying "+
					"against the pinned coordinator key", cfg.Bootstrap.SRVName)
			}
		}
		node.SetGatewayState(cfg.Gateway.Enabled, false)
		// node is non-nil only in the storage role, which is also the only role
		// that sends the five-minute storage heartbeat.
		go node.RefreshHeartbeat(ctx)
	}
	if node != nil {
		gatewayValidator := gateway.DHTValidator{
			TrustedProbes:   cfg.Gateway.TrustedProbes,
			MinimumProbes:   cfg.Gateway.Verification.MinimumSuccessfulProbes,
			MinimumNetworks: cfg.Gateway.Verification.MinimumDistinctNetworks,
		}
		if err := node.ConfigureGatewayRecords(gatewayValidator); err != nil {
			logger.Fatal("configure gateway DHT records: ", err)
		}
	}
	// Shared with the presence heartbeat so a gateway that gains or loses
	// verification is reflected in the next beacon.
	var gatewayVerified atomic.Bool
	var gatewayManager *gateway.Manager
	var gatewayRegistry *gateway.RegistryClient
	if cfg.Gateway.Enabled {
		gatewayRegistry, err = gateway.NewRegistryClient(
			cfg.Gateway.RegistrationAPI, cfg.Gateway.PublicHostname, signer,
		)
		if err != nil {
			logger.Fatalf("gateway registration API: %v", err)
		}
		if cfg.Gateway.TLS.Mode == "acme" {
			reservationCtx, reservationCancel := context.WithTimeout(ctx, 6*time.Minute)
			var reservation gateway.HostnameReservation
			var reserveErr error
			for {
				reservation, reserveErr = gatewayRegistry.ReserveHostname(reservationCtx)
				var httpError *gateway.RegistryHTTPError
				if reserveErr == nil || !errors.As(reserveErr, &httpError) ||
					httpError.StatusCode != http.StatusServiceUnavailable {
					break
				}
				delay := httpError.RetryAfter
				if delay <= 0 {
					delay = 60 * time.Second
				}
				logger.Printf("gateway DNS reservation temporarily unavailable; retrying in %s", delay)
				timer := time.NewTimer(delay)
				select {
				case <-reservationCtx.Done():
					timer.Stop()
					reserveErr = reservationCtx.Err()
					break
				case <-timer.C:
					continue
				}
				break
			}
			if reserveErr == nil {
				reserveErr = gatewayRegistry.WaitForReservedDNS(
					reservationCtx, reservation, 3*time.Second,
				)
			}
			reservationCancel()
			if reserveErr != nil {
				logger.Fatalf("reserve gateway hostname before ACME: %v", reserveErr)
			}
			if cfg.Gateway.PublicHostname != reservation.Hostname {
				cfg.Gateway.PublicHostname = reservation.Hostname
				if saveErr := config.Save(path, cfg, role); saveErr != nil {
					logger.Fatalf("persist controller-assigned gateway hostname: %v", saveErr)
				}
			}
			logger.Printf("controller reserved %s for ACME", reservation.Hostname)
		}
	}
	if !noStorage && cfg.CacheOnly {
		// Contribute no storage to the network: this node keeps only what it
		// caches of its own content, so its disk grows with the site rather
		// than with the number of peers.
		node.SetCacheOnly(true)
		logger.Printf("cache-only: this node will not host shards for other peers")
	}
	if !noStorage && cfg.Draining {
		// Retiring this machine. Applied from the config on every start, which is
		// the whole point of keeping the intent there: a drain takes hours and the
		// operator is about to restart or power down this node, so an intent that
		// only lived in the running process would quietly clear itself and owners
		// would resume writing to a disk on its way out.
		node.SetDraining(true)
		logger.Printf("draining: this node is being retired -- it will refuse new shards, tell the network so, and report what it still holds until it holds nothing")
	}
	var s3Server, uiServer *http.Server
	if !noStorage {
		storageNode.SetShardFetcher(node.FetchShard)
		// So GetObject can reassemble an object this node never stored (the DCS
		// worker reading a build context the bridge published to the DHT).
		storageNode.SetManifestFetcher(node.FetchManifest)
		storageNode.SetShardAdvertiser(func(shardID string) {
			provideCtx, provideCancel := context.WithTimeout(ctx, 30*time.Second)
			defer provideCancel()
			if err := node.Provide(provideCtx, shardID); err != nil {
				logger.Printf("could not advertise shard %s: %v", shardID[:12], err)
			}
		})
		storageNode.SetObjectDistributor(func(manifest store.Manifest) {
			distributeCtx, distributeCancel := context.WithTimeout(ctx, 5*time.Minute)
			defer distributeCancel()
			node.DistributeManifest(distributeCtx, manifest)
		})
		go node.AdvertiseStored(ctx)

		// Proof-of-Facilitation: make this node auditable. Answering costs a
		// Merkle path over data already on disk, and unauditable storage cannot
		// be paid for.
		if pof := startFacilitation(ctx, cfg, node, storageNode, logger); pof != nil {
			defer pof.Close()
		}

		s3Handler := s3api.New(storageNode, cfg.AccessKey, cfg.SecretKey, logger)
		s3Handler.SetMeter(meter)
		// The ledger listing can be served off the Store alone, but a RECALL has
		// to open streams to the holders, so the node is injected the same way
		// the meter is. Without it the ?recall route answers 503 rather than
		// reporting a recall that never happened.
		s3Handler.SetRecaller(node)
		s3Server = &http.Server{
			Addr: cfg.S3Listen, Handler: s3Handler,
			ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 10 * time.Minute,
			WriteTimeout: 10 * time.Minute, IdleTimeout: 90 * time.Second,
			MaxHeaderBytes: 64 << 10,
		}
	}
	// The management page runs in EVERY mode: it is where gateway, storage and
	// Docker settings are edited, and a fresh install starts as storage but can be
	// switched to gateway-only/probe-only right here. NodeInfo is nil for a
	// storage-free role (no p2p node); the page degrades to node-less stats and
	// still edits the config.
	var nodeInfo ui.NodeInfo
	if node != nil {
		nodeInfo = node
	}
	uiServer = &http.Server{
		Addr: cfg.UIListen, Handler: ui.New(storageNode, nodeInfo, logger),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 90 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	// The payment stack (P15). Started before the dashboard is told about it so
	// the console never renders a channel panel backed by nothing. A node with
	// channels switched off gets nil and behaves exactly as before.
	payments, err := startPaymentStack(cfg, logger)
	if err != nil {
		// Fatal on purpose: a node configured to handle money that cannot do so
		// should refuse to run rather than accept tips that go nowhere.
		logger.Fatalf("channels: %v", err)
	}
	if payments != nil {
		payments.attachDashboard(uiServer.Handler.(*ui.Server))
		defer payments.stop(context.Background())
	}

	// Told where it is bound, so the page decides for itself whether to demand
	// a password. Wired here, next to the server it belongs to, rather than in
	// the start-up block further down: the handler must never exist in a state
	// where it is reachable from the network and does not know it.
	uiServer.Handler.(*ui.Server).SetAccessControl(
		cfg.UIListen, cfg.DashboardUsername(), cfg.UIPassword)
	// The live load graph, only when compute is on. A node lending nothing shows
	// no meter rather than a flat line: a graph of nothing invites the reader to
	// conclude the machine is idle when nothing is measuring it.
	if cfg.Compute.Enabled {
		profile := compute.Probe(compute.Options{SkipBenchmark: true})
		policy := cfg.Compute.Policy.Normalise()
		uiServer.Handler.(*ui.Server).SetLoadMeter(ui.NewLoadMeter(
			compute.NewGovernor(policy, profile, compute.LinuxSensors{}),
			compute.LinuxSensors{},
			profile.CPU.LogicalCores,
			// Job count comes from the node, not from a guess at load: an
			// inferred figure presented next to measured ones would be read as
			// equally trustworthy.
			func() int { return 0 },
		))
	}
	// Where compute lives, learned from the signed bootstrap document. Wired as
	// a closure so the UI reads the CURRENT listing rather than one captured at
	// startup — a node that had just joined would otherwise show an empty
	// network forever.
	if node != nil {
		uiServer.Handler.(*ui.Server).SetNetworkSource(func() any {
			return node.ComputeSummary()
		})
	}
	uiServer.Handler.(*ui.Server).SetConfigAccess(
		func() config.Config { cfgMu.Lock(); defer cfgMu.Unlock(); return cfg },
		func(mutate func(*config.Config) error) error {
			cfgMu.Lock()
			defer cfgMu.Unlock()
			next := cfg
			if err := mutate(&next); err != nil {
				return err
			}
			// Validate for the role the config now asks for (a run-mode change
			// switches which requirements apply), then persist.
			if err := next.ValidateForRole(next.ResolvedRole()); err != nil {
				return err
			}
			if err := config.Save(path, next, role); err != nil {
				return err
			}
			cfg = next
			return nil
		},
	)
	var gatewayServer *http.Server
	var gatewayACMEHTTPServer *http.Server
	var gatewayListener net.Listener
	var gatewayService *gateway.Service
	var gatewayFrontend *gatewayfrontend.Server

	// The network directive watcher, for EVERY role. A node that only stores
	// shards still needs to know the origin moved, or it goes on reporting to
	// a host that is gone.
	//
	// Verification is entirely local: an Ethereum signature checked against a
	// wallet written into this node's config at install. Nothing here asks the
	// origin anything, which is the point — the origin may be what moved.
	if wallet := strings.TrimSpace(cfg.NetworkDirective.Wallet); wallet == "" {
		// Said out loud, every start. Without a pinned wallet this node cannot
		// tell a real directive from anybody else's, so it follows none — which
		// is the safe behaviour and an invisible one. An operator upgrading an
		// existing node gets the code and none of the protection, and nothing
		// would ever mention it.
		logger.Printf("network directive: no wallet pinned in %s "+
			"(network_directive.wallet), so this node will NOT learn if the "+
			"origin moves to a new domain or server. Set it to the address "+
			"published at /.well-known/syndichan/network.json to enable this.",
			path)
	} else {
		store, storeErr := directive.OpenStore(cfg.DataDir)
		if storeErr != nil {
			// Fatal on purpose. The store holds the highest sequence this node
			// has seen, and starting without it would silently drop the replay
			// floor — a node that forgets accepts a directive from a year ago.
			logger.Fatalf("network directive store: %v", storeErr)
		}
		if held := store.Held(); held != nil {
			logger.Printf("network directive: holding sequence %d (kind=%s, domain=%s)",
				held.Sequence, held.Kind, held.OriginDomain)
			// Applied HERE, before anything reads these URLs. Adopting a
			// directive and restarting achieves nothing on its own: the config
			// still names the old domain in every origin-derived URL, so the
			// node would come back up and talk to precisely the host that moved.
			applyDirective(&cfg, store, held, logger)
		}
		watcher := &directive.Watcher{
			Wallet:  wallet,
			Sources: cfg.NetworkDirective.Sources,
			Store:   store,
			Log:     logger,
			// This node's own S3 credentials, for reading the object-store copy
			// through its own loopback endpoint. Not used for any other source.
			Credentials: directive.Credentials{
				AccessKey: cfg.AccessKey,
				SecretKey: cfg.SecretKey,
			},
			Interval: time.Duration(cfg.NetworkDirective.PollSeconds) * time.Second,
			OnAdopt: func(d *directive.Directive) {
				// Restart rather than re-point live. Half this process is
				// already holding connections, registrations and a signer bound
				// to the old origin; swapping the address underneath them would
				// leave a node partly on each. Exiting is honest, and every
				// supported way of running this restarts automatically.
				logger.Printf("network directive: sequence %d adopted — restarting "+
					"to come up against %s", d.Sequence,
					directive.OriginBase(d, "the configured origin"))
				cancel()
			},
		}
		go watcher.Run(ctx)
	}

	// Started OUTSIDE the gateway block, which is what GatewayValidatorConfig
	// already claims: "independent of every other role". It was nested under
	// `Gateway.Enabled || Gateway.ProbeEnabled`, so a node configured to do
	// nothing but validate started, logged nothing, and audited nothing — the
	// worst shape of failure, because it looks like it is working.
	//
	// It needs the signer and the logger and nothing from gatewayService, so
	// there is no ordering reason for it to have lived in there.
	if cfg.Gateway.Validator.Enabled {
		originURL := cfg.Gateway.Validator.OriginURL
		if originURL == "" {
			originURL = "https://syndichan.org"
		}
		validator := gateway.NewValidator(signer, originURL, logger,
			time.Now().UnixNano())
		if seconds := cfg.Gateway.Validator.IntervalSeconds; seconds > 0 {
			validator.Interval = time.Duration(seconds) * time.Second
		}
		if size := cfg.Gateway.Validator.SampleSize; size > 0 {
			validator.SampleSize = size
		}
		go validator.Run(ctx)
		logger.Printf("validator auditing gateways published by %s every %s",
			originURL, validator.Interval)
	}
	if cfg.Gateway.Enabled || cfg.Gateway.ProbeEnabled {
		gatewayService = gateway.NewService(signer, "1.0.0", cfg.Gateway.TrustedProbes, logger)
		gatewayService.SetTrustLoopbackProxy(cfg.Gateway.TLS.Mode == "reverse_proxy")
		// The storage DHT only exists in the storage role; a standalone
		// gateway or probe reports readiness from its listener alone.
		//
		// A content-serving gateway is excluded even in storage mode, because
		// its gateway duty is fetching from the origin over HTTPS and does not
		// touch the DHT. Coupling them means a node that is serving content
		// perfectly reports not_ready because an unrelated subsystem has not
		// bootstrapped -- the controller then refuses its registration and
		// pulls its DNS, which is an outage caused by a healthy gateway
		// truthfully describing a part of itself nobody was asking about.
		//
		// Readiness is a self-report either way; the controller still connects
		// back independently before publishing anything.
		gatewayService.SetRequireDHTReady(!noStorage && !cfg.Gateway.Content.Enabled)
		if cfg.Gateway.ProbeEnabled {
			gatewayService.SetProber(&gateway.Prober{
				Signer: signer, Network: cfg.Gateway.ProbeNetwork,
				PublicHostname: cfg.Gateway.PublicHostname,
				Timeout:        time.Duration(cfg.Gateway.Verification.VerificationTimeoutSeconds) * time.Second,
				ResultValidity: time.Duration(cfg.Gateway.Verification.ProbeResultValiditySeconds) * time.Second,
			})
		}
		if cfg.Gateway.Content.Enabled {
			originURL, parseErr := url.Parse(cfg.Gateway.Content.OriginURL)
			if parseErr != nil {
				logger.Fatalf("gateway content origin_url is invalid: %v", parseErr)
			}
			contentProxy := gateway.NewContentProxy(
				originURL, originURL.Hostname(), signer.ID(),
				cfg.Gateway.Content.OriginAddress,
			)
			if cfg.Gateway.Content.MaxBytes > 0 {
				contentProxy.MaxBytes = cfg.Gateway.Content.MaxBytes
			}
			if emergency := cfg.Gateway.Content.Emergency; emergency.Enabled {
				key, keyErr := base64.StdEncoding.DecodeString(
					strings.TrimSpace(emergency.PublisherKey))
				if keyErr != nil || len(key) != ed25519.PublicKeySize {
					// Fatal, not a warning. A gateway that thinks it has an
					// emergency copy and does not is worse than one that knows
					// it has none: the operator would learn during the outage.
					logger.Fatalf("gateway emergency publisher_key is not a "+
						"base64 ed25519 public key: %v", keyErr)
				}
				cacheDir := emergency.CacheDir
				snapshots := gateway.NewSnapshotCache(originURL.String(), cacheDir,
					ed25519.PublicKey(key))
				snapshots.Logger = logger
				if emergency.PollSeconds > 0 {
					snapshots.Poll = time.Duration(emergency.PollSeconds) * time.Second
				}
				if emergency.MaxObjectBytes > 0 {
					snapshots.MaxObjectBytes = emergency.MaxObjectBytes
				}
				contentProxy.Snapshot = snapshots
				contentProxy.Health = gateway.NewOriginHealth()
				contentProxy.Offload = emergency.Offload
				go snapshots.Run(ctx)
				logger.Printf("emergency cache enabled: polling %s every %s, holding in %s%s",
					originURL.Host, snapshots.Poll, cacheDir,
					map[bool]string{true: " (origin offload ON)", false: ""}[emergency.Offload])
			}
			gatewayService.SetContentProxy(contentProxy)
			logger.Printf("gateway serves content for %s under %s as %s",
				originURL.Host, cfg.Gateway.PublicHostname, signer.ID())
		}
		gatewayAddress := net.JoinHostPort(
			cfg.Gateway.ListenAddress, fmt.Sprint(cfg.Gateway.ListenPort),
		)
		serviceAddress := gatewayAddress
		if cfg.Gateway.Frontend.Enabled {
			// The SNI frontend owns the public listener. The identity service
			// still terminates its own TLS, but only on an ephemeral loopback
			// socket selected here and unreachable from other hosts.
			serviceAddress = "127.0.0.1:0"
		}
		gatewayServer = &http.Server{
			Addr:    serviceAddress,
			Handler: gatewayService, ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second,
			IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10,
		}
		gatewayListener, err = net.Listen("tcp", gatewayServer.Addr)
		if err != nil {
			logger.Fatalf("HTTPS gateway bind failed: %v", err)
		}
		switch cfg.Gateway.TLS.Mode {
		case "existing":
			certificate, err := tls.LoadX509KeyPair(
				cfg.Gateway.TLS.CertificatePath, cfg.Gateway.TLS.PrivateKeyPath,
			)
			if err != nil {
				logger.Fatalf("HTTPS gateway TLS configuration failed: %v", err)
			}
			gatewayListener = tls.NewListener(gatewayListener, &tls.Config{
				Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12,
			})
		case "acme":
			cacheDirectory := cfg.Gateway.TLS.ACMECacheDirectory
			if cacheDirectory == "" {
				cacheDirectory = filepath.Join(cfg.DataDir, "gateway-acme")
			}
			acmeManager, managerErr := gateway.NewACMEManager(
				cfg.Gateway.PublicHostname, cfg.Gateway.TLS.ACMEEmail, cacheDirectory,
			)
			if managerErr != nil {
				logger.Fatalf("HTTPS gateway ACME configuration failed: %v", managerErr)
			}
			acmeHTTPListener, listenErr := net.Listen("tcp", cfg.Gateway.TLS.ACMEHTTPAddress)
			if listenErr != nil {
				logger.Fatalf("HTTPS gateway ACME HTTP bind failed: %v", listenErr)
			}
			gatewayACMEHTTPServer = &http.Server{
				Handler:           acmeManager.HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
				WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second,
				MaxHeaderBytes: 16 << 10,
			}
			go func() {
				if serveErr := gatewayACMEHTTPServer.Serve(acmeHTTPListener); serveErr != nil && serveErr != http.ErrServerClosed {
					logger.Printf("gateway ACME HTTP listener failed: %v", serveErr)
				}
			}()
			tlsConfig := acmeManager.TLSConfig()
			tlsConfig.MinVersion = tls.VersionTLS12
			gatewayListener = tls.NewListener(gatewayListener, tlsConfig)
		}
		if cfg.Gateway.Frontend.Enabled {
			frontendListener, listenErr := net.Listen("tcp", gatewayAddress)
			if listenErr != nil {
				logger.Fatalf("gateway frontend bind failed: %v", listenErr)
			}
			gatewayFrontend, err = gatewayfrontend.New(gatewayfrontend.Config{
				OriginAddress:     cfg.Gateway.Frontend.OriginAddress,
				LocalAddress:      gatewayListener.Addr().String(),
				LocalHostname:     cfg.Gateway.PublicHostname,
				SNIAllowlist:      cfg.Gateway.Frontend.SNIAllowlist,
				SNIRoutes:         cfg.Gateway.Frontend.SNIRoutes,
				MaxConnections:    cfg.Gateway.Frontend.MaxConnections,
				MaxBytesPerSecond: cfg.Gateway.Frontend.MaxBytesPerSecond,
				HandshakeTimeout: time.Duration(
					cfg.Gateway.Frontend.HandshakeTimeoutSeconds,
				) * time.Second,
				DialTimeout: time.Duration(
					cfg.Gateway.Frontend.DialTimeoutSeconds,
				) * time.Second,
				IdleTimeout: time.Duration(
					cfg.Gateway.Frontend.IdleTimeoutSeconds,
				) * time.Second,
				ProxyProtocol: cfg.Gateway.Frontend.ProxyProtocol,
			}, logger)
			if err != nil {
				_ = frontendListener.Close()
				logger.Fatalf("gateway frontend configuration failed: %v", err)
			}
			go func() {
				if serveErr := gatewayFrontend.Serve(frontendListener); serveErr != nil && serveErr != gatewayfrontend.ErrServerClosed {
					logger.Fatalf("gateway frontend failed: %v", serveErr)
				}
			}()
		}
		gatewayService.SetListenerReady(true)
		go func() {
			if err := gatewayServer.Serve(gatewayListener); err != nil && err != http.ErrServerClosed {
				logger.Fatalf("HTTPS gateway failed: %v", err)
			}
		}()
		logger.Printf("volunteer gateway candidate listening on %s for %s",
			gatewayAddress, cfg.Gateway.PublicHostname)
	}
	// Registration is what makes a gateway reachable, so it runs whenever the
	// gateway role is on. external_verification only decides HOW the address
	// is proven: by a peer probe quorum, or by the controller's own
	// independent connect-back alone.
	// Registering puts this host's IP into the PUBLIC syndichan.org answer set.
	// Without the SNI frontend this process serves only its own gw-<id>
	// hostname, so a visitor whose DNS lands here gets a completed TCP connect
	// and then a failed TLS handshake ("host not configured in HostWhitelist").
	// Browsers do not fail over from a TLS error the way they do from a refused
	// connection, so that visitor is simply broken -- an outage caused purely
	// by joining the pool. Serve the site, or stay out of the pool.
	if cfg.Gateway.Enabled && !cfg.Gateway.Frontend.Enabled {
		logger.Printf("gateway.frontend is disabled: NOT registering with the controller.")
		logger.Printf("  This node cannot serve %s, so publishing its IP in that DNS answer",
			cfg.Gateway.Frontend.OriginServerName)
		logger.Printf("  set would break every visitor routed to it. It still serves its own")
		logger.Printf("  %s endpoints and sends the presence heartbeat.", cfg.Gateway.PublicHostname)
		logger.Printf("  Set gateway.frontend.enabled=true (with a reachable origin_address) to join the pool.")
	}
	if cfg.Gateway.Enabled && cfg.Gateway.Frontend.Enabled {
		// One definition, shared with validation: a quorum is only in play when
		// the operator actually named a probe fleet.
		quorumInPlay := cfg.Gateway.Verification.Enabled &&
			config.ProbeQuorumConfigured(cfg.Gateway)
		if cfg.Gateway.Verification.Enabled && !quorumInPlay {
			logger.Printf("no probe_urls/trusted_probes configured: verifying through the " +
				"controller alone. It still connect-backs to this host before publishing DNS, " +
				"but this node will not report itself as independently verified.")
		}
		addresses := make([]gateway.Address, 0, len(cfg.Gateway.PublicAddresses))
		for _, value := range cfg.Gateway.PublicAddresses {
			ip := net.ParseIP(value)
			if ip != nil && ip.To4() != nil && !cfg.Gateway.AdvertiseIPv4 {
				continue
			}
			if ip != nil && ip.To4() == nil && !cfg.Gateway.AdvertiseIPv6 {
				continue
			}
			addresses = append(addresses, gateway.Address{Address: value, Port: 443})
		}
		if gatewayRegistry == nil {
			logger.Fatal("gateway registration client was not initialized")
		}
		gatewayRegistry.PublicHostname = cfg.Gateway.PublicHostname
		var publisher gateway.RegistrationPublisher = gatewayRegistry
		// The DHT record is the PEER-VERIFIED artifact: every reader of it
		// independently checks the probe quorum before accepting it, so a
		// registration carrying no probe results can never be published there.
		// Including the DHT publisher without a quorum therefore adds a step
		// that is guaranteed to fail.
		//
		// That is not merely noisy. MultiPublisher stops at the first error, the
		// manager treats the whole attempt as failed, and the health machine
		// eventually reports the gateway unhealthy -- which the registry client
		// sends as an UNREGISTER. A gateway serving perfectly over HTTPS would
		// register and then delete itself, once a minute, forever.
		if node != nil && cfg.Gateway.Verification.Enabled {
			publisher = gateway.MultiPublisher{
				// The central controller verifies the direct source IP and owns
				// DNS. The DHT receives the record only after that request succeeds.
				Publishers: []gateway.RegistrationPublisher{gatewayRegistry, node},
			}
		}
		var manager *gateway.Manager
		manager, err = gateway.NewManager(signer, publisher, gateway.ManagerConfig{
			Addresses: addresses, PublicHostname: cfg.Gateway.PublicHostname,
			ProbeURLs:            cfg.Gateway.ProbeURLs,
			TrustedProbes:        cfg.Gateway.TrustedProbes,
			MinimumProbes:        cfg.Gateway.Verification.MinimumSuccessfulProbes,
			MinimumNetworks:      cfg.Gateway.Verification.MinimumDistinctNetworks,
			RequestTimeout:       time.Duration(cfg.Gateway.Verification.VerificationTimeoutSeconds) * time.Second,
			ResultValidity:       time.Duration(cfg.Gateway.Verification.ProbeResultValiditySeconds) * time.Second,
			RegistrationValidity: time.Duration(cfg.Gateway.Verification.RegistrationValiditySeconds) * time.Second,
			Interval:             time.Duration(cfg.Gateway.Verification.ReverifyIntervalSeconds) * time.Second,
			StatePath:            filepath.Join(cfg.DataDir, "gateway-registration.json"),
			SoftwareVersion:      "1.0.0",
			FailureThreshold:     cfg.Gateway.Health.FailureThreshold,
			RecoveryThreshold:    cfg.Gateway.Health.RecoveryThreshold,
			DrainDuration:        time.Duration(cfg.Gateway.Health.DrainSeconds) * time.Second,
			RequireProbeQuorum:   quorumInPlay,
		}, logger, func(verified bool) {
			gatewayVerified.Store(verified)
			if node != nil {
				node.SetGatewayState(true, verified)
				if verified && manager != nil {
					node.SetGatewayRegistration(manager.Current())
				} else {
					node.SetGatewayRegistration(nil)
				}
				go node.RefreshHeartbeat(ctx)
			}
		})
		if err != nil {
			logger.Fatalf("gateway verification manager: %v", err)
		}
		gatewayManager = manager
		go manager.Run(ctx)
	}
	// Presence heartbeat for the storage-free roles. A storage node sends its
	// own from inside the p2p node; a dedicated gateway or probe has no p2p
	// node, but it still has a persistent identity and the operator still
	// needs to see it. It reports zero capacity, which is exactly how the
	// frontend tells a gateway apart from a storage node.
	if noStorage {
		presence := &heartbeat.Client{
			// Endpoint, not the package default: gateway-only mode builds its
			// own presence client here, so without this a node on a different
			// origin keeps beaconing the compiled-in domain -- which 405s and
			// leaves the gateway invisible on its own network's status page.
			Endpoint: cfg.HeartbeatEndpoint,
			Signer:   signer, Logger: logger,
			Snapshot: func() heartbeat.State {
				state := heartbeat.State{
					CapacityBytes:   0,
					GatewayEnabled:  cfg.Gateway.Enabled,
					GatewayVerified: gatewayVerified.Load(),
					Monitor:         cfg.Monitor.Enabled,
				}
				w := meter.Window(time.Now())
				state.Traffic = heartbeat.Traffic{
					Bytes: w.Bytes, Requests: w.Requests, WindowSeconds: w.WindowSeconds,
				}
				if state.GatewayVerified && gatewayManager != nil {
					state.Registration = gatewayManager.Current()
				}
				return state
			},
		}
		logger.Printf("presence heartbeat every %s to %s", heartbeat.Interval, func() string {
			if cfg.HeartbeatEndpoint != "" {
				return cfg.HeartbeatEndpoint
			}
			return heartbeat.Endpoint
		}())
		go presence.Run(ctx)
	}
	// Status monitoring, in EVERY role including storage nodes. Checking that
	// the site answers needs no disk, no port and no p2p node -- only an
	// internet connection and a different vantage point from the server's own,
	// which is the entire value of doing it out here.
	if cfg.Monitor.Enabled && cfg.Monitor.TargetsURL != "" {
		watcher := &monitor.Client{
			Signer:     signer,
			TargetsURL: cfg.Monitor.TargetsURL,
			ReportURL:  cfg.Monitor.ReportURL,
			Logger:     logger,
		}
		logger.Printf("status monitor: checking %s", cfg.Monitor.TargetsURL)
		go watcher.Run(ctx)
	}
	if !noStorage {
		uiServer.Handler.(*ui.Server).SetStoragePaths(cfg.DataDir, func(target string) error {
			// Persist only; the store is open and moving it live would risk
			// corrupting it. Takes effect on the next start (see ui.setStorageDir).
			cfgMu.Lock()
			defer cfgMu.Unlock()
			next := cfg
			next.DataDir = target
			if err := config.Save(path, next, role); err != nil {
				return err
			}
			cfg = next
			return nil
		})
		logger.Printf("starting S3 gateway on %s", cfg.S3Listen)
		go serve(s3Server, cfg, logger, "S3 gateway")
	}
	// The management page starts in every mode EXCEPT when it is switched off.
	// A headless server administered over SSH cannot reach a loopback page
	// anyway, and running an unauthenticated one it never uses is pure surface.
	if cfg.UIListen != "" {
		if config.ListenIsLoopback(cfg.UIListen) {
			logger.Printf("starting management page on http://%s/ (this machine only)", cfg.UIListen)
		} else {
			// Said plainly, and said at every start rather than only at the one
			// where it was configured. An operator who did this by accident --
			// or inherited a config that did -- finds out from the log the
			// first time they read it, not from whoever finds the port.
			logger.Printf("starting management page on http://%s/ — REACHABLE FROM YOUR LOCAL "+
				"NETWORK, not just this machine. It asks for the ui_username (%q) and "+
				"ui_password from %s. Set ui_listen to 127.0.0.1:9090 to make it local again.",
				cfg.UIListen, cfg.DashboardUsername(), path)
		}
		go serve(uiServer, cfg, logger, "management page")
	} else {
		uiServer = nil
		logger.Printf("management page disabled — configure by editing %s", path)
	}
	// Distributed Container Service. Off unless dcs.enabled + role.worker; a
	// no-op otherwise, and non-fatal if Docker is unreachable. Needs the full
	// storage node (host, DHT, I2P, store), so it is wired here in that path.
	if !noStorage {
		startDCSWorker(ctx, cfg, node, storageNode, logger)
		// Compute, made reachable from the network rather than from loopback
		// only. Built here rather than inside the bridge because a volunteer
		// lending a CPU has no reason to have configured a bridge for a site it
		// does not host, and gating peer-reachable compute on dcs.api_listen
		// would leave such a node advertising a device nothing could dispatch
		// to. Returns nil when the operator lends nothing.
		computeNode := startComputePeerService(cfg, node, logger)
		// The images that make that offer true. Both are told the answer: the
		// node, whose heartbeat stops claiming a capability it cannot honour,
		// and the API, which stops accepting work it would die on. Runs in the
		// background — nothing else here waits on a download.
		startCatalogueImages(ctx, cfg, logger, node, computeNode)
		// The bridge API lets a co-located website deploy on its users' behalf
		// through this one node. Independent of the worker role: a node can be a
		// bridge without running containers itself.
		startDCSBridge(ctx, cfg, node, storageNode, computeNode, logger)
	}
	// Tray icon when built with -tags tray; nil otherwise. It does not keep the
	// node alive -- the node is a service and outlives any window -- it just
	// makes that visible and gives the dashboard somewhere to be reopened from.
	if runTray != nil {
		runTray(ctx, "http://"+cfg.UIListen, logger, cancel)
	}
	if node != nil {
		logger.Printf("node %s started on %s; bootstrap=%s", signer.ID(), config.PlatformLabel(), config.BootstrapURL)
	} else {
		logger.Printf("node %s started on %s", signer.ID(), config.PlatformLabel())
	}
	if noStorage {
		logger.Printf("%s mode: %s", role, role.Description())
	} else {
		logger.Printf("S3 gateway: %s; dashboard: %s", cfg.S3Listen, cfg.UIListen)
	}

	<-ctx.Done()
	shutdownTimeout := 15 * time.Second
	if cfg.Gateway.Frontend.Enabled {
		configuredDrain := time.Duration(cfg.Gateway.Frontend.DrainSeconds) * time.Second
		if configuredDrain > shutdownTimeout {
			shutdownTimeout = configuredDrain
		}
	}
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutdownCancel()
	if gatewayService != nil {
		gatewayService.Drain()
	}
	if gatewayFrontend != nil {
		_ = gatewayFrontend.Shutdown(shutdownCtx)
	}
	if gatewayServer != nil {
		_ = gatewayServer.Shutdown(shutdownCtx)
	}
	if gatewayACMEHTTPServer != nil {
		_ = gatewayACMEHTTPServer.Shutdown(shutdownCtx)
	}
	if s3Server != nil {
		_ = s3Server.Shutdown(shutdownCtx)
	}
	if uiServer != nil {
		_ = uiServer.Shutdown(shutdownCtx)
	}
	logger.Printf("shutdown complete")
}

func serve(server *http.Server, cfg config.Config, logger *log.Logger, label string) {
	var err error
	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		err = server.ListenAndServeTLS(cfg.TLSCert, cfg.TLSKey)
	} else {
		err = server.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		logger.Fatalf("%s failed: %v", label, err)
	}
}
