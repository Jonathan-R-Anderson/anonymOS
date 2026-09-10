package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type ManagerConfig struct {
	Addresses            []Address
	PublicHostname       string
	ProbeURLs            []string
	TrustedProbes        map[string]string
	MinimumProbes        int
	MinimumNetworks      int
	RequestTimeout       time.Duration
	ResultValidity       time.Duration
	RegistrationValidity time.Duration
	Interval             time.Duration
	StatePath            string
	SoftwareVersion      string
	FailureThreshold     int
	RecoveryThreshold    int
	DrainDuration        time.Duration
	// RequireProbeQuorum runs the peer verification round before registering.
	// When false the node still registers with the controller, which performs
	// its own independent connect-back; it simply never claims to be
	// peer-verified. This is what external_verification.enabled selects.
	RequireProbeQuorum bool
}

type RegistrationPublisher interface {
	PublishGatewayRegistration(context.Context, Registration) error
}

type Manager struct {
	signer     Signer
	publisher  RegistrationPublisher
	config     ManagerConfig
	client     *http.Client
	logger     interface{ Printf(string, ...any) }
	onVerified func(bool)
	mu         sync.RWMutex
	current    *Registration
	health     HealthMachine
}

func NewManager(signer Signer, publisher RegistrationPublisher, config ManagerConfig,
	logger interface{ Printf(string, ...any) }, onVerified func(bool)) (*Manager, error) {
	config.Addresses = NormalizeAddresses(config.Addresses)
	if len(config.Addresses) == 0 {
		return nil, errors.New("gateway has no public addresses to verify")
	}
	for _, address := range config.Addresses {
		ip, err := netip.ParseAddr(address.Address)
		if err != nil || !PublicAddress(ip) || address.Port != 443 {
			return nil, fmt.Errorf("gateway address %q is not eligible", address.Address)
		}
	}
	if config.RequireProbeQuorum && len(config.ProbeURLs) < config.MinimumProbes {
		return nil, errors.New("fewer probe URLs than the required quorum")
	}
	for _, raw := range config.ProbeURLs {
		parsed, err := url.Parse(raw)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
			parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
			return nil, fmt.Errorf("probe URL %q must be a credential-free HTTPS origin", raw)
		}
	}
	manager := &Manager{
		signer: signer, publisher: publisher, config: config, logger: logger,
		onVerified: onVerified,
		health:     HealthMachine{State: StateCandidate},
		client: &http.Client{
			Timeout: config.RequestTimeout,
			Transport: &http.Transport{
				// Probe requests must leave directly so the independent probe
				// observes the candidate's real source address. Environment
				// HTTP(S)_PROXY settings would both break that guarantee and
				// commonly reject the probes' nonstandard HTTPS ports.
				Proxy:           nil,
				TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("probe redirects are forbidden")
			},
		},
	}
	manager.load()
	return manager, nil
}

func (m *Manager) Run(ctx context.Context) {
	m.verify(ctx)
	interval := m.config.Interval
	if interval <= 0 {
		interval = time.Minute
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			m.publishDraining()
			if m.onVerified != nil {
				m.onVerified(false)
			}
			return
		case <-ticker.C:
			m.verify(ctx)
		}
	}
}

func (m *Manager) Current() *Registration {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return nil
	}
	copy := *m.current
	return &copy
}

func (m *Manager) verify(ctx context.Context) {
	if !m.config.RequireProbeQuorum {
		m.registerWithoutQuorum(ctx)
		return
	}
	now := time.Now().UTC()
	request, err := NewVerificationRequest(
		m.signer, m.config.PublicHostname, m.config.Addresses, now, m.config.ResultValidity,
	)
	if err != nil {
		m.failed(ctx, "create verification request: %v", err)
		return
	}
	body, _ := json.Marshal(request)
	type response struct {
		url    string
		result ProbeResult
		err    error
	}
	responses := make(chan response, len(m.config.ProbeURLs))
	for _, rawURL := range m.config.ProbeURLs {
		go func(rawURL string) {
			result, err := m.requestProbe(ctx, rawURL, body)
			responses <- response{url: rawURL, result: result, err: err}
		}(rawURL)
	}
	var results []ProbeResult
	for range m.config.ProbeURLs {
		item := <-responses
		if item.err == nil {
			results = append(results, item.result)
			if m.logger != nil && (!item.result.TCPReachable || !item.result.TLSValid ||
				!item.result.IdentityValid || !item.result.ChallengeValid ||
				!item.result.ProtocolValid) {
				m.logger.Printf("gateway probe %s rejected candidate: %s",
					item.url, item.result.FailureReason)
			}
		} else if m.logger != nil {
			m.logger.Printf("gateway probe %s failed: %v", item.url, item.err)
		}
	}
	verifiedAddresses, verifiedResults := VerifiedAddressResults(
		m.config.Addresses, results, m.config.TrustedProbes, time.Now(),
		m.config.MinimumProbes, m.config.MinimumNetworks,
	)
	if len(verifiedAddresses) == 0 {
		m.failed(ctx, "external verification failed: no address family met quorum")
		return
	}
	m.mu.Lock()
	if m.health.State == StateDraining || m.health.State == StateUnhealthy ||
		m.health.State == StateRemoved {
		recoveryThreshold := m.config.RecoveryThreshold
		if recoveryThreshold < 1 {
			recoveryThreshold = 2
		}
		m.health = m.health.Observe(true, time.Now(), 1, recoveryThreshold, 0)
		if m.health.State != StateHealthy {
			passes := m.health.ConsecutivePasses
			m.mu.Unlock()
			if m.logger != nil {
				m.logger.Printf("gateway recovery check %d/%d passed",
					passes, recoveryThreshold)
			}
			return
		}
	}
	m.mu.Unlock()
	sequence := uint64(1)
	if current := m.Current(); current != nil {
		sequence = current.Sequence + 1
	}
	registration, err := NewRegistration(
		m.signer, verifiedAddresses, verifiedResults, m.config.TrustedProbes,
		time.Now(), m.config.RegistrationValidity, sequence,
		m.config.SoftwareVersion, m.config.MinimumProbes, m.config.MinimumNetworks,
	)
	if err != nil {
		m.failed(ctx, "registration failed: %v", err)
		return
	}
	if err := m.consume(ctx, registration); err != nil {
		return
	}
	publishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = m.publisher.PublishGatewayRegistration(publishCtx, registration)
	cancel()
	if err != nil {
		m.failed(ctx, "gateway registration publish failed: %v", err)
		return
	}
	m.mu.Lock()
	m.health = HealthMachine{State: StateHealthy}
	m.mu.Unlock()
	if m.onVerified != nil {
		m.onVerified(true)
	}
	if m.logger != nil {
		m.logger.Printf("gateway verified at %d address(es) by %d probes across %d networks; registration expires %s",
			len(registration.Addresses),
			registration.SuccessfulProbes, registration.DistinctNetworks,
			time.Unix(registration.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
}

// registerWithoutQuorum submits a signed registration and lets the controller
// be the one that proves reachability. The controller connects back to the
// derived source address, requires HTTP 200 and X-Gateway-Version on /readyz,
// and publishes DNS only if that succeeds -- so a gateway that is not actually
// reachable still never enters the answer set. What is lost relative to a
// probe quorum is the independent multi-network view, which is why this path
// never reports itself as verified.
func (m *Manager) registerWithoutQuorum(ctx context.Context) {
	sequence := uint64(1)
	if current := m.Current(); current != nil {
		sequence = current.Sequence + 1
	}
	registration, err := NewControllerRegistration(
		m.signer, m.config.Addresses, time.Now(),
		m.config.RegistrationValidity, sequence, m.config.SoftwareVersion,
	)
	if err != nil {
		m.failed(ctx, "registration failed: %v", err)
		return
	}
	if err := m.consume(ctx, registration); err != nil {
		return
	}
	publishCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	err = m.publisher.PublishGatewayRegistration(publishCtx, registration)
	cancel()
	if err != nil {
		m.failed(ctx, "gateway registration publish failed: %v", err)
		return
	}
	m.mu.Lock()
	m.health = HealthMachine{State: StateHealthy}
	m.mu.Unlock()
	// Deliberately false: registered with the controller, but not
	// independently peer-verified. The frontend shows a gateway role only for
	// the latter.
	if m.onVerified != nil {
		m.onVerified(false)
	}
	if m.logger != nil {
		m.logger.Printf("gateway registered with the controller at %d address(es) without a peer probe quorum; registration expires %s",
			len(registration.Addresses),
			time.Unix(registration.ExpiresAt, 0).UTC().Format(time.RFC3339))
	}
}

func (m *Manager) requestProbe(ctx context.Context, rawURL string, body []byte) (ProbeResult, error) {
	var result ProbeResult
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		rawURL+"/probe/verify", bytes.NewReader(body))
	if err != nil {
		return result, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		return result, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return result, fmt.Errorf("probe returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 256<<10)).Decode(&result); err != nil {
		return result, err
	}
	key, ok := m.config.TrustedProbes[result.ProbeNodeID]
	if !ok {
		return result, errors.New("result came from an untrusted probe")
	}
	if err := VerifyProbeResult(result, key, time.Now()); err != nil {
		return result, err
	}
	return result, nil
}

func (m *Manager) failed(ctx context.Context, format string, args ...any) {
	m.mu.Lock()
	failureThreshold := m.config.FailureThreshold
	if failureThreshold < 1 {
		failureThreshold = 3
	}
	recoveryThreshold := m.config.RecoveryThreshold
	if recoveryThreshold < 1 {
		recoveryThreshold = 2
	}
	drain := m.config.DrainDuration
	if drain <= 0 {
		drain = time.Minute
	}
	m.health = m.health.Observe(false, time.Now(), failureThreshold, recoveryThreshold, drain)
	state := m.health.State
	m.mu.Unlock()
	if state == StateDraining || state == StateRemoved {
		m.publishHealth(ctx, state)
		if m.onVerified != nil {
			m.onVerified(false)
		}
	}
	if m.logger != nil {
		m.logger.Printf(format, args...)
	}
}

func (m *Manager) publishHealth(ctx context.Context, state HealthState) {
	current := m.Current()
	if current == nil {
		return
	}
	current.HealthState = state
	current.Sequence++
	current.IssuedAt = time.Now().Unix()
	if state == StateRemoved {
		current.ExpiresAt = current.IssuedAt + 1
	}
	current.Signature = ""
	signature, err := signJSON(m.signer, *current)
	if err != nil {
		return
	}
	current.Signature = signature
	publishCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = m.publisher.PublishGatewayRegistration(publishCtx, *current)
	cancel()
	if err != nil {
		return
	}
	_ = m.save(*current)
	m.mu.Lock()
	m.current = current
	m.mu.Unlock()
}

func (m *Manager) publishDraining() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	m.publishHealth(ctx, StateDraining)
}

func (m *Manager) save(registration Registration) error {
	if m.config.StatePath == "" {
		return nil
	}
	raw, err := json.MarshalIndent(registration, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.config.StatePath), 0700); err != nil {
		return err
	}
	temp := m.config.StatePath + ".tmp"
	if err := os.WriteFile(temp, append(raw, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(temp, m.config.StatePath)
}

// consume records a registration BEFORE it is published, because its sequence
// is spent the moment the controller sees it.
//
// The controller refuses any registration whose sequence is not strictly
// greater than the last it stored. It does not require them to be contiguous,
// so skipping a number when an attempt fails costs nothing — while REUSING one
// is refused permanently, and a gateway in that state can never come back.
//
// That is not hypothetical. A registration goes to the controller and to the
// DHT through one MultiPublisher, which returns on the first error. A gateway
// running without a peer probe quorum always fails the DHT step, so the
// controller would accept and store sequence N while the node, seeing an error
// from a later and unrelated step, discarded it and kept N-1. On the next
// restart it offered N again, was refused with 409, and stayed refused —
// forever, with no message naming the cause.
//
// Saving first inverts that: the number is burnt on attempt. A failure now
// costs one wasted sequence instead of the gateway's identity.
func (m *Manager) consume(ctx context.Context, registration Registration) error {
	m.mu.Lock()
	m.current = &registration
	m.mu.Unlock()
	if err := m.save(registration); err != nil {
		m.failed(ctx, "persist registration: %v", err)
		return err
	}
	return nil
}

func (m *Manager) load() {
	raw, err := os.ReadFile(m.config.StatePath)
	if err != nil {
		return
	}
	var registration Registration
	if json.Unmarshal(raw, &registration) != nil {
		return
	}
	// Restart never restores verified status. The old sequence is retained only
	// to prevent rollback; a fresh external quorum is still mandatory.
	m.current = &registration
	if m.onVerified != nil {
		m.onVerified(false)
	}
}
