package gateway

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	maxChallengeBody = 8 << 10
	maxReplayEntries = 4096
)

type Service struct {
	signer             Signer
	version            string
	trustedProbes      map[string]string
	logger             *log.Logger
	now                func() time.Time
	mu                 sync.Mutex
	used               map[string]int64
	lastRequest        map[string]time.Time
	listenerReady      bool
	draining           bool
	prober             *Prober
	probeSlots         chan struct{}
	trustLoopbackProxy bool
	requireDHTReady    bool
	content            *ContentProxy
}

// SetContentProxy enables serving site content under this gateway's own
// hostname. Nil (the default) keeps the gateway a pure identity/probe endpoint,
// which is what an operator who only wants to donate transport should get.
func (s *Service) SetContentProxy(proxy *ContentProxy) { s.content = proxy }

// controlPlanePaths are answered by this node itself and never by the origin.
// They are how a probe or the controller establishes what this node is, so a
// content proxy must not be able to shadow any of them.
var controlPlanePaths = map[string]struct{}{
	"/healthz": {}, "/readyz": {},
	"/gateway/identity": {}, "/gateway/challenge": {}, "/probe/verify": {},
}

func isControlPlanePath(path string) bool {
	_, found := controlPlanePaths[path]
	return found
}

func NewService(signer Signer, version string, trustedProbes map[string]string, logger *log.Logger) *Service {
	trusted := make(map[string]string, len(trustedProbes))
	for id, key := range trustedProbes {
		if subtle.ConstantTimeCompare([]byte(id), []byte(signer.ID())) != 1 {
			trusted[id] = key
		}
	}
	return &Service{
		signer: signer, version: version, trustedProbes: trusted, logger: logger,
		now: time.Now, used: make(map[string]int64), lastRequest: make(map[string]time.Time),
		probeSlots: make(chan struct{}, 8), requireDHTReady: true,
	}
}

func (s *Service) SetProber(prober *Prober) { s.prober = prober }

// SetTrustLoopbackProxy allows an explicitly configured reverse proxy on the
// same host to supply the observed candidate address. The header is ignored
// unless the direct peer is loopback.
func (s *Service) SetTrustLoopbackProxy(value bool) { s.trustLoopbackProxy = value }

func (s *Service) SetRequireDHTReady(value bool) { s.requireDHTReady = value }

func (s *Service) SetListenerReady(ready bool) {
	s.mu.Lock()
	s.listenerReady = ready
	s.mu.Unlock()
}

func (s *Service) Drain() {
	s.mu.Lock()
	s.draining = true
	s.mu.Unlock()
}

func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Gateway-Version", s.version)
	// The control plane is claimed by PATH, before any method is considered. A
	// method-qualified match would let anything else -- a HEAD, most obviously
	// -- fall through to the content proxy, and /readyz would then be answered
	// by the origin instead of by this node. That is how a probe decides
	// whether this gateway is who it says it is, so the origin must never be
	// able to answer it.
	if s.content != nil && isControlPlanePath(r.URL.Path) &&
		r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed,
			map[string]string{"error": "control plane accepts GET or POST"})
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/healthz":
		// (control-plane routes below; content, if enabled, is the default case)
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": s.version})
	case r.Method == http.MethodGet && r.URL.Path == "/readyz":
		s.ready(w)
	case r.Method == http.MethodGet && r.URL.Path == "/gateway/identity":
		s.identity(w)
	case r.Method == http.MethodPost && r.URL.Path == "/gateway/challenge":
		s.challenge(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/probe/verify":
		s.probe(w, r)
	case s.content != nil:
		// Site content. The control-plane routes above are matched first and
		// always win, so a path collision cannot let the origin's response
		// masquerade as this gateway's identity or health.
		//
		// The JSON defaults set above are wrong for HTML, and the origin sends
		// its own; clear them rather than letting them override, or a signed
		// page arrives labelled application/json and no-store.
		w.Header().Del("Content-Type")
		w.Header().Del("Cache-Control")
		s.content.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Service) probe(w http.ResponseWriter, r *http.Request) {
	if s.prober == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "probe role disabled"})
		return
	}
	select {
	case s.probeSlots <- struct{}{}:
		defer func() { <-s.probeSlots }()
	default:
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "probe capacity exhausted"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 256<<10))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "invalid request"})
		return
	}
	var request VerificationRequest
	if json.Unmarshal(body, &request) != nil || request.Validate(s.now()) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid verification request"})
		return
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "source address unavailable"})
		return
	}
	peerIP := net.ParseIP(host)
	if s.trustLoopbackProxy && peerIP != nil && peerIP.IsLoopback() {
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		if forwarded == "" || net.ParseIP(forwarded) == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "forwarded source address unavailable"})
			return
		}
		host = forwarded
	}
	observedIP, err := netip.ParseAddr(host)
	if err != nil || !PublicAddress(observedIP) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "restricted observed source"})
		return
	}
	observedIP = observedIP.Unmap()
	var observed *Address
	for index := range request.ClaimedAddresses {
		claimedIP, parseErr := netip.ParseAddr(request.ClaimedAddresses[index].Address)
		if parseErr == nil && claimedIP.Unmap() == observedIP {
			observed = &request.ClaimedAddresses[index]
			break
		}
	}
	if observed == nil {
		// Never probe an arbitrary claimed victim. The address must be the
		// source of the signed request as observed by this independent node.
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "claimed address differs from observed source"})
		return
	}
	result := s.prober.Verify(r.Context(), request, *observed)
	writeJSON(w, http.StatusOK, result)
}

func (s *Service) ready(w http.ResponseWriter) {
	s.mu.Lock()
	listenerReady, draining := s.listenerReady, s.draining
	s.mu.Unlock()
	if !listenerReady || draining || (s.requireDHTReady && !s.signer.DHTReady()) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "protocol_version": ProtocolVersion,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready", "node_id": s.signer.ID(),
		"protocol_version": ProtocolVersion,
	})
}

func (s *Service) identity(w http.ResponseWriter) {
	doc, err := NewIdentity(s.signer, s.version, s.now().UTC())
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "identity unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

func (s *Service) challenge(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := s.now().UTC()
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxChallengeBody))
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "invalid challenge"})
		return
	}
	var challenge ChallengeRequest
	if json.Unmarshal(body, &challenge) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid challenge"})
		return
	}
	probeKey, admitted := s.trustedProbes[challenge.ProbeID]
	if !admitted || challenge.ProbeID == s.signer.ID() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "probe not admitted"})
		return
	}
	if challenge.ChallengeID == "" || len(challenge.ChallengeID) > 128 ||
		challenge.Nonce == "" || len(challenge.Nonce) > 256 ||
		challenge.IssuedAt > now.Add(30*time.Second).Unix() ||
		challenge.ExpiresAt <= now.Unix() ||
		challenge.ExpiresAt-challenge.IssuedAt > 60 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expired or invalid challenge"})
		return
	}
	unsigned := challenge
	unsigned.ProbeSignature = ""
	if err := verifyJSON(challenge.ProbeID, probeKey, challenge.ProbeSignature, unsigned); err != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "invalid probe signature"})
		return
	}
	// Multiple admitted probes can legitimately share one public NAT address.
	// Pace each authenticated probe/source pair rather than letting one probe
	// rate-limit every other identity on that network.
	rateKey := host + "\x00" + challenge.ProbeID
	s.mu.Lock()
	if last := s.lastRequest[rateKey]; !last.IsZero() && now.Sub(last) < time.Second {
		s.mu.Unlock()
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate limited"})
		return
	}
	s.lastRequest[rateKey] = now
	s.mu.Unlock()

	replayKey := challenge.ProbeID + "\x00" + challenge.ChallengeID + "\x00" + challenge.Nonce
	s.mu.Lock()
	s.purgeReplays(now.Unix())
	if _, reused := s.used[replayKey]; reused {
		s.mu.Unlock()
		writeJSON(w, http.StatusConflict, map[string]string{"error": "challenge already used"})
		return
	}
	if len(s.used) >= maxReplayEntries {
		s.mu.Unlock()
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "challenge capacity exhausted"})
		return
	}
	s.used[replayKey] = challenge.ExpiresAt
	s.mu.Unlock()

	response := ChallengeResponse{
		ChallengeID: challenge.ChallengeID, Nonce: challenge.Nonce,
		GatewayNodeID: s.signer.ID(), ObservedServerTime: now.Unix(),
	}
	response.Signature, err = signJSON(s.signer, response)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "signing unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) purgeReplays(now int64) {
	for key, expiry := range s.used {
		if expiry <= now {
			delete(s.used, key)
		}
	}
	for host, instant := range s.lastRequest {
		if now-instant.Unix() > 300 {
			delete(s.lastRequest, host)
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func VerifyChallengeResponse(response ChallengeResponse, identity IdentityDocument, expected ChallengeRequest) error {
	if response.ChallengeID != expected.ChallengeID || response.Nonce != expected.Nonce ||
		response.GatewayNodeID != identity.NodeID {
		return errors.New("challenge response binding mismatch")
	}
	unsigned := response
	unsigned.Signature = ""
	return verifyJSON(identity.NodeID, identity.PublicKey, response.Signature, unsigned)
}

func SignChallenge(s Signer, challenge *ChallengeRequest) error {
	if challenge.ProbeID != s.ID() {
		return errors.New("challenge probe ID does not match signer")
	}
	unsigned := *challenge
	unsigned.ProbeSignature = ""
	signature, err := signJSON(s, unsigned)
	if err != nil {
		return err
	}
	challenge.ProbeSignature = signature
	return nil
}

func DecodeIdentityKey(value string) ([]byte, error) {
	return base64.RawStdEncoding.DecodeString(value)
}
