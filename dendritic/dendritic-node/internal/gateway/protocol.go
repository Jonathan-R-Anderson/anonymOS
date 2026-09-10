package gateway

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
)

const ProtocolVersion = 1

type Signer interface {
	ID() string
	Sign([]byte) ([]byte, error)
	PublicKey() ([]byte, error)
	DHTReady() bool
}

type IdentityDocument struct {
	NodeID          string `json:"node_id"`
	PublicKey       string `json:"public_key"`
	ProtocolVersion int    `json:"protocol_version"`
	SoftwareVersion string `json:"software_version"`
	Timestamp       int64  `json:"timestamp"`
	Signature       string `json:"signature,omitempty"`
}

type ChallengeRequest struct {
	ChallengeID    string `json:"challenge_id"`
	Nonce          string `json:"nonce"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	ProbeID        string `json:"probe_id"`
	ProbeSignature string `json:"probe_signature,omitempty"`
}

type ChallengeResponse struct {
	ChallengeID        string `json:"challenge_id"`
	Nonce              string `json:"nonce"`
	GatewayNodeID      string `json:"gateway_node_id"`
	ObservedServerTime int64  `json:"observed_server_time"`
	Signature          string `json:"signature,omitempty"`
}

type Address struct {
	Family  string `json:"family"`
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type VerificationRequest struct {
	RequestID          string    `json:"request_id"`
	CandidateNodeID    string    `json:"candidate_node_id"`
	CandidatePublicKey string    `json:"candidate_public_key"`
	PublicHostname     string    `json:"public_hostname"`
	ClaimedAddresses   []Address `json:"claimed_addresses"`
	ProtocolVersion    int       `json:"protocol_version"`
	IssuedAt           int64     `json:"issued_at"`
	ExpiresAt          int64     `json:"expires_at"`
	Signature          string    `json:"signature,omitempty"`
}

type ProbeResult struct {
	RequestID       string `json:"request_id"`
	CandidateNodeID string `json:"candidate_node_id"`
	ProbeNodeID     string `json:"probe_node_id"`
	ProbeNetwork    string `json:"probe_network"`
	TestedAddress   string `json:"tested_address"`
	TestedPort      int    `json:"tested_port"`
	TCPReachable    bool   `json:"tcp_reachable"`
	TLSValid        bool   `json:"tls_valid"`
	IdentityValid   bool   `json:"identity_valid"`
	ChallengeValid  bool   `json:"challenge_valid"`
	ProtocolValid   bool   `json:"protocol_valid"`
	LatencyMS       int64  `json:"latency_ms"`
	ObservedAt      int64  `json:"observed_at"`
	ExpiresAt       int64  `json:"expires_at"`
	FailureReason   string `json:"failure_reason,omitempty"`
	Signature       string `json:"signature,omitempty"`
}

type Registration struct {
	RecordType       string        `json:"record_type"`
	NodeID           string        `json:"node_id"`
	PublicKey        string        `json:"public_key"`
	Addresses        []Address     `json:"addresses"`
	ProtocolVersion  int           `json:"protocol_version"`
	SoftwareVersion  string        `json:"software_version"`
	Capabilities     []string      `json:"capabilities"`
	SuccessfulProbes int           `json:"successful_probes"`
	DistinctNetworks int           `json:"distinct_networks"`
	VerifiedAt       int64         `json:"verified_at"`
	HealthState      HealthState   `json:"health_state"`
	IssuedAt         int64         `json:"issued_at"`
	ExpiresAt        int64         `json:"expires_at"`
	Sequence         uint64        `json:"sequence"`
	ProbeResults     []ProbeResult `json:"probe_results"`
	Signature        string        `json:"signature,omitempty"`
}

type HealthState string

const (
	StateCandidate HealthState = "candidate"
	StateHealthy   HealthState = "healthy"
	StateSuspect   HealthState = "suspect"
	StateDraining  HealthState = "draining"
	StateUnhealthy HealthState = "unhealthy"
	StateRemoved   HealthState = "removed"
)

func signJSON(s Signer, value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	signature, err := s.Sign(body)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(signature), nil
}

func verifyJSON(nodeID, publicKey, signature string, value any) error {
	rawKey, err := base64.RawStdEncoding.DecodeString(publicKey)
	if err != nil {
		return errors.New("invalid public key encoding")
	}
	key, err := crypto.UnmarshalPublicKey(rawKey)
	if err != nil {
		return errors.New("invalid public key")
	}
	id, err := peer.IDFromPublicKey(key)
	if err != nil || id.String() != nodeID {
		return errors.New("public key does not match node ID")
	}
	rawSignature, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	ok, err := key.Verify(body, rawSignature)
	if err != nil || !ok {
		return errors.New("invalid signature")
	}
	return nil
}

func NewIdentity(s Signer, version string, now time.Time) (IdentityDocument, error) {
	key, err := s.PublicKey()
	if err != nil {
		return IdentityDocument{}, err
	}
	doc := IdentityDocument{
		NodeID: s.ID(), PublicKey: base64.RawStdEncoding.EncodeToString(key),
		ProtocolVersion: ProtocolVersion, SoftwareVersion: version,
		Timestamp: now.Unix(),
	}
	doc.Signature, err = signJSON(s, doc)
	return doc, err
}

func NewVerificationRequest(s Signer, hostname string, addresses []Address, now time.Time, validity time.Duration) (VerificationRequest, error) {
	key, err := s.PublicKey()
	if err != nil {
		return VerificationRequest{}, err
	}
	request := VerificationRequest{
		RequestID: randomID(), CandidateNodeID: s.ID(),
		CandidatePublicKey: base64.RawStdEncoding.EncodeToString(key),
		PublicHostname:     strings.ToLower(strings.TrimSuffix(hostname, ".")),
		ClaimedAddresses:   append([]Address(nil), addresses...),
		ProtocolVersion:    ProtocolVersion, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(validity).Unix(),
	}
	request.Signature, err = signJSON(s, request)
	return request, err
}

func (r VerificationRequest) Validate(now time.Time) error {
	if r.ProtocolVersion != ProtocolVersion || r.RequestID == "" {
		return errors.New("unsupported or incomplete request")
	}
	if r.IssuedAt > now.Add(30*time.Second).Unix() || r.ExpiresAt <= now.Unix() ||
		r.ExpiresAt-r.IssuedAt > 300 {
		return errors.New("verification request expired or excessively long")
	}
	if r.PublicHostname == "" || len(r.PublicHostname) > 253 ||
		strings.ContainsAny(r.PublicHostname, "/:@") ||
		!strings.Contains(r.PublicHostname, ".") {
		return errors.New("candidate public hostname is invalid")
	}
	for _, address := range r.ClaimedAddresses {
		if address.Port != 443 {
			return errors.New("only public TCP port 443 may be verified")
		}
		ip, err := netip.ParseAddr(address.Address)
		if err != nil || !PublicAddress(ip) {
			return fmt.Errorf("restricted probe target %q", address.Address)
		}
		if ip.Is4() != (address.Family == "ipv4") {
			return errors.New("address family mismatch")
		}
	}
	unsigned := r
	unsigned.Signature = ""
	return verifyJSON(r.CandidateNodeID, r.CandidatePublicKey, r.Signature, unsigned)
}

func VerifyProbeResult(result ProbeResult, probePublicKey string, now time.Time) error {
	if result.ProbeNodeID == result.CandidateNodeID {
		return errors.New("self-verification is forbidden")
	}
	if result.ExpiresAt <= now.Unix() || result.ObservedAt > now.Add(30*time.Second).Unix() {
		return errors.New("probe result expired")
	}
	unsigned := result
	unsigned.Signature = ""
	return verifyJSON(result.ProbeNodeID, probePublicKey, result.Signature, unsigned)
}

func EvaluateQuorum(results []ProbeResult, trusted map[string]string, now time.Time, successes, networks int) error {
	seenProbes := map[string]struct{}{}
	seenNetworks := map[string]struct{}{}
	count := 0
	for _, result := range results {
		key, admitted := trusted[result.ProbeNodeID]
		if !admitted {
			continue
		}
		if _, duplicate := seenProbes[result.ProbeNodeID]; duplicate {
			continue
		}
		if err := VerifyProbeResult(result, key, now); err != nil {
			continue
		}
		if !(result.TCPReachable && result.TLSValid && result.IdentityValid &&
			result.ChallengeValid && result.ProtocolValid) {
			continue
		}
		seenProbes[result.ProbeNodeID] = struct{}{}
		seenNetworks[result.ProbeNetwork] = struct{}{}
		count++
	}
	if count < successes || len(seenNetworks) < networks {
		return fmt.Errorf("verification quorum not met: %d/%d probes, %d/%d networks",
			count, successes, len(seenNetworks), networks)
	}
	return nil
}

// VerifiedAddressResults keeps only addresses which independently met the
// configured probe and network quorum. A successful IPv4 probe can therefore
// never authorize an advertised IPv6 address, or vice versa.
func VerifiedAddressResults(
	addresses []Address,
	results []ProbeResult,
	trusted map[string]string,
	now time.Time,
	successes, networks int,
) ([]Address, []ProbeResult) {
	var verified []Address
	var accepted []ProbeResult
	for _, address := range NormalizeAddresses(addresses) {
		var matching []ProbeResult
		for _, result := range results {
			if result.TestedAddress == address.Address &&
				result.TestedPort == address.Port {
				matching = append(matching, result)
			}
		}
		if EvaluateQuorum(matching, trusted, now, successes, networks) != nil {
			continue
		}
		verified = append(verified, address)
		seenProbes := map[string]struct{}{}
		for _, result := range matching {
			probeKey, admitted := trusted[result.ProbeNodeID]
			if !admitted {
				continue
			}
			if _, duplicate := seenProbes[result.ProbeNodeID]; duplicate {
				continue
			}
			if VerifyProbeResult(result, probeKey, now) != nil ||
				!(result.TCPReachable && result.TLSValid && result.IdentityValid &&
					result.ChallengeValid && result.ProtocolValid) {
				continue
			}
			seenProbes[result.ProbeNodeID] = struct{}{}
			accepted = append(accepted, result)
		}
	}
	return verified, accepted
}

func NewRegistration(s Signer, addresses []Address, results []ProbeResult, trusted map[string]string,
	now time.Time, validity time.Duration, sequence uint64, version string,
	minimumSuccesses, minimumNetworks int) (Registration, error) {
	normalized := NormalizeAddresses(addresses)
	verifiedAddresses, verifiedResults := VerifiedAddressResults(
		normalized, results, trusted, now, minimumSuccesses, minimumNetworks,
	)
	if len(normalized) == 0 || len(verifiedAddresses) != len(normalized) {
		return Registration{}, errors.New("every advertised address must independently meet verification quorum")
	}
	key, err := s.PublicKey()
	if err != nil {
		return Registration{}, err
	}
	networks := map[string]struct{}{}
	seenProbes := map[string]struct{}{}
	successes := 0
	for _, result := range verifiedResults {
		probeKey, ok := trusted[result.ProbeNodeID]
		if _, duplicate := seenProbes[result.ProbeNodeID]; duplicate {
			continue
		}
		if ok && VerifyProbeResult(result, probeKey, now) == nil &&
			result.TCPReachable && result.TLSValid && result.IdentityValid &&
			result.ChallengeValid && result.ProtocolValid {
			seenProbes[result.ProbeNodeID] = struct{}{}
			successes++
			networks[result.ProbeNetwork] = struct{}{}
		}
	}
	registration := Registration{
		RecordType: "verified_gateway", NodeID: s.ID(),
		PublicKey: base64.RawStdEncoding.EncodeToString(key),
		Addresses: verifiedAddresses, ProtocolVersion: ProtocolVersion,
		SoftwareVersion:  version,
		Capabilities:     []string{"https_gateway", "dht_lookup", "content_proxy"},
		SuccessfulProbes: successes, DistinctNetworks: len(networks),
		VerifiedAt: now.Unix(), HealthState: StateHealthy,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(validity).Unix(),
		Sequence: sequence, ProbeResults: append([]ProbeResult(nil), verifiedResults...),
	}
	registration.Signature, err = signJSON(s, registration)
	return registration, err
}

// NewControllerRegistration builds a registration that carries no peer probe
// results, for a gateway that is not running a peer probe quorum.
//
// This is not a weaker claim smuggled in under the same name -- it is a
// different claim. It asserts only "this identity owns these addresses"; it
// asserts nothing about reachability. The authoritative controller performs
// its own independent connect-back to the address before it will publish DNS,
// and that check is what actually gates traffic.
//
// Because SuccessfulProbes and DistinctNetworks are zero, this registration is
// rejected by DHTValidator and by the frontend's gateway-role check. A node
// holding one must report gateway_verified=false in its heartbeat: it is
// registered, not independently verified.
func NewControllerRegistration(s Signer, addresses []Address, now time.Time,
	validity time.Duration, sequence uint64, version string) (Registration, error) {
	normalized := NormalizeAddresses(addresses)
	if len(normalized) == 0 {
		return Registration{}, errors.New("gateway has no public addresses to register")
	}
	for _, address := range normalized {
		ip, err := netip.ParseAddr(address.Address)
		if err != nil || !PublicAddress(ip) || address.Port != 443 {
			return Registration{}, fmt.Errorf("address %q is not eligible", address.Address)
		}
	}
	key, err := s.PublicKey()
	if err != nil {
		return Registration{}, err
	}
	registration := Registration{
		RecordType: "verified_gateway", NodeID: s.ID(),
		PublicKey: base64.RawStdEncoding.EncodeToString(key),
		Addresses: normalized, ProtocolVersion: ProtocolVersion,
		SoftwareVersion:  version,
		Capabilities:     []string{"https_gateway", "dht_lookup", "content_proxy"},
		SuccessfulProbes: 0, DistinctNetworks: 0,
		VerifiedAt: now.Unix(), HealthState: StateHealthy,
		IssuedAt: now.Unix(), ExpiresAt: now.Add(validity).Unix(),
		Sequence: sequence,
	}
	registration.Signature, err = signJSON(s, registration)
	return registration, err
}

func (r Registration) Validate(trusted map[string]string, now time.Time, minimumSuccesses, minimumNetworks int) error {
	if r.RecordType != "verified_gateway" || r.ProtocolVersion != ProtocolVersion ||
		r.ExpiresAt <= now.Unix() || r.ExpiresAt-r.IssuedAt > 900 ||
		r.Sequence == 0 || len(r.Addresses) == 0 {
		return errors.New("invalid or expired gateway registration")
	}
	for _, address := range r.Addresses {
		ip, err := netip.ParseAddr(address.Address)
		if err != nil || !PublicAddress(ip) || address.Port != 443 {
			return errors.New("registration contains a restricted address")
		}
	}
	verificationTime := time.Unix(r.VerifiedAt, 0)
	if verificationTime.After(now.Add(30*time.Second)) ||
		verificationTime.Before(now.Add(-15*time.Minute)) {
		return errors.New("invalid registration verification time")
	}
	normalized := NormalizeAddresses(r.Addresses)
	if len(normalized) != len(r.Addresses) {
		return errors.New("registration addresses must be unique and canonical")
	}
	for index := range normalized {
		if normalized[index] != r.Addresses[index] {
			return errors.New("registration address family or canonical form is invalid")
		}
	}
	verifiedAddresses, _ := VerifiedAddressResults(
		normalized, r.ProbeResults, trusted, verificationTime,
		minimumSuccesses, minimumNetworks,
	)
	if len(verifiedAddresses) != len(normalized) {
		return errors.New("every advertised address must independently meet verification quorum")
	}
	unsigned := r
	unsigned.Signature = ""
	return verifyJSON(r.NodeID, r.PublicKey, r.Signature, unsigned)
}

type HealthMachine struct {
	State             HealthState `json:"state"`
	ConsecutiveFails  int         `json:"consecutive_failures"`
	ConsecutivePasses int         `json:"consecutive_successes"`
	DrainStartedAt    int64       `json:"drain_started_at,omitempty"`
}

func (h HealthMachine) Observe(ok bool, now time.Time, failureThreshold, recoveryThreshold int, drain time.Duration) HealthMachine {
	if ok {
		h.ConsecutiveFails = 0
		h.ConsecutivePasses++
		if (h.State == StateCandidate || h.State == StateSuspect ||
			h.State == StateUnhealthy || h.State == StateDraining ||
			h.State == StateRemoved) && h.ConsecutivePasses >= recoveryThreshold {
			h.State = StateHealthy
			h.DrainStartedAt = 0
		}
		return h
	}
	h.ConsecutivePasses = 0
	h.ConsecutiveFails++
	switch h.State {
	case StateHealthy:
		h.State = StateSuspect
	case StateSuspect, StateCandidate:
		if h.ConsecutiveFails >= failureThreshold {
			h.State = StateDraining
			h.DrainStartedAt = now.Unix()
		}
	case StateDraining:
		if now.Unix()-h.DrainStartedAt >= int64(drain.Seconds()) {
			h.State = StateRemoved
		}
	}
	return h
}

func PublicAddress(ip netip.Addr) bool {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsPrivate() {
		return false
	}
	blocked := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001::/32"), // Teredo
	}
	ip = ip.Unmap()
	for _, prefix := range blocked {
		if prefix.Contains(ip) {
			return false
		}
	}
	return true
}

func NormalizeAddresses(addresses []Address) []Address {
	seen := map[string]struct{}{}
	result := make([]Address, 0, len(addresses))
	for _, value := range addresses {
		ip, err := netip.ParseAddr(strings.TrimSpace(value.Address))
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		value.Address = ip.String()
		if ip.Is4() {
			value.Family = "ipv4"
		} else {
			value.Family = "ipv6"
		}
		key := fmt.Sprintf("%s/%d", value.Address, value.Port)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		return result[i].Address < result[j].Address
	})
	return result
}

func randomID() string {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}
