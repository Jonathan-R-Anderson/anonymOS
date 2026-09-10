package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"time"
)

type Prober struct {
	Signer         Signer
	Network        string
	PublicHostname string
	Timeout        time.Duration
	ResultValidity time.Duration
}

func (p *Prober) Verify(ctx context.Context, request VerificationRequest, address Address) ProbeResult {
	started := time.Now()
	result := ProbeResult{
		RequestID: request.RequestID, CandidateNodeID: request.CandidateNodeID,
		ProbeNodeID: p.Signer.ID(), ProbeNetwork: p.Network,
		TestedAddress: address.Address, TestedPort: address.Port,
		ObservedAt: started.Unix(),
	}
	validity := p.ResultValidity
	if validity <= 0 {
		validity = 2 * time.Minute
	}
	result.ExpiresAt = started.Add(validity).Unix()
	if err := request.Validate(started); err != nil {
		result.FailureReason = err.Error()
		return p.sign(result)
	}
	ip, err := netip.ParseAddr(address.Address)
	if err != nil || !PublicAddress(ip) || address.Port != 443 {
		result.FailureReason = "restricted probe target"
		return p.sign(result)
	}
	hostname := request.PublicHostname
	if hostname == "" {
		result.FailureReason = "probe hostname is not configured"
		return p.sign(result)
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	dialAddress := net.JoinHostPort(ip.String(), strconv.Itoa(address.Port))
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12, ServerName: hostname,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			// Connect only to the already validated literal IP. DNS cannot
			// rebind the probe to localhost, metadata services, or a LAN.
			return dialer.DialContext(ctx, network, dialAddress)
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Timeout: timeout, Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are forbidden during gateway verification")
		},
	}
	base := "https://" + hostname
	identity, err := p.fetchIdentity(ctx, client, base)
	if err != nil {
		result.FailureReason = err.Error()
		return p.sign(result)
	}
	result.TCPReachable, result.TLSValid = true, true
	if err := validateIdentity(identity, request, time.Now()); err != nil {
		result.FailureReason = err.Error()
		return p.sign(result)
	}
	result.IdentityValid = true
	challenge := ChallengeRequest{
		ChallengeID: randomID(), Nonce: randomID(), ProbeID: p.Signer.ID(),
		IssuedAt: time.Now().Unix(), ExpiresAt: time.Now().Add(30 * time.Second).Unix(),
	}
	if err := SignChallenge(p.Signer, &challenge); err != nil {
		result.FailureReason = "probe signing failed"
		return p.sign(result)
	}
	response, err := p.sendChallenge(ctx, client, base, challenge)
	if err != nil {
		result.FailureReason = err.Error()
		return p.sign(result)
	}
	if err := VerifyChallengeResponse(response, identity, challenge); err != nil {
		result.FailureReason = err.Error()
		return p.sign(result)
	}
	result.ChallengeValid = true
	ready, err := p.checkReady(ctx, client, base, request.CandidateNodeID)
	if err != nil || !ready {
		result.FailureReason = "gateway protocol is not ready"
		return p.sign(result)
	}
	result.ProtocolValid = true
	result.LatencyMS = time.Since(started).Milliseconds()
	return p.sign(result)
}

func (p *Prober) fetchIdentity(ctx context.Context, client *http.Client, base string) (IdentityDocument, error) {
	var identity IdentityDocument
	if err := getJSON(ctx, client, base+"/gateway/identity", &identity); err != nil {
		return identity, fmt.Errorf("identity request failed: %w", err)
	}
	return identity, nil
}

func validateIdentity(identity IdentityDocument, request VerificationRequest, now time.Time) error {
	if identity.NodeID != request.CandidateNodeID ||
		identity.PublicKey != request.CandidatePublicKey ||
		identity.ProtocolVersion != ProtocolVersion {
		return errors.New("gateway identity substitution detected")
	}
	if identity.Timestamp < now.Add(-2*time.Minute).Unix() ||
		identity.Timestamp > now.Add(30*time.Second).Unix() {
		return errors.New("stale gateway identity")
	}
	unsigned := identity
	unsigned.Signature = ""
	return verifyJSON(identity.NodeID, identity.PublicKey, identity.Signature, unsigned)
}

func (p *Prober) sendChallenge(ctx context.Context, client *http.Client, base string, challenge ChallengeRequest) (ChallengeResponse, error) {
	var response ChallengeResponse
	body, err := json.Marshal(challenge)
	if err != nil {
		return response, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/gateway/challenge", bytes.NewReader(body))
	if err != nil {
		return response, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return response, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return response, fmt.Errorf("challenge returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<10)).Decode(&response); err != nil {
		return response, err
	}
	return response, nil
}

func (p *Prober) checkReady(ctx context.Context, client *http.Client, base, expectedNode string) (bool, error) {
	var response struct {
		Status          string `json:"status"`
		NodeID          string `json:"node_id"`
		ProtocolVersion int    `json:"protocol_version"`
	}
	if err := getJSON(ctx, client, base+"/readyz", &response); err != nil {
		return false, err
	}
	return response.Status == "ready" && response.NodeID == expectedNode &&
		response.ProtocolVersion == ProtocolVersion, nil
}

func getJSON(ctx context.Context, client *http.Client, url string, target any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 32<<10)).Decode(target)
}

func (p *Prober) sign(result ProbeResult) ProbeResult {
	unsigned := result
	unsigned.Signature = ""
	result.Signature, _ = signJSON(p.Signer, unsigned)
	return result
}
