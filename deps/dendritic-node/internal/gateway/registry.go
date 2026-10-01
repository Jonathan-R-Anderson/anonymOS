package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const RegistryUserAgent = "Syndichan-Storage-Client/1.0"

// RegistryClient sends signed, short-lived statements to the central gateway
// controller. It deliberately has no credential field: the node identity is
// the client credential, while Name.com credentials remain server-side.
type RegistryClient struct {
	Endpoint       string
	PublicHostname string
	Signer         Signer
	Client         *http.Client
	Now            func() time.Time
	LookupIP       func(context.Context, string) ([]net.IPAddr, error)
}

type registryRequest struct {
	Version        int          `json:"version"`
	NodeID         string       `json:"node_id"`
	PublicKey      string       `json:"public_key"`
	PublicHostname string       `json:"public_hostname"`
	Port           int          `json:"port"`
	Timestamp      int64        `json:"timestamp"`
	Nonce          string       `json:"nonce"`
	Registration   Registration `json:"registration"`
}

type reservationRequest struct {
	Version   int    `json:"version"`
	NodeID    string `json:"node_id"`
	PublicKey string `json:"public_key"`
	Timestamp int64  `json:"timestamp"`
	Nonce     string `json:"nonce"`
}

type HostnameReservation struct {
	Hostname  string `json:"hostname"`
	IP        string `json:"ip"`
	ExpiresAt int64  `json:"expires_at"`
}

type RegistryHTTPError struct {
	StatusCode int
	RetryAfter time.Duration
}

func (e *RegistryHTTPError) Error() string {
	return fmt.Sprintf("gateway registry returned HTTP %d", e.StatusCode)
}

func NewRegistryClient(endpoint, hostname string, signer Signer) (*RegistryClient, error) {
	parsed, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("registration endpoint must be a credential-free HTTPS URL")
	}
	if signer == nil {
		return nil, errors.New("registration signer is required")
	}
	return &RegistryClient{
		Endpoint: strings.TrimRight(endpoint, "/"), PublicHostname: hostname,
		Signer: signer, Now: time.Now,
		LookupIP: net.DefaultResolver.LookupIPAddr,
		Client: &http.Client{
			Timeout: 25 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("registration redirects are forbidden")
			},
		},
	}, nil
}

// WaitForReservedDNS prevents ACME from racing authoritative/recursive DNS
// propagation. Success requires the controller-returned source IP to be among
// the public answers for the exact reserved hostname.
func (c *RegistryClient) WaitForReservedDNS(
	ctx context.Context, reservation HostnameReservation, retry time.Duration,
) error {
	if retry <= 0 {
		retry = 2 * time.Second
	}
	expected := net.ParseIP(reservation.IP)
	if expected == nil {
		return errors.New("reservation IP is invalid")
	}
	for {
		addresses, err := c.LookupIP(ctx, reservation.Hostname)
		if err == nil {
			for _, address := range addresses {
				if address.IP.Equal(expected) {
					return nil
				}
			}
		}
		timer := time.NewTimer(retry)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("gateway DNS did not publish %s: %w",
				reservation.IP, ctx.Err())
		case <-timer.C:
		}
	}
}

// ReserveHostname asks the controller to derive and temporarily publish this
// node identity's one allowed gw-* hostname to the request's source address.
// The response is then used for exact-host ACME; no DNS credential reaches the
// volunteer client.
func (c *RegistryClient) ReserveHostname(ctx context.Context) (HostnameReservation, error) {
	publicKey, err := c.Signer.PublicKey()
	if err != nil {
		return HostnameReservation{}, fmt.Errorf("read public key: %w", err)
	}
	nonce, err := registryNonce()
	if err != nil {
		return HostnameReservation{}, err
	}
	body, err := json.Marshal(reservationRequest{
		Version: ProtocolVersion, NodeID: c.Signer.ID(),
		PublicKey: base64.RawStdEncoding.EncodeToString(publicKey),
		Timestamp: c.Now().UTC().Unix(), Nonce: nonce,
	})
	if err != nil {
		return HostnameReservation{}, err
	}
	response, err := c.signedPost(ctx, "reserve", body)
	if err != nil {
		return HostnameReservation{}, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
		return HostnameReservation{}, registryHTTPError(response)
	}
	var reservation HostnameReservation
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&reservation); err != nil {
		return HostnameReservation{}, fmt.Errorf("decode gateway reservation: %w", err)
	}
	if reservation.Hostname == "" || net.ParseIP(reservation.IP) == nil ||
		reservation.ExpiresAt <= c.Now().Unix() {
		return HostnameReservation{}, errors.New("gateway registry returned an invalid reservation")
	}
	c.PublicHostname = strings.ToLower(strings.TrimSuffix(reservation.Hostname, "."))
	return reservation, nil
}

func (c *RegistryClient) PublishGatewayRegistration(ctx context.Context, registration Registration) error {
	if c.PublicHostname == "" {
		return errors.New("gateway hostname has not been reserved")
	}
	publicKey, err := c.Signer.PublicKey()
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	nonce, err := registryNonce()
	if err != nil {
		return err
	}
	now := c.Now().UTC()
	body, err := json.Marshal(registryRequest{
		Version: ProtocolVersion, NodeID: c.Signer.ID(),
		PublicKey:      base64.RawStdEncoding.EncodeToString(publicKey),
		PublicHostname: c.PublicHostname, Port: 443, Timestamp: now.Unix(),
		Nonce: nonce, Registration: registration,
	})
	if err != nil {
		return err
	}
	action := "register"
	if registration.HealthState == StateDraining ||
		registration.HealthState == StateUnhealthy ||
		registration.HealthState == StateRemoved {
		action = "unregister"
	}
	response, err := c.signedPost(ctx, action, body)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return registryHTTPError(response)
	}
	return nil
}

func registryHTTPError(response *http.Response) error {
	retryAfter := time.Duration(0)
	if seconds, err := strconv.Atoi(response.Header.Get("Retry-After")); err == nil &&
		seconds > 0 {
		retryAfter = time.Duration(seconds) * time.Second
	}
	return &RegistryHTTPError{
		StatusCode: response.StatusCode,
		RetryAfter: retryAfter,
	}
}

func registryNonce() (string, error) {
	nonce := make([]byte, 24)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("create nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(nonce), nil
}

func (c *RegistryClient) signedPost(
	ctx context.Context, action string, body []byte,
) (*http.Response, error) {
	signature, err := c.Signer.Sign(body)
	if err != nil {
		return nil, fmt.Errorf("sign registration request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, c.Endpoint+"/"+action, bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", RegistryUserAgent)
	request.Header.Set("X-Syndichan-Node", c.Signer.ID())
	request.Header.Set("X-Syndichan-Signature", base64.RawStdEncoding.EncodeToString(signature))
	response, err := c.Client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("gateway registry: %w", err)
	}
	return response, nil
}

// MultiPublisher performs the authoritative server registration first. A
// failed server-side verification therefore cannot accidentally become a
// successful local/DHT registration.
type MultiPublisher struct {
	Publishers []RegistrationPublisher
}

func (m MultiPublisher) PublishGatewayRegistration(ctx context.Context, registration Registration) error {
	for _, publisher := range m.Publishers {
		if publisher == nil {
			continue
		}
		if err := publisher.PublishGatewayRegistration(ctx, registration); err != nil {
			return err
		}
	}
	return nil
}
