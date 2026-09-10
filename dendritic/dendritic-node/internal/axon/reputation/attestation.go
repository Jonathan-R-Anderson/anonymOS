// Package reputation is G6 and G7: signed attestations and the LOCAL reducer.
//
// R14 forbids a consensus document and forbids any party measuring the network
// on everyone else's behalf, and §23's P12a is built on that -- profiles are
// first-hand, never transmitted, because "a capacity tier derived from your own
// traffic is a fingerprint of your own traffic if it ever escapes the node".
// A network-wide reputation vector is precisely the global metric R14 rules out.
//
// R-88.1 is the resolution: there is NO network-wide score and NO query that
// returns one. There are signed attestations, and each node reduces the ones it
// chooses to trust into its own view. Two nodes with different trusted issuers
// legitimately reach different conclusions, and THAT IS THE DESIGN -- it is what
// makes this a pluralistic network rather than a consensus one. E-G7 tests it by
// requiring divergence.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS PACKAGE MAY NOT PUBLISH, AND THAT IS NOT A TODO.
//
// R-97.1 (2026-08-19) broke the G6/G17 cycle by separating a BUILD dependency
// from a DEPLOYMENT one. G17's need for G6 is a schema dependency -- proving "I
// have sufficient reputation in category X" needs the format fixed, not any
// reputation accumulated. G6's need for G17 is a deployment dependency: the
// schema can exist and be tested with synthetic attestations; what must not
// happen at nine nodes is publishing real ones, because §96 names exactly that
// scale as where "that history identifies the operator completely".
//
// So this package has no DHT record class, no wire encoding, no transport, and
// no publish path. Reaching G6/G7 means IMPLEMENTED AND TESTED, not published --
// "a reading that treats reaching G6/G7 as permission to publish attestations is
// the privacy regression §96 exists to prevent". TestNothingHerePublishes is the
// guard, and it is a test rather than a comment because a comment does not fail.
// ─────────────────────────────────────────────────────────────────────────────
package reputation

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// Dimension is what an attestation is about.
//
// SEPARATE DIMENSIONS, per §88, and the reason is worth keeping: someone can be
// an excellent malware reporter and a poor governance participant, and a single
// score forces the network to choose which of those to be wrong about.
type Dimension uint8

const (
	DimUptime Dimension = iota
	DimBandwidth
	DimRouting
	DimHosting
	DimReporting
	DimGovernance
	DimClassification
	DimEconomic
	dimCount
)

var dimensionNames = [dimCount]string{
	"uptime", "bandwidth", "routing", "hosting",
	"reporting", "governance", "classification", "economic",
}

func (d Dimension) String() string {
	if int(d) >= len(dimensionNames) {
		return "dimension(" + strconv.Itoa(int(d)) + ")"
	}
	return dimensionNames[d]
}

// Valid reports whether d is one of §88's eight.
func (d Dimension) Valid() bool { return int(d) < int(dimCount) }

// ParseDimension is the inverse of String.
func ParseDimension(s string) (Dimension, error) {
	for i, name := range dimensionNames {
		if name == s {
			return Dimension(i), nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrBadDimension, s)
}

var (
	ErrBadDimension = errors.New("axon/reputation: not one of §88's dimensions")
	ErrBadValue     = errors.New("axon/reputation: value outside [-1, 1]")
	ErrNoSubject    = errors.New("axon/reputation: attestation names no subject")
	ErrNoIssuer     = errors.New("axon/reputation: attestation names no issuer")
	ErrNoBasis      = errors.New("axon/reputation: attestation states no basis")
	ErrBasisTooLong = errors.New("axon/reputation: basis exceeds its bound")
	ErrBadSignature = errors.New("axon/reputation: signature does not verify")
	ErrSelfAttested = errors.New("axon/reputation: an issuer may not attest to itself")
	ErrNoWindow     = errors.New("axon/reputation: basis states no observation window")
)

const (
	// MaxBasisBytes bounds the free-text basis.
	//
	// Bounded for the reason §89's evidence entries are: an unbounded string in
	// a signed record is a payload channel smuggled inside a governance object.
	// It is text a human reads, not a field anything parses.
	MaxBasisBytes = 512

	// SigningPrefix domain-separates the signature. Every signed encoding in
	// this tree is built by hand for the same reason: a signature over
	// "whatever the encoder produced" is a signature over an encoder version.
	SigningPrefix = "axon:attestation:v1"
)

// Attestation is §88's record.
type Attestation struct {
	// Subject is a node id or content identity.
	Subject   string
	Dimension Dimension
	// Value is in [-1, 1].
	Value float64
	// Basis is what the issuer OBSERVED, and over what window.
	//
	// REQUIRED, and the window with it. §88 puts "what the issuer observed, and
	// over what window" in the schema itself, so an attestation that states
	// neither is an opinion wearing a signature -- and the whole point of the
	// reducer below is that a node can weigh issuers against its own
	// measurements, which is impossible if it cannot tell what was measured.
	Basis string
	// Window is how long the issuer observed for.
	Window time.Duration
	// Issuer is the attesting identity's public key.
	Issuer ed25519.PublicKey
	// At is when the attestation was made.
	At time.Time
	// Signature over SigningBytes.
	Signature []byte
}

// SigningBytes is the exact pre-image, built by hand and in a fixed order.
func (a Attestation) SigningBytes() []byte {
	var b strings.Builder
	b.WriteString(SigningPrefix)
	b.WriteByte('\n')
	b.WriteString("subject: " + a.Subject + "\n")
	b.WriteString("dimension: " + a.Dimension.String() + "\n")
	// Fixed precision, so the same value never signs two ways.
	b.WriteString("value: " + strconv.FormatFloat(a.Value, 'f', 6, 64) + "\n")
	b.WriteString("window_s: " + strconv.FormatInt(int64(a.Window.Seconds()), 10) + "\n")
	b.WriteString("at: " + strconv.FormatInt(a.At.UTC().Unix(), 10) + "\n")
	// Basis LAST and length-prefixed, so a basis containing a newline cannot
	// forge the fields above it.
	b.WriteString("basis: " + strconv.Itoa(len(a.Basis)) + "\n")
	b.WriteString(a.Basis)
	return []byte(b.String())
}

// Validate checks everything that does not need a key.
func (a Attestation) Validate() error {
	if strings.TrimSpace(a.Subject) == "" {
		return ErrNoSubject
	}
	if !a.Dimension.Valid() {
		return fmt.Errorf("%w: %d", ErrBadDimension, a.Dimension)
	}
	if math.IsNaN(a.Value) || math.IsInf(a.Value, 0) || a.Value < -1 || a.Value > 1 {
		return fmt.Errorf("%w: %v", ErrBadValue, a.Value)
	}
	if len(a.Issuer) != ed25519.PublicKeySize {
		return ErrNoIssuer
	}
	if strings.TrimSpace(a.Basis) == "" {
		return ErrNoBasis
	}
	if len(a.Basis) > MaxBasisBytes {
		return fmt.Errorf("%w: %d > %d", ErrBasisTooLong, len(a.Basis), MaxBasisBytes)
	}
	if a.Window <= 0 {
		return ErrNoWindow
	}
	// An issuer attesting to itself is a declaration, and §88 is explicit that
	// there is no bootstrap by declaration.
	if a.Subject == IssuerID(a.Issuer) {
		return ErrSelfAttested
	}
	return nil
}

// Sign fills in Signature.
func (a *Attestation) Sign(priv ed25519.PrivateKey) error {
	a.Issuer = priv.Public().(ed25519.PublicKey)
	if err := a.Validate(); err != nil {
		return err
	}
	a.Signature = ed25519.Sign(priv, a.SigningBytes())
	return nil
}

// Verify checks the signature against the carried issuer key.
func (a Attestation) Verify() error {
	if err := a.Validate(); err != nil {
		return err
	}
	if len(a.Signature) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	if !ed25519.Verify(a.Issuer, a.SigningBytes(), a.Signature) {
		return ErrBadSignature
	}
	return nil
}

// IssuerID renders an issuer key as the string the trusted-issuer set uses.
func IssuerID(pub ed25519.PublicKey) string {
	if len(pub) == 0 {
		return ""
	}
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, len(pub)*2)
	for _, b := range pub {
		out = append(out, hexd[b>>4], hexd[b&0x0f])
	}
	return string(out)
}
