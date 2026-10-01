package identity

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
)

// Signed identity records (section 5.2).
//
// Canonical encoding is the whole point of this file. A record is signed, and
// two encodings of one record produce two DHT keys and two signatures, so the
// encoder is fixed-layout with no optional fields, no maps and no varints:
// every field is written at a known offset with a known width.

// Record type bytes.
const (
	TypeIdentityRotation byte = 0x02
	TypeRevocation       byte = 0x03
	TypeDelegationCert   byte = 0x04
)

// Class identifies which identity class a record concerns, so a verifier can
// refuse a record that names the wrong class rather than checking only that
// some signature validates.
type Class byte

const (
	ClassNode    Class = 1
	ClassRouting Class = 2
	ClassService Class = 3
	ClassDomain  Class = 4
)

var (
	// ErrBadSignature is returned for any signature failure. Like ErrBadAddress
	// it does not say which signature failed: distinguishing them tells an
	// attacker which half of a two-signature record to keep working on.
	ErrBadSignature = errors.New("identity: signature verification failed")
	ErrWrongClass   = errors.New("identity: record signed by the wrong identity class")
	ErrExpired      = errors.New("identity: record outside its validity window")
)

// IdentityRotation moves a class from an old key to a new one. It carries two
// signatures: the old key authorises the move, and the new key proves
// possession, so neither key alone can perform a rotation.
type IdentityRotation struct {
	Class     Class
	OldPublic ed25519.PublicKey
	NewPublic ed25519.PublicKey
	NotBefore uint64
	NotAfter  uint64
	Serial    uint64
	SigOld    []byte
	SigNew    []byte
}

func (r *IdentityRotation) body() []byte {
	b := make([]byte, 0, 1+1+32+32+24)
	b = append(b, TypeIdentityRotation, byte(r.Class))
	b = append(b, r.OldPublic...)
	b = append(b, r.NewPublic...)
	b = binary.BigEndian.AppendUint64(b, r.NotBefore)
	b = binary.BigEndian.AppendUint64(b, r.NotAfter)
	b = binary.BigEndian.AppendUint64(b, r.Serial)
	return b
}

// SignRotation produces both signatures. oldPriv and newPriv are taken as raw
// ed25519 keys because a rotation is by definition a transition between two
// key objects rather than an operation on one.
func SignRotation(r *IdentityRotation, oldPriv, newPriv ed25519.PrivateKey) {
	body := r.body()
	r.SigOld = signPrefixed(oldPriv, LabelRotationOld, body)
	r.SigNew = signPrefixed(newPriv, LabelRotationNew, body)
}

// Verify checks both signatures and the validity window.
func (r *IdentityRotation) Verify(now uint64) error {
	body := r.body()
	if !VerifyPrefixed(r.OldPublic, LabelRotationOld, body, r.SigOld) {
		return ErrBadSignature
	}
	if !VerifyPrefixed(r.NewPublic, LabelRotationNew, body, r.SigNew) {
		return ErrBadSignature
	}
	if now < r.NotBefore || (r.NotAfter != 0 && now > r.NotAfter) {
		return ErrExpired
	}
	return nil
}

// Revocation withdraws a key. It is signed by the key being revoked: a third
// party cannot revoke someone else's identity, and the holder can always
// revoke their own.
//
// Revocation PROPAGATION is unsolved and is deliberately not implemented here.
// This type says what a revocation is; nothing in P1 claims to deliver one
// reliably to a client that has already cached the key.
type Revocation struct {
	Class     Class
	Public    ed25519.PublicKey
	Reason    uint8
	IssuedAt  uint64
	Serial    uint64
	Signature []byte
}

func (r *Revocation) body() []byte {
	b := make([]byte, 0, 1+1+32+1+16)
	b = append(b, TypeRevocation, byte(r.Class))
	b = append(b, r.Public...)
	b = append(b, r.Reason)
	b = binary.BigEndian.AppendUint64(b, r.IssuedAt)
	b = binary.BigEndian.AppendUint64(b, r.Serial)
	return b
}

// SignRevocation signs a revocation with the key it revokes.
func SignRevocation(r *Revocation, priv ed25519.PrivateKey) {
	r.Signature = signPrefixed(priv, LabelRevocation, r.body())
}

// Verify checks the revocation is self-signed by the key it names.
func (r *Revocation) Verify() error {
	if !VerifyPrefixed(r.Public, LabelRevocation, r.body(), r.Signature) {
		return ErrBadSignature
	}
	return nil
}

// DelegationCertificate lets a DomainIdentity authorise a ServiceIdentity for a
// scope and a window. Both parties sign: the issuer to grant, the subject to
// accept, so a domain cannot unilaterally name a service it does not control
// and a service cannot claim a domain that did not grant it.
type DelegationCertificate struct {
	IssuerClass  Class
	SubjectClass Class
	Issuer       ed25519.PublicKey
	Subject      ed25519.PublicKey
	Scope        string
	NotBefore    uint64
	NotAfter     uint64
	SigIssuer    []byte
	SigSubject   []byte
}

func (c *DelegationCertificate) body() []byte {
	scope := []byte(c.Scope)
	b := make([]byte, 0, 1+2+32+32+2+len(scope)+16)
	b = append(b, TypeDelegationCert, byte(c.IssuerClass), byte(c.SubjectClass))
	b = append(b, c.Issuer...)
	b = append(b, c.Subject...)
	// Length-prefixed so that a scope containing the separator cannot be made
	// to parse as a different field split.
	b = binary.BigEndian.AppendUint16(b, uint16(len(scope)))
	b = append(b, scope...)
	b = binary.BigEndian.AppendUint64(b, c.NotBefore)
	b = binary.BigEndian.AppendUint64(b, c.NotAfter)
	return b
}

// SignDelegation produces both signatures.
func SignDelegation(c *DelegationCertificate, issuerPriv, subjectPriv ed25519.PrivateKey) error {
	if len(c.Scope) > 65535 {
		return fmt.Errorf("identity: delegation scope too long: %d bytes", len(c.Scope))
	}
	body := c.body()
	c.SigIssuer = signPrefixed(issuerPriv, LabelDelegationIssuer, body)
	c.SigSubject = signPrefixed(subjectPriv, LabelDelegationSubj, body)
	return nil
}

// Verify checks both signatures, the declared classes, and the window.
//
// wantIssuer and wantSubject are the classes the caller expects. Passing them
// is mandatory rather than optional because "this certificate is valid" is not
// a useful answer without "and it delegates the thing I am about to rely on".
func (c *DelegationCertificate) Verify(now uint64, wantIssuer, wantSubject Class) error {
	if c.IssuerClass != wantIssuer || c.SubjectClass != wantSubject {
		return ErrWrongClass
	}
	body := c.body()
	if !VerifyPrefixed(c.Issuer, LabelDelegationIssuer, body, c.SigIssuer) {
		return ErrBadSignature
	}
	if !VerifyPrefixed(c.Subject, LabelDelegationSubj, body, c.SigSubject) {
		return ErrBadSignature
	}
	if now < c.NotBefore || (c.NotAfter != 0 && now > c.NotAfter) {
		return ErrExpired
	}
	return nil
}
