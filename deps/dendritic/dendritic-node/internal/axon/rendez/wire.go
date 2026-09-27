package rendez

import (
	"encoding/binary"
	"fmt"

	"github.com/syndichan/maniwani/storage-client/internal/axon/circuit"
)

// Wire bodies for the §9.5 L5 command set.
//
// §8 owns the cell and the command CODES; this file owns the BODIES. Every
// decoder bounds each length against the remaining buffer before using it --
// these bodies arrive from an intro point or a rendezvous point, neither of
// which is trusted, and a length used before it is bounded is how a parser
// becomes a read primitive.

// EstablishIntro registers a service at an intro point.
//
//	auth_key(32) ‖ cert_len(2) ‖ auth_key_cert ‖ sig_len(2) ‖ sig
type EstablishIntro struct {
	AuthKey [authKeySize]byte
	Cert    []byte
	Sig     []byte
}

func (e *EstablishIntro) Encode() []byte {
	b := make([]byte, 0, authKeySize+4+len(e.Cert)+len(e.Sig))
	b = append(b, e.AuthKey[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Cert)))
	b = append(b, e.Cert...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Sig)))
	return append(b, e.Sig...)
}

func DecodeEstablishIntro(b []byte) (*EstablishIntro, error) {
	e := &EstablishIntro{}
	p, err := take(b, authKeySize)
	if err != nil {
		return nil, err
	}
	copy(e.AuthKey[:], p)
	rest := b[authKeySize:]
	if e.Cert, rest, err = takeLV(rest); err != nil {
		return nil, err
	}
	if e.Sig, _, err = takeLV(rest); err != nil {
		return nil, err
	}
	return e, nil
}

// IntroEstablished is the intro point's confirmation.
//
//	status(1) ‖ rate_limit_state(4)
type IntroEstablished struct {
	Status    AckStatus
	RateState uint32
}

func (i *IntroEstablished) Encode() []byte {
	return binary.BigEndian.AppendUint32([]byte{byte(i.Status)}, i.RateState)
}

func DecodeIntroEstablished(b []byte) (*IntroEstablished, error) {
	if _, err := take(b, 5); err != nil {
		return nil, err
	}
	return &IntroEstablished{Status: AckStatus(b[0]),
		RateState: binary.BigEndian.Uint32(b[1:])}, nil
}

// Encode writes INTRODUCE1's wire body.
//
//	version(1) ‖ auth_key(32) ‖ ext_len(2) ‖ puzzle_proof ‖ X(32) ‖ enc_len(2) ‖ ENCRYPTED
func (i *Introduce1) Encode() []byte {
	b := make([]byte, 0, 1+authKeySize+2+len(i.PuzzleProof)+pubKeySize+2+len(i.Encrypted))
	b = append(b, i.Version)
	b = append(b, i.AuthKeyID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(i.PuzzleProof)))
	b = append(b, i.PuzzleProof...)
	b = append(b, i.X[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(i.Encrypted)))
	return append(b, i.Encrypted...)
}

// DecodeIntroduce1 parses an INTRODUCE1 body.
func DecodeIntroduce1(b []byte) (*Introduce1, error) {
	i := &Introduce1{}
	if _, err := take(b, 1+authKeySize); err != nil {
		return nil, err
	}
	i.Version = b[0]
	copy(i.AuthKeyID[:], b[1:1+authKeySize])
	rest := b[1+authKeySize:]

	var err error
	if i.PuzzleProof, rest, err = takeLV(rest); err != nil {
		return nil, err
	}
	if _, err = take(rest, pubKeySize); err != nil {
		return nil, err
	}
	copy(i.X[:], rest[:pubKeySize])
	rest = rest[pubKeySize:]
	if i.Encrypted, _, err = takeLV(rest); err != nil {
		return nil, err
	}
	// The encrypted region is a FIXED size. A body claiming any other length is
	// malformed rather than merely unusual: the fixed length is what stops the
	// intro point sizing a resumption or an authorised client.
	if want := IntroPlaintextSize + 16; len(i.Encrypted) != want {
		return nil, fmt.Errorf("%w: encrypted region is %d, want %d",
			ErrMalformed, len(i.Encrypted), want)
	}
	return i, nil
}

// IntroduceAck is the intro point's verdict to the client.
//
//	status(1) ‖ puzzle_params_len(2) ‖ puzzle_params
type IntroduceAck struct {
	Status       AckStatus
	PuzzleParams []byte
}

func (a *IntroduceAck) Encode() []byte {
	b := []byte{byte(a.Status)}
	b = binary.BigEndian.AppendUint16(b, uint16(len(a.PuzzleParams)))
	return append(b, a.PuzzleParams...)
}

func DecodeIntroduceAck(b []byte) (*IntroduceAck, error) {
	if _, err := take(b, 1); err != nil {
		return nil, err
	}
	params, _, err := takeLV(b[1:])
	if err != nil {
		return nil, err
	}
	return &IntroduceAck{Status: AckStatus(b[0]), PuzzleParams: params}, nil
}

// EstablishRendezvous carries the client's cookie to the RP.
type EstablishRendezvous struct {
	Cookie Cookie
	Token  []byte
}

func (e *EstablishRendezvous) Encode() []byte {
	b := append([]byte{}, e.Cookie[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(e.Token)))
	return append(b, e.Token...)
}

func DecodeEstablishRendezvous(b []byte) (*EstablishRendezvous, error) {
	e := &EstablishRendezvous{}
	if _, err := take(b, CookieSize); err != nil {
		return nil, err
	}
	copy(e.Cookie[:], b[:CookieSize])
	tok, _, err := takeLV(b[CookieSize:])
	if err != nil {
		return nil, err
	}
	e.Token = tok
	return e, nil
}

// Rendezvous1 is the service's half, addressed to the RP by cookie.
//
//	cookie(20) ‖ Y(32) ‖ AUTH(32)
type Rendezvous1 struct {
	Cookie Cookie
	HS     Handshake
}

func (r *Rendezvous1) Encode() []byte {
	b := append([]byte{}, r.Cookie[:]...)
	b = append(b, r.HS.Y[:]...)
	return append(b, r.HS.Auth[:]...)
}

func DecodeRendezvous1(b []byte) (*Rendezvous1, error) {
	if _, err := take(b, CookieSize+pubKeySize+authTagSize); err != nil {
		return nil, err
	}
	r := &Rendezvous1{}
	copy(r.Cookie[:], b[:CookieSize])
	copy(r.HS.Y[:], b[CookieSize:CookieSize+pubKeySize])
	copy(r.HS.Auth[:], b[CookieSize+pubKeySize:])
	return r, nil
}

// Rendezvous2 is what the RP passes to the client.
//
// THE COOKIE IS NOT IN IT. The RP drops the cookie at the join, and forwarding
// it to the client would hand the client back a token the RP is supposed to have
// forgotten -- and put it on the wire a second time for no reason.
type Rendezvous2 struct {
	HS Handshake
}

func (r *Rendezvous2) Encode() []byte {
	return append(append([]byte{}, r.HS.Y[:]...), r.HS.Auth[:]...)
}

func DecodeRendezvous2(b []byte) (*Rendezvous2, error) {
	if _, err := take(b, pubKeySize+authTagSize); err != nil {
		return nil, err
	}
	r := &Rendezvous2{}
	copy(r.HS.Y[:], b[:pubKeySize])
	copy(r.HS.Auth[:], b[pubKeySize:])
	return r, nil
}

// -----------------------------------------------------------------------------

// RelayCell wraps a body in the L5 command with the right scope.
//
// Every L5 command is circuit-scoped, so STREAMID is zero. circuit.RelayCell's
// encoder enforces that, which is why this helper cannot get it wrong.
func RelayCell(cmd circuit.RCmd, body []byte) *circuit.RelayCell {
	return &circuit.RelayCell{Stream: 0, Cmd: cmd, Data: body}
}

func take(b []byte, n int) ([]byte, error) {
	if len(b) < n {
		return nil, fmt.Errorf("%w: need %d bytes, have %d", ErrMalformed, n, len(b))
	}
	return b[:n], nil
}

// takeLV reads a uint16-prefixed value and returns it with the remainder.
func takeLV(b []byte) (val, rest []byte, err error) {
	if _, err = take(b, 2); err != nil {
		return nil, nil, err
	}
	n := int(binary.BigEndian.Uint16(b))
	if len(b[2:]) < n {
		return nil, nil, fmt.Errorf("%w: field claims %d of %d", ErrMalformed, n, len(b)-2)
	}
	return append([]byte(nil), b[2:2+n]...), b[2+n:], nil
}
