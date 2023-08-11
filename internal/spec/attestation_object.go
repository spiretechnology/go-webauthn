package spec

import (
	"encoding/binary"
	"errors"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// AttestationObject represents the structure of the attestation object.
type AttestationObject struct {
	AuthData []byte         `cbor:"authData"`
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`
}

// AuthenticatorData represents the authenticator data structure.
type AuthenticatorData struct {
	RPIDHash      [32]byte
	Flags         byte
	SignCount     uint32
	AttCredential []byte // This will need further parsing
}

func (o *AttestationObject) DecodeAuthData() (*AuthenticatorData, error) {
	if len(o.AuthData) < 37 {
		return nil, errutil.Wrap(errors.New("invalid authenticator data length"))
	}
	var authData AuthenticatorData
	copy(authData.RPIDHash[:], o.AuthData[:32])
	authData.Flags = o.AuthData[32]
	authData.SignCount = binary.BigEndian.Uint32(o.AuthData[33:37])
	authData.AttCredential = o.AuthData[37:]
	return &authData, nil
}

func (a *AuthenticatorData) Encode() []byte {
	buf := make([]byte, 37+len(a.AttCredential))
	copy(buf[:32], a.RPIDHash[:])
	buf[32] = a.Flags
	binary.BigEndian.PutUint32(buf[33:37], a.SignCount)
	copy(buf[37:], a.AttCredential)
	return buf
}
