package spec

import (
	"crypto/sha256"
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
	RPIDHash      [sha256.Size]byte
	Flags         byte
	SignCount     uint32
	AttCredential []byte // This will need further parsing
}

func (o *AttestationObject) DecodeAuthData() (*AuthenticatorData, error) {
	if len(o.AuthData) < sha256.Size+5 {
		return nil, errutil.Wrap(errors.New("invalid authenticator data length"))
	}
	var authData AuthenticatorData
	var cursor int

	// RPID hash
	copy(authData.RPIDHash[:], o.AuthData[cursor:sha256.Size])
	cursor += sha256.Size

	// Flags
	authData.Flags = o.AuthData[cursor]
	cursor++

	// Sign count
	authData.SignCount = binary.BigEndian.Uint32(o.AuthData[cursor : cursor+4])
	cursor += 4

	// Att Credential
	authData.AttCredential = o.AuthData[cursor:]

	return &authData, nil
}

func (a *AuthenticatorData) Encode() []byte {
	buf := make([]byte, sha256.Size+5+len(a.AttCredential))
	var cursor int

	// RPID hash
	copy(buf[:sha256.Size], a.RPIDHash[:])
	cursor += sha256.Size

	// Flags
	buf[cursor] = a.Flags
	cursor++

	// Sign count
	binary.BigEndian.PutUint32(buf[cursor:cursor+4], a.SignCount)
	cursor += 4

	// Att Credential
	copy(buf[cursor:], a.AttCredential)

	return buf
}
