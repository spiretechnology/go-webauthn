package spec

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

const (
	// User Present flag.
	AuthDataFlag_UserPresent = 1 << iota
	// Reserved for future use.
	AuthDataFlag_RFU1
	// User Verified flag.
	AuthDataFlag_UserVerified
	// Reserved for future use.
	AuthDataFlag_RFU2
	// Reserved for future use.
	AuthDataFlag_RFU3
	// Reserved for future use.
	AuthDataFlag_RFU4
	// Attested credential data included.
	AuthDataFlag_AttestedCredentialData
	// Extension data included.
	AuthDataFlag_ExtensionData
)

// AuthenticatorData represents the authenticator data structure.
type AuthenticatorData struct {
	RPIDHash           [sha256.Size]byte
	Flags              byte
	SignCount          uint32
	AttestedCredential *AttestedCredential
}

func (a *AuthenticatorData) Decode(buf []byte) error {
	if len(buf) < sha256.Size+5 {
		return errutil.Wrap(errors.New("invalid authenticator data length"))
	}
	var cursor int

	// RPID hash
	copy(a.RPIDHash[:], buf[cursor:sha256.Size])
	cursor += sha256.Size

	// Flags
	a.Flags = buf[cursor]
	cursor++

	// Sign count
	a.SignCount = binary.BigEndian.Uint32(buf[cursor : cursor+4])
	cursor += 4

	// Att Credential
	if cursor < len(buf) && a.Flags&AuthDataFlag_AttestedCredentialData != 0 {
		a.AttestedCredential = &AttestedCredential{}
		if err := a.AttestedCredential.Decode(buf[cursor:]); err != nil {
			return errutil.Wrapf(err, "decoding attested credential")
		}
	}

	return nil
}
