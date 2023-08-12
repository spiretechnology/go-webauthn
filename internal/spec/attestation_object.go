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

func (o *AttestationObject) AuthenticatorData() (*AuthenticatorData, error) {
	authData := &AuthenticatorData{}
	if err := authData.Decode(o.AuthData); err != nil {
		return nil, errutil.Wrapf(err, "decoding authenticator data")
	}
	return authData, nil
}

type AttestedCredential struct {
	AAGUID        [16]byte
	CredID        []byte
	CredPublicKey []byte
}

func (c *AttestedCredential) Encode() []byte {
	buf := make([]byte, 16+2+len(c.CredID)+len(c.CredPublicKey))
	var cursor int

	// AAGUID
	copy(buf[:16], c.AAGUID[:])
	cursor += 16

	// Cred ID length
	binary.BigEndian.PutUint16(buf[cursor:cursor+2], uint16(len(c.CredID)))
	cursor += 2

	// Cred ID
	copy(buf[cursor:], c.CredID)
	cursor += len(c.CredID)

	// Cred public key
	copy(buf[cursor:], c.CredPublicKey)

	return buf
}

func (c *AttestedCredential) Decode(buf []byte) error {
	if len(buf) < 18 {
		return errutil.Wrap(errors.New("invalid attested credential length"))
	}

	var cursor int

	// AAGUID
	copy(c.AAGUID[:], buf[cursor:cursor+16])
	cursor += 16

	// Cred ID length
	credIDLen := binary.BigEndian.Uint16(buf[cursor : cursor+2])
	cursor += 2

	if len(buf) < 18+int(credIDLen) {
		return errutil.Wrap(errors.New("invalid attested credential length"))
	}

	// Cred ID
	c.CredID = make([]byte, credIDLen)
	copy(c.CredID, buf[cursor:cursor+int(credIDLen)])
	cursor += int(credIDLen)

	// Cred public key
	c.CredPublicKey = make([]byte, len(buf)-cursor)
	copy(c.CredPublicKey, buf[cursor:])

	return nil
}
