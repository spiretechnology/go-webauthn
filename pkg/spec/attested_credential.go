package spec

import (
	"crypto"
	"encoding/binary"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/cosekey"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

type AttestedCredential struct {
	AAGUID            [16]byte
	CredID            []byte
	CredPublicKeyType pubkey.KeyType
	CredPublicKey     crypto.PublicKey
}

func (c *AttestedCredential) Decode(buf []byte) error {
	if len(buf) < 18 {
		return errutil.New("invalid attested credential length")
	}

	var cursor int

	// AAGUID
	copy(c.AAGUID[:], buf[cursor:cursor+16])
	cursor += 16

	// Cred ID length
	credIDLen := binary.BigEndian.Uint16(buf[cursor : cursor+2])
	cursor += 2

	if len(buf) < 18+int(credIDLen) {
		return errutil.New("invalid attested credential length")
	}

	// Cred ID
	c.CredID = make([]byte, credIDLen)
	copy(c.CredID, buf[cursor:cursor+int(credIDLen)])
	cursor += int(credIDLen)

	// Cred public key
	pubKeyBytes := buf[cursor:]
	coseKey, err := cosekey.DecodeCOSEPublicKey(pubKeyBytes)
	if err != nil {
		return errutil.Wrapf(err, "parsing COSE key")
	}
	c.CredPublicKey = coseKey.PublicKey
	c.CredPublicKeyType = coseKey.KeyType

	return nil
}
