package spec

import (
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
