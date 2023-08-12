package spec

import (
	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// AttestationObject represents the structure of the attestation object.
type AttestationObject struct {
	AuthData []byte         `cbor:"authData"`
	Fmt      string         `cbor:"fmt"`
	AttStmt  map[string]any `cbor:"attStmt"`

	authData *AuthenticatorData
}

func (o *AttestationObject) AuthenticatorData() (*AuthenticatorData, error) {
	if o.authData == nil {
		var authData AuthenticatorData
		if err := authData.Decode(o.AuthData); err != nil {
			return nil, errutil.Wrapf(err, "decoding authenticator data")
		}
		o.authData = &authData
	}
	return o.authData, nil
}
