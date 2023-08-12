package spec

import (
	"crypto"
	"encoding/json"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

// AuthenticatorAssertionResponse is an authentication response.
type AuthenticatorAssertionResponse struct {
	AuthData       []byte
	ClientDataJSON []byte
	Signature      []byte
	UserHandle     []byte

	authData   *AuthenticatorData
	clientData *ClientData
}

func (a *AuthenticatorAssertionResponse) AuthenticatorData() (*AuthenticatorData, error) {
	if a.authData == nil {
		var authData AuthenticatorData
		if err := authData.Decode(a.AuthData); err != nil {
			return nil, errutil.Wrapf(err, "decoding authenticator data")
		}
		a.authData = &authData
	}
	return a.authData, nil
}

func (a *AuthenticatorAssertionResponse) ClientData() (*ClientData, error) {
	if a.clientData == nil {
		var clientData ClientData
		if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
			return nil, errutil.Wrapf(err, "decoding json")
		}
		a.clientData = &clientData
	}
	return a.clientData, nil
}

// verifyAssertionSignature checks a signed WebAuthn response against the registered public key of the device.
func (a *AuthenticatorAssertionResponse) Verify(publicKey crypto.PublicKey, keyType pubkey.KeyType) error {
	valid, err := VerifySignature(publicKey, keyType, a.Signature, a.ClientDataJSON, a.AuthData)
	if err != nil {
		return errutil.Wrapf(err, "verifying signature")
	}
	if !valid {
		return errutil.Wrap(errs.ErrSignatureMismatch)
	}
	return nil
}
