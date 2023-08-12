package spec

import (
	"crypto"
	"crypto/sha256"
	"encoding/json"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

// AuthenticatorAssertionResponse is an authentication response.
type AuthenticatorAssertionResponse struct {
	AuthData       []byte
	ClientDataJSON []byte
	Signature      []byte
	UserHandle     []byte
}

func (a *AuthenticatorAssertionResponse) AuthenticatorData() (*AuthenticatorData, error) {
	authData := &AuthenticatorData{}
	if err := authData.Decode(a.AuthData); err != nil {
		return nil, errutil.Wrapf(err, "decoding authenticator data")
	}
	return authData, nil
}

func (a *AuthenticatorAssertionResponse) ClientData() (*ClientData, error) {
	var clientData ClientData
	if err := json.Unmarshal(a.ClientDataJSON, &clientData); err != nil {
		return nil, errutil.Wrapf(err, "decoding json")
	}
	return &clientData, nil
}

// verifyAssertionSignature checks a signed WebAuthn response against the registered public key of the device.
func (a *AuthenticatorAssertionResponse) VerifySignature(publicKey crypto.PublicKey, hasher crypto.Hash) (bool, error) {
	// Calculate the hash of the client data
	clientDataHash := sha256.Sum256(a.ClientDataJSON)

	// Combine all the data that is included in the signature
	hashInput := make([]byte, 0, len(a.AuthData)+len(clientDataHash))
	hashInput = append(hashInput, a.AuthData...)
	hashInput = append(hashInput, clientDataHash[:]...)

	// Check the signature
	return pubkey.VerifySignature(publicKey, hasher, hashInput, a.Signature)
}
