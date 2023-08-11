package spec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// AuthenticatorAssertionResponse is an authentication response.
type AuthenticatorAssertionResponse struct {
	AuthenticatorData []byte
	ClientDataJSON    []byte
	Signature         []byte
	UserHandle        []byte
}

func (a *AuthenticatorAssertionResponse) DecodeClientData() (*ClientData, error) {
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

	// Calculate the combined hash for everything
	hashInput := make([]byte, 0, len(a.AuthenticatorData)+len(clientDataHash))
	hashInput = append(hashInput, a.AuthenticatorData...)
	hashInput = append(hashInput, clientDataHash[:]...)

	// Calculate the hash using the provided hash function
	h := hasher.New()
	h.Write(hashInput)
	combinedHash := h.Sum(nil)

	// Verify the hash depending on the type of the public key
	var verified bool
	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		verified = ecdsa.VerifyASN1(pk, combinedHash, a.Signature)
	case *rsa.PublicKey:
		verified = rsa.VerifyPSS(pk, hasher, combinedHash, a.Signature, nil) == nil
	default:
		return false, errutil.Wrap(errors.New("unsupported public key type"))
	}
	return verified, nil
}
