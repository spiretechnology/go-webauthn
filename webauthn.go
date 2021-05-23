package webauthn

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// ChallengeResponse contains a signed response from a WebAuthn client device
type ChallengeResponse struct {
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	Signature         string `json:"signature"`
	// UserHandle        *string `json:"userHandle"`
}

// NewChallenge generates a new WebAuthn challenge string
func NewChallenge() (string, error) {

	// Generate a random challenge
	token := make([]byte, 32)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}

	// Encode it to base64 URL-safe encoding
	str := base64.RawURLEncoding.EncodeToString(token)

	// Return the encoded challenge string
	return str, nil

}

// Verify checks a signed WebAuthn response against the registered public key of the device
func Verify(
	publicKey *ecdsa.PublicKey,
	response *ChallengeResponse,
) error {

	// Decode the client data
	clientData, err := base64.RawURLEncoding.DecodeString(response.ClientDataJSON)
	if err != nil {
		return fmt.Errorf("error decoding WebAuthn client data: %s", err.Error())
	}

	// Decode the authenticator data
	authenticatorData, err := base64.RawURLEncoding.DecodeString(response.AuthenticatorData)
	if err != nil {
		return fmt.Errorf("error decoding WebAuthn authenticator data: %s", err.Error())
	}

	// Decode the signature string
	signature, err := base64.RawURLEncoding.DecodeString(response.Signature)
	if err != nil {
		return fmt.Errorf("error decoding WebAuthn signature: %s", err.Error())
	}

	// Calculate the hash of the client data
	clientDataHash := sha256.Sum256(clientData)

	// Calculate the combined hash for everything
	combinedHash := sha256.Sum256(bytes.Join(
		[][]byte{
			authenticatorData,
			clientDataHash[:],
		},
		[]byte{},
	))

	// Verify the signature
	verified := ecdsa.VerifyASN1(
		publicKey,
		combinedHash[:],
		signature,
	)

	// If verification failed
	if !verified {
		return errors.New("signature does not match device public key")
	}

	// Return no error signalling success
	return nil

}

// ReadPublicKey parses a WebAuthn public key from the provided string value
func ReadPublicKey(publicKeyStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyStr))
	enc := x509.IsEncryptedPEMBlock(block)
	b := block.Bytes
	var err error
	if enc {
		b, err = x509.DecryptPEMBlock(block, nil)
		if err != nil {
			return nil, err
		}
	}
	ifc, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	key, ok := ifc.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("parsed key is not an ECDSA public key")
	}
	return key, nil
}
