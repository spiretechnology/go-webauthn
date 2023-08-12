package spec

import (
	"crypto"
	"crypto/sha256"

	"github.com/spiretechnology/go-webauthn/pkg/pubkey"
)

// VerifySignature verifies the signature of an attestation or assertion.
func VerifySignature(publicKey crypto.PublicKey, keyType pubkey.KeyType, signature, clientDataJSON, authData []byte) (bool, error) {
	// Calculate the hash of the client data
	clientDataHash := sha256.Sum256(clientDataJSON)

	// Combine all the data that is included in the signature
	hashInput := make([]byte, 0, len(authData)+len(clientDataHash))
	hashInput = append(hashInput, authData...)
	hashInput = append(hashInput, clientDataHash[:]...)

	// Check the signature
	return pubkey.VerifySignature(
		publicKey,
		keyType.Hash(),
		hashInput,
		signature,
	)
}
