package pubkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
)

// VerifySignature verifies a signature against a public key.
func VerifySignature(publicKey crypto.PublicKey, hasher crypto.Hash, data, signature []byte) (bool, error) {
	// Calculate the hash using the provided hash function
	h := hasher.New()
	h.Write(data)
	combinedHash := h.Sum(nil)

	// Verify the hash depending on the type of the public key
	var verified bool
	switch pk := publicKey.(type) {
	case *ecdsa.PublicKey:
		verified = ecdsa.VerifyASN1(pk, combinedHash, signature)
	case *rsa.PublicKey:
		verified = rsa.VerifyPSS(pk, hasher, combinedHash, signature, nil) == nil
	default:
		return false, errutil.Wrap(errors.New("unsupported public key type"))
	}
	return verified, nil
}
