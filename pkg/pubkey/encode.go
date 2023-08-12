package pubkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
)

// Decode parses a DER-encoded public key, specifically for storage of registered credentials.
func Decode(publicKeyBytes []byte) (crypto.PublicKey, error) {
	// Parse the public key
	ifc, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, errutil.Wrapf(err, "parsing public key")
	}

	// If it's an RSA or ECDSA key, accept it
	switch key := ifc.(type) {
	case *ecdsa.PublicKey:
		return key, nil
	case *rsa.PublicKey:
		return key, nil
	default:
		return nil, errutil.Wrap(errs.ErrUnsupportedPublicKey)
	}
}

// Encode serializes a public key to DER format, specifically for storage of registered credentials.
func Encode(publicKey crypto.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(publicKey)
}
