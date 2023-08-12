package pubkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"

	"github.com/spiretechnology/go-webauthn/internal/errutil"
	"github.com/spiretechnology/go-webauthn/pkg/errs"
)

const (
	// ECDSA with SHA-256 signature hash
	ES256 = KeyType(-7)
	// ECDSA with SHA-384 signature hash
	ES384 = KeyType(-35)
	// ECDSA with SHA-512 signature hash
	ES512 = KeyType(-36)
	// RSA-PSS with SHA-256 signature hash
	PS256 = KeyType(-257)
	// RSA-PSS with SHA-384 signature hash
	PS384 = KeyType(-258)
	// RSA-PSS with SHA-512 signature hash
	PS512 = KeyType(-259)
)

// KeyType is a type of public key and signature algorithm.
type KeyType int

// Hash returns the hash function used by this public key type.
func (k KeyType) Hash() crypto.Hash {
	switch k {
	case -7, -257:
		return crypto.SHA256
	case -35, -258:
		return crypto.SHA384
	case -36, -259:
		return crypto.SHA512
	default:
		return crypto.Hash(0)
	}
}

// CheckKey checks that the given public key is valid for this public key type.
func (k KeyType) CheckKey(key crypto.PublicKey) error {
	switch k {
	case -7, -35, -36:
		if _, ok := key.(*ecdsa.PublicKey); ok {
			return nil
		}
	case -257, -258, -259:
		if _, ok := key.(*rsa.PublicKey); ok {
			return nil
		}
	}
	return errutil.Wrap(errs.ErrInvalidKeyForAlg)
}

// Parse parses a DER-encoded public key.
func Parse(publicKeyBytes []byte) (crypto.PublicKey, error) {
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
