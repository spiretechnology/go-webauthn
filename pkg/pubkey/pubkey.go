package pubkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
)

// See here for the COSE key type registry:
// https://www.iana.org/assignments/cose/cose.xhtml#algorithms

const (
	// ECDSA with SHA-256 signature hash
	ES256 = KeyType(-7)
	// ECDSA with SHA-384 signature hash
	ES384 = KeyType(-35)
	// ECDSA with SHA-512 signature hash
	ES512 = KeyType(-36)
	// RSASSA-PSS with SHA-256 signature hash
	RS256 = KeyType(-257)
	// RSASSA-PSS with SHA-384 signature hash
	RS384 = KeyType(-258)
	// RSASSA-PSS with SHA-512 signature hash
	RS512 = KeyType(-259)
	// RSASSA-PKCS1 with SHA-256 signature hash
	PS256 = KeyType(-37)
	// RSASSA-PKCS1 with SHA-384 signature hash
	PS384 = KeyType(-38)
	// RSASSA-PKCS1 with SHA-512 signature hash
	PS512 = KeyType(-39)
)

// AllKeyTypes is a list of all supported key types.
var AllKeyTypes = []KeyType{
	ES256, ES384, ES512,
	RS256, RS256, RS256,
	PS256, PS384, PS512,
}

// KeyType is a type of public key and signature algorithm.
type KeyType int

// Hash returns the hash function used by this public key type.
func (k KeyType) Hash() crypto.Hash {
	switch k {
	case ES256, RS256, PS256:
		return crypto.SHA256
	case ES384, RS384, PS384:
		return crypto.SHA384
	case ES512, RS512, PS512:
		return crypto.SHA512
	default:
		return 0
	}
}

// CheckKey checks that the given public key is valid for this public key type.
func (k KeyType) CheckKey(key crypto.PublicKey) bool {
	switch k {
	case ES256, ES384, ES512:
		_, ok := key.(*ecdsa.PublicKey)
		return ok
	case RS256, RS384, RS512, PS256, PS384, PS512:
		_, ok := key.(*rsa.PublicKey)
		return ok
	}
	return false
}
