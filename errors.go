package webauthn

import (
	"errors"
)

var (
	ErrUnsupportedPublicKey  = errors.New("unsupported public key type")
	ErrInvalidKeyForAlg      = errors.New("invalid key for alg")
	ErrSignatureMismatch     = errors.New("signature mismatch")
	ErrUserNotFound          = errors.New("user not found")
	ErrCredentialNotFound    = errors.New("credential not found")
	ErrNoCredentials         = errors.New("user has no credential")
	ErrUnrecognizedChallenge = errors.New("unrecognized challenge")
	ErrInvalidChallenge      = errors.New("invalid challenge size")
)
