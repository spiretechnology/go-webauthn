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
	ErrUnrecognizedChallenge = errors.New("unrecognized challenge")
)
