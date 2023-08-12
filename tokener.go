package webauthn

import (
	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

// Tokener defines the interface for creating tokens to ensure the authenticity of registration and
// authentication responses from users.
type Tokener interface {
	CreateToken(challenge challenge.Challenge, user User) (string, error)
	VerifyToken(token string, challenge challenge.Challenge, user User) error
}
