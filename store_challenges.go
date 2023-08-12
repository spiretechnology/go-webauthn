package webauthn

import (
	"context"

	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

// Challenges defines the interface for storing and recalling challenges that have been issued to users.
type Challenges interface {
	StoreChallenge(ctx context.Context, user User, challenge challenge.Challenge) error
	HasChallenge(ctx context.Context, user User, challege challenge.Challenge) (bool, error)
	RemoveChallenge(ctx context.Context, user User, challege challenge.Challenge) error
}
