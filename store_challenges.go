package webauthn

import "context"

// Challenges defines the interface for storing and recalling challenges that have been issued to users.
type Challenges interface {
	StoreChallenge(ctx context.Context, user User, challenge Challenge) error
	HasChallenge(ctx context.Context, user User, challege Challenge) (bool, error)
	RemoveChallenge(ctx context.Context, user User, challege Challenge) error
}
