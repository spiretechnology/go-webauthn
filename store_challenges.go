package webauthn

import "context"

// Challenges defines the interface for storing and recalling challenges that have been issued to users.
type Challenges interface {
	StoreChallenge(ctx context.Context, user User, challenge [32]byte) error
	HasChallenge(ctx context.Context, user User, challege [32]byte) (bool, error)
	RemoveChallenge(ctx context.Context, user User, challege [32]byte) error
}
