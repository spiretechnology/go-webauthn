package store

import "context"

type Challenges interface {
	StoreChallenge(ctx context.Context, userID string, challenge [32]byte) error
	HasChallenge(ctx context.Context, userID string, challege [32]byte) (bool, error)
	RemoveChallenge(ctx context.Context, userID string, challege [32]byte) error
}
