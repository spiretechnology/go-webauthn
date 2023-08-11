package webauthn

import "context"

type Challenges interface {
	StoreChallenge(ctx context.Context, user User, challenge [32]byte) error
	HasChallenge(ctx context.Context, user User, challege [32]byte) (bool, error)
	RemoveChallenge(ctx context.Context, user User, challege [32]byte) error
}
