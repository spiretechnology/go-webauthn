package webauthn

import (
	"context"
	"sync"

	"github.com/spiretechnology/go-webauthn/pkg/challenge"
)

type storedChallege struct {
	userID    string
	challenge challenge.Challenge
}

func challengeKey(user User, challenge challenge.Challenge) storedChallege {
	return storedChallege{
		userID:    user.ID,
		challenge: challenge,
	}
}

// NewChallengesInMemory returns a new in-memory implementation of the Challenges interface.
func NewChallengesInMemory() Challenges {
	return &inMemChallenges{
		challenges: make(map[storedChallege]struct{}),
	}
}

type inMemChallenges struct {
	challenges map[storedChallege]struct{}
	mut        sync.RWMutex
}

func (c *inMemChallenges) StoreChallenge(ctx context.Context, user User, challenge challenge.Challenge) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	c.challenges[challengeKey(user, challenge)] = struct{}{}
	return nil
}

func (c *inMemChallenges) HasChallenge(ctx context.Context, user User, challenge challenge.Challenge) (bool, error) {
	c.mut.RLock()
	defer c.mut.RUnlock()
	_, ok := c.challenges[challengeKey(user, challenge)]
	return ok, nil
}

func (c *inMemChallenges) RemoveChallenge(ctx context.Context, user User, challenge challenge.Challenge) error {
	c.mut.Lock()
	defer c.mut.Unlock()
	delete(c.challenges, challengeKey(user, challenge))
	return nil
}
