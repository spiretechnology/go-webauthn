package webauthn

import "context"

type storedChallege struct {
	userID    string
	challenge Challenge
}

func challengeKey(user User, challenge Challenge) storedChallege {
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
}

func (c *inMemChallenges) StoreChallenge(ctx context.Context, user User, challenge Challenge) error {
	c.challenges[challengeKey(user, challenge)] = struct{}{}
	return nil
}

func (c *inMemChallenges) HasChallenge(ctx context.Context, user User, challenge Challenge) (bool, error) {
	_, ok := c.challenges[challengeKey(user, challenge)]
	return ok, nil
}

func (c *inMemChallenges) RemoveChallenge(ctx context.Context, user User, challenge Challenge) error {
	delete(c.challenges, challengeKey(user, challenge))
	return nil
}
